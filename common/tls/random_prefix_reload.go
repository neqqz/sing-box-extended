package tls

import (
	"bytes"
	"context"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// DefaultRandomPrefixReloadInterval — как часто сервер перечитывает файлы
// с префиксами/секретами.
const DefaultRandomPrefixReloadInterval = 5 * time.Second

// RandomPrefixSet — актуальный набор проверок ClientHello.Random на сервере.
// Непустой Secrets означает режим ротации (Prefixes при этом пуст: два режима
// взаимоисключающие), иначе проверяются статичные Prefixes.
type RandomPrefixSet struct {
	Prefixes []RandomPrefix
	Secrets  [][]byte
}

// RandomPrefixProvider отдаёт текущий набор. Set неизменяем после публикации,
// поэтому вызывающий может спокойно читать его без блокировок.
type RandomPrefixProvider interface {
	Current() *RandomPrefixSet
}

// RandomPrefixLogger — то, что нужно от логгера (удовлетворяется
// logger.ContextLogger из sing).
type RandomPrefixLogger interface {
	Info(args ...any)
	Error(args ...any)
}

// RandomPrefixSource описывает, откуда берётся набор: инлайн-значения из
// конфига плюс (необязательно) два файла, которые можно менять на лету.
// Формат файлов: одна запись на строку, пустые строки игнорируются, всё после
// '#' — комментарий. В файле префиксов — "hex" или "hex/mask_hex", в файле
// секретов — hex-секрет. Записи из конфига и из файла объединяются.
type RandomPrefixSource struct {
	Prefixes   []string
	Secrets    []string
	PrefixFile string
	SecretFile string
}

// Enabled — задан ли хоть какой-то источник (иначе проверка Random выключена).
func (s RandomPrefixSource) Enabled() bool {
	return HasNonEmpty(s.Prefixes) || HasNonEmpty(s.Secrets) || s.PrefixFile != "" || s.SecretFile != ""
}

// HasFiles — есть ли что перечитывать.
func (s RandomPrefixSource) HasFiles() bool {
	return s.PrefixFile != "" || s.SecretFile != ""
}

// ParseListFile разбирает содержимое файла со списком: строки, пустые
// пропускаются, '#' начинает комментарий (до конца строки).
func ParseListFile(data []byte) []string {
	text := strings.TrimPrefix(string(data), "\ufeff")
	var result []string
	for _, line := range strings.Split(text, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		result = append(result, line)
	}
	return result
}

type randomPrefixFiles struct {
	prefix []byte
	secret []byte
}

func (s RandomPrefixSource) read() (randomPrefixFiles, error) {
	var files randomPrefixFiles
	var err error
	if s.PrefixFile != "" {
		files.prefix, err = os.ReadFile(s.PrefixFile)
		if err != nil {
			return files, E.Cause(err, "read client_random_prefix_file")
		}
	}
	if s.SecretFile != "" {
		files.secret, err = os.ReadFile(s.SecretFile)
		if err != nil {
			return files, E.Cause(err, "read client_random_prefix_secret_file")
		}
	}
	return files, nil
}

// build разбирает и проверяет набор целиком. Ошибка, если оба режима заданы
// одновременно или если в итоге нет ни одной записи (пустой набор молча
// принимал бы любые соединения — так «открывать» проверку нельзя).
func (s RandomPrefixSource) build(files randomPrefixFiles) (*RandomPrefixSet, error) {
	inlinePrefixes, err := ParseRandomPrefixes(s.Prefixes)
	if err != nil {
		return nil, err
	}
	filePrefixes, err := ParseRandomPrefixes(ParseListFile(files.prefix))
	if err != nil {
		return nil, E.Cause(err, "in ", s.PrefixFile)
	}
	inlineSecrets, err := ParseRandomPrefixSecrets(s.Secrets)
	if err != nil {
		return nil, err
	}
	fileSecrets, err := ParseRandomPrefixSecrets(ParseListFile(files.secret))
	if err != nil {
		return nil, E.Cause(err, "in ", s.SecretFile)
	}
	set := &RandomPrefixSet{
		Prefixes: append(inlinePrefixes, filePrefixes...),
		Secrets:  append(inlineSecrets, fileSecrets...),
	}
	if len(set.Prefixes) > 0 && len(set.Secrets) > 0 {
		return nil, E.New("client_random_prefix and client_random_prefix_secret are mutually exclusive; secret-based rotation replaces the static prefix entirely")
	}
	if len(set.Prefixes) == 0 && len(set.Secrets) == 0 {
		return nil, E.New("client_random_prefix: no entries (config values and files are all empty)")
	}
	return set, nil
}

// RandomPrefixReloader хранит текущий набор и по запросу (Reload/Run)
// перечитывает файлы, атомарно подменяя набор.
type RandomPrefixReloader struct {
	source  RandomPrefixSource
	current atomic.Pointer[RandomPrefixSet]

	mtx     sync.Mutex
	last    randomPrefixFiles // содержимое файлов, которое уже видели (применённое или отклонённое)
	lastErr string
}

// NewRandomPrefixReloader делает первую загрузку; при любой ошибке
// возвращает её (сервер не должен стартовать с невалидными префиксами).
func NewRandomPrefixReloader(source RandomPrefixSource) (*RandomPrefixReloader, error) {
	files, err := source.read()
	if err != nil {
		return nil, err
	}
	set, err := source.build(files)
	if err != nil {
		return nil, err
	}
	r := &RandomPrefixReloader{source: source, last: files}
	r.current.Store(set)
	return r, nil
}

// Current реализует RandomPrefixProvider.
func (r *RandomPrefixReloader) Current() *RandomPrefixSet {
	return r.current.Load()
}

// Reload — одна итерация: перечитать файлы и, если содержимое изменилось,
// собрать и подменить набор. Невалидный или пустой результат отклоняется
// (остаётся прежний набор, ошибка пишется в лог один раз на изменение).
// Возвращает true, если набор был заменён.
func (r *RandomPrefixReloader) Reload(log RandomPrefixLogger) bool {
	r.mtx.Lock()
	defer r.mtx.Unlock()
	files, err := r.source.read()
	if err != nil {
		// Файл мог быть на миг недоступен (замена через rename и т.п.):
		// оставляем прежний набор, а в лог пишем только новое сообщение.
		if msg := err.Error(); msg != r.lastErr {
			r.lastErr = msg
			log.Error("client_random_prefix reload failed, keeping previous set: ", err)
		}
		return false
	}
	r.lastErr = ""
	if bytes.Equal(files.prefix, r.last.prefix) && bytes.Equal(files.secret, r.last.secret) {
		return false
	}
	r.last = files
	set, err := r.source.build(files)
	if err != nil {
		log.Error("client_random_prefix reload rejected, keeping previous set: ", err)
		return false
	}
	r.current.Store(set)
	log.Info("client_random_prefix reloaded: ", len(set.Prefixes), " prefixes, ", len(set.Secrets), " secrets")
	return true
}

// Run блокируется и раз в interval вызывает Reload, пока ctx не отменён.
// Ничего не делает, если файлы не заданы.
func (r *RandomPrefixReloader) Run(ctx context.Context, interval time.Duration, log RandomPrefixLogger) {
	if !r.source.HasFiles() {
		return
	}
	if interval <= 0 {
		interval = DefaultRandomPrefixReloadInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.Reload(log)
		}
	}
}
