package tls

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type testPrefixLogger struct {
	mtx    sync.Mutex
	infos  []string
	errors []string
}

func (l *testPrefixLogger) Info(args ...any) {
	l.mtx.Lock()
	defer l.mtx.Unlock()
	l.infos = append(l.infos, sprintArgs(args))
}

func (l *testPrefixLogger) Error(args ...any) {
	l.mtx.Lock()
	defer l.mtx.Unlock()
	l.errors = append(l.errors, sprintArgs(args))
}

func (l *testPrefixLogger) counts() (int, int) {
	l.mtx.Lock()
	defer l.mtx.Unlock()
	return len(l.infos), len(l.errors)
}

func sprintArgs(args []any) string {
	return fmt.Sprint(args...)
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

func TestParseListFile(t *testing.T) {
	require.Empty(t, ParseListFile(nil))
	got := ParseListFile([]byte("\ufeff# header\r\naabb   # alice\r\n\r\n  ccdd/ff00\n#only comment\n11\n"))
	require.Equal(t, []string{"aabb", "ccdd/ff00", "11"}, got)
}

func TestRandomPrefixSourceEnabled(t *testing.T) {
	require.False(t, RandomPrefixSource{}.Enabled())
	require.False(t, RandomPrefixSource{Prefixes: []string{""}, Secrets: []string{""}}.Enabled())
	require.True(t, RandomPrefixSource{Prefixes: []string{"aa"}}.Enabled())
	require.True(t, RandomPrefixSource{SecretFile: "/x"}.Enabled())
	require.True(t, RandomPrefixSource{PrefixFile: "/x"}.HasFiles())
	require.False(t, RandomPrefixSource{Secrets: []string{"aa"}}.HasFiles())
}

func TestRandomPrefixReloaderInitialLoad(t *testing.T) {
	dir := t.TempDir()
	secretFile := filepath.Join(dir, "secrets.txt")

	t.Run("inline and file entries are merged", func(t *testing.T) {
		writeFile(t, secretFile, "# users\n0102 # alice\n0304 # bob\n")
		r, err := NewRandomPrefixReloader(RandomPrefixSource{Secrets: []string{"ff"}, SecretFile: secretFile})
		require.NoError(t, err)
		require.Len(t, r.Current().Secrets, 3)
		require.Empty(t, r.Current().Prefixes)
	})

	t.Run("nothing configured yields an error, never an open set", func(t *testing.T) {
		writeFile(t, secretFile, "# nothing here\n")
		_, err := NewRandomPrefixReloader(RandomPrefixSource{SecretFile: secretFile})
		require.Error(t, err)
	})

	t.Run("mutually exclusive modes", func(t *testing.T) {
		writeFile(t, secretFile, "0102\n")
		_, err := NewRandomPrefixReloader(RandomPrefixSource{Prefixes: []string{"aabb"}, SecretFile: secretFile})
		require.Error(t, err)
	})

	t.Run("bad content and missing file", func(t *testing.T) {
		writeFile(t, secretFile, "not-hex\n")
		_, err := NewRandomPrefixReloader(RandomPrefixSource{SecretFile: secretFile})
		require.Error(t, err)
		_, err = NewRandomPrefixReloader(RandomPrefixSource{SecretFile: filepath.Join(dir, "missing.txt")})
		require.Error(t, err)
	})
}

func TestRandomPrefixReloaderReload(t *testing.T) {
	dir := t.TempDir()
	secretFile := filepath.Join(dir, "secrets.txt")
	prefixFile := filepath.Join(dir, "prefixes.txt")
	writeFile(t, secretFile, "0102\n")
	writeFile(t, prefixFile, "")
	log := &testPrefixLogger{}

	r, err := NewRandomPrefixReloader(RandomPrefixSource{SecretFile: secretFile, PrefixFile: prefixFile})
	require.NoError(t, err)
	require.Len(t, r.Current().Secrets, 1)

	// unchanged content -> nothing happens
	require.False(t, r.Reload(log))

	// add a secret -> swapped
	writeFile(t, secretFile, "0102\n0304\n")
	require.True(t, r.Reload(log))
	require.Len(t, r.Current().Secrets, 2)
	infos, errs := log.counts()
	require.Equal(t, 1, infos)
	require.Equal(t, 0, errs)

	// invalid content -> rejected once, previous set kept, not retried every tick
	writeFile(t, secretFile, "zzzz\n")
	require.False(t, r.Reload(log))
	require.False(t, r.Reload(log))
	require.Len(t, r.Current().Secrets, 2)
	_, errs = log.counts()
	require.Equal(t, 1, errs)

	// empty content -> rejected (fail closed), previous set kept
	writeFile(t, secretFile, "# all removed\n")
	require.False(t, r.Reload(log))
	require.Len(t, r.Current().Secrets, 2)

	// switching to static mode: secret file emptied + prefix file filled is only
	// valid once both files are consistent
	writeFile(t, prefixFile, "aabb\nccdd/ff00\n")
	require.True(t, r.Reload(log))
	require.Empty(t, r.Current().Secrets)
	require.Len(t, r.Current().Prefixes, 2)
	random := make([]byte, 32)
	random[0], random[1] = 0xaa, 0xbb
	require.True(t, MatchAnyRandomPrefix(r.Current().Prefixes, random))

	// both modes at once -> rejected, previous (static) set kept
	writeFile(t, secretFile, "0102\n")
	require.False(t, r.Reload(log))
	require.Len(t, r.Current().Prefixes, 2)
	require.Empty(t, r.Current().Secrets)

	// file temporarily unreadable -> previous set kept, error logged once
	require.NoError(t, os.Remove(prefixFile))
	_, before := log.counts()
	require.False(t, r.Reload(log))
	require.False(t, r.Reload(log))
	_, after := log.counts()
	require.Equal(t, before+1, after)
	require.Len(t, r.Current().Prefixes, 2)

	// file is back and consistent again
	writeFile(t, prefixFile, "")
	writeFile(t, secretFile, "0506\n")
	require.True(t, r.Reload(log))
	require.Len(t, r.Current().Secrets, 1)
	require.Empty(t, r.Current().Prefixes)
}

func TestRandomPrefixReloaderRun(t *testing.T) {
	dir := t.TempDir()
	secretFile := filepath.Join(dir, "secrets.txt")
	writeFile(t, secretFile, "0102\n")
	log := &testPrefixLogger{}

	r, err := NewRandomPrefixReloader(RandomPrefixSource{SecretFile: secretFile})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.Run(ctx, 10*time.Millisecond, log)
		close(done)
	}()

	writeFile(t, secretFile, "0102\n0304\n0506\n")
	deadline := time.Now().Add(3 * time.Second)
	for len(r.Current().Secrets) != 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	require.Len(t, r.Current().Secrets, 3)

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not stop after context cancel")
	}

	// no files -> Run returns immediately
	inlineOnly, err := NewRandomPrefixReloader(RandomPrefixSource{Prefixes: []string{"aa"}})
	require.NoError(t, err)
	finished := make(chan struct{})
	go func() {
		inlineOnly.Run(context.Background(), 10*time.Millisecond, log)
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("Run should return immediately without files")
	}
}
