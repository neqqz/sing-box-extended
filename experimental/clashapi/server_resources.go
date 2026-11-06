package clashapi

import (
	"archive/zip"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/service/filemanager"
)

func (s *Server) checkAndDownloadExternalUI() {
	if s.externalUI == "" {
		return
	}
	entries, err := filemanager.ReadDir(s.ctx, s.externalUI)
	if err != nil {
		filemanager.MkdirAll(s.ctx, s.externalUI, 0o755)
	}
	if len(entries) == 0 {
		err = s.downloadExternalUI()
		if err != nil {
			s.logger.Error("download external ui error: ", err)
		}
	}
}

func (s *Server) downloadExternalUI() error {
	var downloadURL string
	if s.externalUIDownloadURL != "" {
		downloadURL = s.externalUIDownloadURL
	} else {
		downloadURL = "https://github.com/MetaCubeX/Yacd-meta/archive/gh-pages.zip"
	}
	var detour adapter.Outbound
	if s.externalUIDownloadDetour != "" {
		outbound, loaded := s.outbound.Outbound(s.externalUIDownloadDetour)
		if !loaded {
			return E.New("detour outbound not found: ", s.externalUIDownloadDetour)
		}
		detour = outbound
	} else {
		outbound := s.outbound.Default()
		detour = outbound
	}
	s.logger.Info("downloading external ui using outbound/", detour.Type(), "[", detour.Tag(), "]")
	httpClient := &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: C.TCPTimeout,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return detour.DialContext(ctx, network, M.ParseSocksaddr(addr))
			},
			TLSClientConfig: &tls.Config{
				Time:    ntp.TimeFuncFromContext(s.ctx),
				RootCAs: adapter.RootPoolFromContext(s.ctx),
			},
		},
	}
	defer httpClient.CloseIdleConnections()
	response, err := httpClient.Get(downloadURL)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return E.New("download external ui failed: ", response.Status)
	}
	err = s.downloadZIP(response.Body, s.externalUI)
	if err != nil {
		removeAllInDirectory(s.ctx, s.externalUI)
	}
	return err
}

const (
	maxExternalUIArchiveSize       = 256 << 20
	maxExternalUIEntrySize         = 64 << 20
	maxExternalUIExtractedSize     = 512 << 20
)

func (s *Server) downloadZIP(body io.Reader, output string) error {
	tempFile, err := filemanager.CreateTemp(s.ctx, "external-ui.zip")
	if err != nil {
		return err
	}
	defer filemanager.Remove(s.ctx, tempFile.Name())
	written, err := io.Copy(tempFile, io.LimitReader(body, maxExternalUIArchiveSize+1))
	tempFile.Close()
	if err != nil {
		return err
	}
	if written > maxExternalUIArchiveSize {
		return fmt.Errorf("external ui archive is too large")
	}
	reader, err := zip.OpenReader(tempFile.Name())
	if err != nil {
		return err
	}
	defer reader.Close()
	trimDir := zipIsInSingleDirectory(reader.File)
	var extractedSize uint64
	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}
		pathElements, ok := safeZIPPath(file.Name, trimDir)
		if !ok {
			return fmt.Errorf("unsafe path in external ui archive: %q", file.Name)
		}
		if file.FileInfo().Mode()&os.ModeSymlink != 0 || file.UncompressedSize64 > maxExternalUIEntrySize {
			return fmt.Errorf("unsafe entry in external ui archive: %q", file.Name)
		}
		if extractedSize > maxExternalUIExtractedSize-file.UncompressedSize64 {
			return fmt.Errorf("external ui contents are too large")
		}
		extractedSize += file.UncompressedSize64
		savePath := filepath.Join(append([]string{output}, pathElements...)...)
		cleanOutput := filepath.Clean(output)
		cleanPath := filepath.Clean(savePath)
		if cleanPath != cleanOutput && !strings.HasPrefix(cleanPath, cleanOutput+string(filepath.Separator)) {
			return fmt.Errorf("path escapes external ui directory: %q", file.Name)
		}
		saveDirectory := filepath.Dir(savePath)
		err = filemanager.MkdirAll(s.ctx, saveDirectory, 0o755)
		if err != nil {
			return err
		}
		err = downloadZIPEntry(s.ctx, file, savePath)
		if err != nil {
			return err
		}
	}
	return nil
}

func safeZIPPath(name string, trimDir bool) ([]string, bool) {
	if name == "" || strings.Contains(name, "\\") {
		return nil, false
	}
	// ZIP paths use '/', while filepath.IsLocal applies the platform's
	// absolute-path and traversal rules (including Windows drive paths).
	localName := filepath.FromSlash(name)
	if !filepath.IsLocal(localName) {
		return nil, false
	}
	parts := strings.Split(name, "/")
	if trimDir {
		if len(parts) < 2 {
			return nil, false
		}
		parts = parts[1:]
	}
	if len(parts) == 0 {
		return nil, false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, false
		}
	}
	return parts, true
}

func downloadZIPEntry(ctx context.Context, zipFile *zip.File, savePath string) error {
	saveFile, err := filemanager.Create(ctx, savePath)
	if err != nil {
		return err
	}
	defer saveFile.Close()
	reader, err := zipFile.Open()
	if err != nil {
		return err
	}
	defer reader.Close()
	return common.Error(io.Copy(saveFile, reader))
}

func removeAllInDirectory(ctx context.Context, directory string) {
	dirEntries, err := filemanager.ReadDir(ctx, directory)
	if err != nil {
		return
	}
	for _, dirEntry := range dirEntries {
		filemanager.RemoveAll(ctx, filepath.Join(directory, dirEntry.Name()))
	}
}

func zipIsInSingleDirectory(files []*zip.File) bool {
	var singleDirectory string
	for _, file := range files {
		if file.FileInfo().IsDir() {
			continue
		}
		pathElements := strings.Split(file.Name, "/")
		if len(pathElements) == 0 {
			return false
		}
		if singleDirectory == "" {
			singleDirectory = pathElements[0]
		} else if singleDirectory != pathElements[0] {
			return false
		}
	}
	return true
}
