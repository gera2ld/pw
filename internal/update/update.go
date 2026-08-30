package update

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

var Repo string

func versionURL() string {
	return fmt.Sprintf("https://github.com/%s/releases/latest/download/version.txt", Repo)
}

func fetchVersion() (string, error) {
	resp, err := http.Get(versionURL())
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return "", nil
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("failed to fetch version: status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	text := string(data)
	if i := strings.IndexByte(text, '\n'); i >= 0 {
		text = text[:i]
	}
	return strings.TrimSpace(text), nil
}

func fetchManifest() (map[string]string, error) {
	resp, err := http.Get(versionURL())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to fetch checksums: status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	hashes := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		hashes[fields[0]] = fields[1]
	}
	return hashes, nil
}

func assetName() string {
	name := fmt.Sprintf("pw-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

func archiveName() string {
	return assetName() + ".tar.gz"
}

func archiveURL() string {
	return fmt.Sprintf("https://github.com/%s/releases/latest/download/%s", Repo, archiveName())
}

func downloadAsset() (string, error) {
	resp, err := http.Get(archiveURL())
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return "", fmt.Errorf("no archive found for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("failed to download: status %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp("", "pw-update-*")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	tmp.Close()

	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return "", err
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return "", err
	}

	return tmpPath, nil
}

func CheckLatest() (string, bool, error) {
	if Repo == "" {
		return "", false, nil
	}
	version, err := fetchVersion()
	if err != nil {
		return "", false, err
	}
	resp, err := http.Head(archiveURL())
	if err != nil {
		return "", false, err
	}
	resp.Body.Close()
	return version, resp.StatusCode == 200, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func extractBinary(archivePath, name string) (string, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Name != name {
			continue
		}
		tmp, err := os.CreateTemp("", "pw-update-*")
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(tmp, tr); err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			return "", err
		}
		if err := tmp.Close(); err != nil {
			os.Remove(tmp.Name())
			return "", err
		}
		return tmp.Name(), nil
	}
	return "", fmt.Errorf("binary %s not found in archive", name)
}

func Install() error {
	hashes, err := fetchManifest()
	if err != nil {
		return fmt.Errorf("failed to fetch checksums: %w", err)
	}
	expected, ok := hashes[archiveName()]
	if !ok {
		return fmt.Errorf("no checksum found for %s", archiveName())
	}

	archivePath, err := downloadAsset()
	if err != nil {
		return err
	}

	actual, err := fileSHA256(archivePath)
	if err != nil {
		os.Remove(archivePath)
		return fmt.Errorf("failed to verify download: %w", err)
	}
	if actual != expected {
		os.Remove(archivePath)
		return fmt.Errorf("checksum mismatch for %s: expected %s, got %s", archiveName(), expected, actual)
	}

	tmpPath, err := extractBinary(archivePath, assetName())
	os.Remove(archivePath)
	if err != nil {
		return fmt.Errorf("failed to extract archive: %w", err)
	}

	if err := os.Chmod(tmpPath, 0755); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	dir := filepath.Dir(exePath)
	if err := os.Rename(tmpPath, filepath.Join(dir, filepath.Base(exePath))); err != nil {
		return fmt.Errorf("failed to replace binary: %w", err)
	}

	fmt.Println("Updated successfully")
	return nil
}
