package update

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

var Repo string

func fetchVersion() (string, error) {
	url := fmt.Sprintf("https://github.com/%s/releases/download/latest/version.txt", Repo)
	resp, err := http.Get(url)
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
	return strings.TrimSpace(string(data)), nil
}

func binaryURL() string {
	return fmt.Sprintf("https://github.com/%s/releases/download/latest/pw-%s-%s", Repo, runtime.GOOS, runtime.GOARCH)
}

func downloadAsset() (string, error) {
	resp, err := http.Get(binaryURL())
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return "", fmt.Errorf("no binary found for %s/%s", runtime.GOOS, runtime.GOARCH)
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
	resp, err := http.Head(binaryURL())
	if err != nil {
		return "", false, err
	}
	resp.Body.Close()
	return version, resp.StatusCode == 200, nil
}

func Install() error {
	tmpPath, err := downloadAsset()
	if err != nil {
		return err
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
