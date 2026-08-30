package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func writeTarGz(t *testing.T, path string, files map[string][]byte) {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name:     name,
			Mode:     0o755,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestExtractBinary(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "pw-test.tar.gz")
	content := []byte("fake binary")
	writeTarGz(t, archive, map[string][]byte{"pw-test": content})

	got, err := extractBinary(archive, "pw-test")
	if err != nil {
		t.Fatalf("extractBinary: %v", err)
	}
	defer os.Remove(got)

	data, err := os.ReadFile(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, content) {
		t.Fatalf("extracted content mismatch: got %q", data)
	}
}

func TestExtractBinaryMissingEntry(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "pw-test.tar.gz")
	writeTarGz(t, archive, map[string][]byte{"other": []byte("x")})

	if _, err := extractBinary(archive, "pw-test"); err == nil {
		t.Fatal("expected error for missing entry")
	}
}
