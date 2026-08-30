package config

import (
	"os"
	"path/filepath"
	"testing"

	"pw/internal/filehandler"
)

func writeConfig(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestMergedRecipientsUnionDedup(t *testing.T) {
	root := t.TempDir()
	vault := filepath.Join(root, "vault")

	writeConfig(t, filepath.Join(root, ".pw.yml"), "recipients:\n  - A\n  - B\n")
	writeConfig(t, filepath.Join(vault, ".pw.yml"), "recipients:\n  - C\n")
	// Per-folder config overlaps with global (B) and adds a new recipient (D).
	writeConfig(t, filepath.Join(vault, "db", ".pw.yml"), "recipients:\n  - B\n  - D\n")

	cfg := &ConfigType{RootDir: root, DataDir: vault, ConfigFile: ".pw.yml"}
	fh := filehandler.NewFileHandler(root, false)
	uc := &UserConfigType{config: cfg, filehandler: fh, cache: map[string]UserConfigData{}}

	got := uc.GetRecipientsForPath("db/secret")
	want := []string{"A", "B", "C", "D"}
	if len(got) != len(want) {
		t.Fatalf("recipients = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("recipients = %v, want %v", got, want)
		}
	}
}

func TestMergedObscureNamesReplace(t *testing.T) {
	root := t.TempDir()
	vault := filepath.Join(root, "vault")

	writeConfig(t, filepath.Join(root, ".pw.yml"), "obscure_names: false\n")
	writeConfig(t, filepath.Join(vault, "db", ".pw.yml"), "obscure_names: true\n")

	cfg := &ConfigType{RootDir: root, DataDir: vault, ConfigFile: ".pw.yml"}
	fh := filehandler.NewFileHandler(root, false)
	uc := &UserConfigType{config: cfg, filehandler: fh, cache: map[string]UserConfigData{}}

	if !uc.GetObscureNamesForPath("db/secret") {
		t.Fatal("expected obscure_names true for db/secret")
	}
	if uc.GetObscureNamesForPath("other/secret") {
		t.Fatal("expected obscure_names false for other/secret")
	}
}
