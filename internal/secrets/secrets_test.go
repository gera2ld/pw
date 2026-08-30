package secrets

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"pw/internal/config"
	"pw/internal/filehandler"
)

func TestParseRawValue(t *testing.T) {
	d := &SecretManager{}

	tests := []struct {
		name        string
		value       string
		wantID      string
		wantData    map[string]any
		wantPayload string
		wantErr     bool
	}{
		{
			name:        "basic with data",
			value:       "__name: github-token\nTOKEN: ghp_abc123\n",
			wantID:      "github-token",
			wantData:    map[string]any{"TOKEN": "ghp_abc123"},
			wantPayload: "",
			wantErr:     false,
		},
		{
			name:        "with data and payload",
			value:       "__name: ssh-key\nKEY: value\n---\n-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----\n",
			wantID:      "ssh-key",
			wantData:    map[string]any{"KEY": "value"},
			wantPayload: "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----\n",
			wantErr:     false,
		},
		{
			name:   "with local and export vars",
			value:  "__name: my-api\n_base_url: https://api.example.com\nAPI_KEY: secret123\nENDPOINT: $_base_url/v1\n",
			wantID: "my-api",
			wantData: map[string]any{
				"_base_url": "https://api.example.com",
				"API_KEY":   "secret123",
				"ENDPOINT":  "$_base_url/v1",
			},
			wantPayload: "",
			wantErr:     false,
		},
		{
			name:    "missing __name",
			value:   "FOO: bar\nBAZ: qux\n",
			wantErr: true,
		},
		{
			name:        "just __name with payload",
			value:       "__name: test\n---\nraw payload data\n",
			wantID:      "test",
			wantData:    map[string]any{},
			wantPayload: "raw payload data\n",
			wantErr:     false,
		},
		{
			name:        "empty data with payload",
			value:       "__name: test\n---\n",
			wantID:      "test",
			wantData:    map[string]any{},
			wantPayload: "",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := d.ParseRawValue(tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRawValue() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if got.Data["__name"].(string) != tt.wantID {
				t.Errorf("Data[__name] = %v, want %v", got.Data["__name"], tt.wantID)
			}
			for k, v := range tt.wantData {
				if got.Data[k] != v {
					t.Errorf("Data[%q] = %v, want %v", k, got.Data[k], v)
				}
			}
			if got.Payload != tt.wantPayload {
				t.Errorf("Payload = %q, want %q", got.Payload, tt.wantPayload)
			}
			t.Logf("Input: %q", tt.value)
			t.Logf("Got: ID=%q, Data=%+v, Payload=%q", got.Data["__name"], got.Data, got.Payload)
		})
	}
}

func TestFormatValue(t *testing.T) {
	d := &SecretManager{}

	tests := []struct {
		name         string
		value        *Secret
		wantContains []string
	}{
		{
			name: "basic with data",
			value: &Secret{
				Data:    map[string]any{"__name": "github-token", "TOKEN": "ghp_abc123"},
				Payload: "",
			},
			wantContains: []string{"__name: github-token", "TOKEN: ghp_abc123"},
		},
		{
			name: "with payload",
			value: &Secret{
				Data:    map[string]any{"__name": "ssh-key", "KEY": "value"},
				Payload: "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----",
			},
			wantContains: []string{"__name: ssh-key", "KEY: value", "-----BEGIN OPENSSH PRIVATE KEY-----"},
		},
		{
			name: "just data",
			value: &Secret{
				Data: map[string]any{"__name": "test", "FOO": "bar"},
			},
			wantContains: []string{"FOO: bar"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := d.FormatValue(tt.value)
			if err != nil {
				t.Errorf("FormatValue() error = %v", err)
				return
			}
			for _, want := range tt.wantContains {
				if !strings.Contains(got, want) {
					t.Errorf("FormatValue() = %q, should contain %q", got, want)
				}
			}
		})
	}
}

func TestParseSecret(t *testing.T) {
	d := &SecretManager{}

	parsed, err := d.ParseRawValue("__name: my-api\n_base_url: \"https://api.example.com\"\nAPI_KEY: secret123\nENDPOINT: '{{._base_url}}/v1'\n_PASSWORD: p@ss$word!\n")
	if err != nil {
		t.Fatalf("ParseRawValue() error = %v", err)
	}

	result := Vars{Local: make(map[string]string), Env: make(map[string]string)}

	for k, v := range parsed.Data {
		strVal := fmt.Sprintf("%v", v)
		if strings.HasPrefix(k, "__") {
			continue
		}
		if strings.HasPrefix(k, "_") {
			result.Local[k] = strVal
		} else {
			result.Env[k] = strVal
		}
	}

	for k, v := range result.Env {
		result.Env[k] = resolveVariables(v, result.Local)
	}

	t.Logf("Local vars: %+v", result.Local)
	t.Logf("Env vars: %+v", result.Env)

	if result.Local["_base_url"] != "https://api.example.com" {
		t.Errorf("Local _base_url = %q, want %q", result.Local["_base_url"], "https://api.example.com")
	}
	if result.Env["ENDPOINT"] != "https://api.example.com/v1" {
		t.Errorf("Env ENDPOINT = %q, want %q", result.Env["ENDPOINT"], "https://api.example.com/v1")
	}
	if result.Env["API_KEY"] != "secret123" {
		t.Errorf("Env API_KEY = %q, want %q", result.Env["API_KEY"], "secret123")
	}
	if result.Local["_PASSWORD"] != "p@ss$word!" {
		t.Errorf("Local _PASSWORD = %q, want %q", result.Local["_PASSWORD"], "p@ss$word!")
	}
}

func TestValidateTemplates(t *testing.T) {
	d := &SecretManager{}

	valid := "__name: test\nURL: '{{._base}}/api'\n"
	invalid := "__name: test\nURL: '{{._base'\n"

	secret, err := d.ParseRawValue(valid)
	if err != nil {
		t.Fatalf("ParseRawValue() error = %v", err)
	}
	if err := d.ValidateTemplates(secret); err != nil {
		t.Errorf("ValidateTemplates() valid = %v", err)
	}

	secret, err = d.ParseRawValue(invalid)
	if err != nil {
		t.Fatalf("ParseRawValue() error = %v", err)
	}
	if err := d.ValidateTemplates(secret); err == nil {
		t.Errorf("ValidateTemplates() invalid = expected error, got nil")
	}
}

func TestNormalizeFilename(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"My Pass", "my-pass"},
		{"my_pass", "my_pass"},
		{"my-pass", "my-pass"},
		{"My.Var@host", "my-var-host"},
		{"A_B-C", "a_b-c"},
		{strings.Repeat("a", 50), strings.Repeat("a", 40)},
		{"!!!", "secret"},
	}
	for _, tt := range tests {
		if got := normalizeFilename(tt.name); got != tt.want {
			t.Errorf("normalizeFilename(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestIsReadableFilename(t *testing.T) {
	tests := []struct {
		uid  string
		name string
		want bool
	}{
		{"db/prod/password", "password", true},
		{"db/prod/my-pass", "my-pass", true},
		{"db/prod/my_pass", "my_pass", true},
		{"db/prod/my-pass.2", "my pass", true},
		{"db/prod/abc123def456", "password", false},
	}
	for _, tt := range tests {
		if got := isReadableFilename(tt.uid, tt.name); got != tt.want {
			t.Errorf("isReadableFilename(%q, %q) = %v, want %v", tt.uid, tt.name, got, tt.want)
		}
	}
}

func TestUniqueReadableUID(t *testing.T) {
	d := &SecretManager{}
	index := map[string]string{
		filepath.Join("db/prod", "password"):   "db/prod/password",
		filepath.Join("db/prod", "password.2"): "db/prod/password2",
	}

	// No exclusion: first free is password.3.
	if got := d.uniqueReadableUID(filepath.Join("db/prod", "password"), &index, ""); got != filepath.Join("db/prod", "password.3") {
		t.Errorf("uniqueReadableUID() = %q, want %q", got, filepath.Join("db/prod", "password.3"))
	}

	// Excluding the current uid: still must be free (password.3).
	if got := d.uniqueReadableUID(filepath.Join("db/prod", "password"), &index, filepath.Join("db/prod", "password")); got != filepath.Join("db/prod", "password.3") {
		t.Errorf("uniqueReadableUID() = %q, want %q", got, filepath.Join("db/prod", "password.3"))
	}
}

func TestFuzzyFullIDMatches(t *testing.T) {
	tests := []struct {
		query  string
		fullID string
		want   bool
	}{
		{"a/b", "/a/b", true},
		{"a/b", "/whatever/a/xxx/b", true},
		{"a/b", "/x/a/c/b", true},
		{"a/b/c", "/x/a/b/c", true},
		{"a/b/c", "/x/b/a/c", false},
		{"a/b", "/x/a/c", false},
		{"b", "/x/a/b", true},
		{"b", "/x/a/c", false},
		{"x/y", "/x/y", true},
		{"x/y", "/z/x/y", true},
		{"x/y", "/y/z/x", false},
		{"a/b", "/b/a", false},
		{"a/b", "/b", false},
		{"", "/a/b", false},
	}
	for _, tt := range tests {
		if got := fuzzyFullIDMatches(tt.query, tt.fullID); got != tt.want {
			t.Errorf("fuzzyFullIDMatches(%q, %q) = %v, want %v", tt.query, tt.fullID, got, tt.want)
		}
	}
}

func TestResolveKey(t *testing.T) {
	index := &map[string]string{
		"db/prod/password": "/db/prod/password",
		"x/a/y/b":          "/x/a/y/b",
		"db/z/b":           "/db/z/b",
	}
	d := &SecretManager{index: index}

	// Exact match with leading "/".
	got, err := d.ResolveKey("/db/prod/password")
	if err != nil || got != "/db/prod/password" {
		t.Errorf("ResolveKey(/db/prod/password) = %q, %v", got, err)
	}

	// Exact miss with leading "/" -> not found.
	if _, err := d.ResolveKey("/db/prod/missing"); err == nil {
		t.Error("ResolveKey(/db/prod/missing) expected error")
	}

	// Fuzzy single match.
	got, err = d.ResolveKey("password")
	if err != nil || got != "/db/prod/password" {
		t.Errorf("ResolveKey(password) = %q, %v", got, err)
	}

	// Fuzzy subsequence single match.
	got, err = d.ResolveKey("prod/password")
	if err != nil || got != "/db/prod/password" {
		t.Errorf("ResolveKey(prod/password) = %q, %v", got, err)
	}

	// Ambiguous: both /db/prod/password and /x/a/y/b match "b".
	if _, err := d.ResolveKey("b"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Errorf("ResolveKey(b) expected ambiguous error, got %v", err)
	}

	// Ambiguous: "a/b" matches both /db/prod/password? No: basename must be b.
	// /x/a/y/b matches (basename b, ancestor a), /db/prod/password does not.
	got, err = d.ResolveKey("a/b")
	if err != nil || got != "/x/a/y/b" {
		t.Errorf("ResolveKey(a/b) = %q, %v", got, err)
	}
}

func TestReencryptAll(t *testing.T) {
	if _, err := exec.LookPath("age"); err != nil {
		t.Skip("age not available; skipping reencrypt test")
	}
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not available; skipping reencrypt test")
	}

	root := t.TempDir()
	id1 := filepath.Join(root, "id1")
	id2 := filepath.Join(root, "id2")

	genKey := func(path string) string {
		if out, err := exec.Command("age-keygen", "-o", path).CombinedOutput(); err != nil {
			t.Fatalf("age-keygen: %v: %s", err, out)
		}
		out, err := exec.Command("age-keygen", "-y", path).Output()
		if err != nil {
			t.Fatalf("age-keygen -y: %v", err)
		}
		return strings.TrimSpace(string(out))
	}
	pub1 := genKey(id1)
	pub2 := genKey(id2)

	// Global recipients include id1; a per-folder config (db/) adds id2.
	if err := os.WriteFile(filepath.Join(root, ".pw.yml"), []byte("recipients:\n  - "+pub1+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "vault", "db"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "vault", "db", ".pw.yml"), []byte("recipients:\n  - "+pub2+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.ConfigType{
		RootDir:    root,
		Identities: id1,
		DataDir:    filepath.Join(root, "vault"),
		EnvSuffix:  ".age",
		IndexFile:  filepath.Join(root, "vault", "index.dat.age"),
		ConfigFile: ".pw.yml",
	}
	fh := filehandler.NewFileHandler(root, false)
	uc := config.NewUserConfig(cfg, fh)
	sm := NewSecretManager(cfg, uc, fh)

	val := &Secret{Data: map[string]any{"__name": "password", "TOKEN": "secret123"}}
	if err := sm.SetSecret("/db/prod/password", val); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}

	if _, err := sm.ReencryptAll(); err != nil {
		t.Fatalf("ReencryptAll: %v", err)
	}

	// Content survives re-encryption under id1.
	got, err := sm.GetSecret("/db/prod/password")
	if err != nil {
		t.Fatalf("GetSecret after reencrypt: %v", err)
	}
	if got.Data["TOKEN"] != "secret123" {
		t.Fatalf("TOKEN = %v, want secret123", got.Data["TOKEN"])
	}

	// Per-folder recipients (id2) are honored during reencrypt: id2 can decrypt.
	uid, err := sm.GetSecretUID("/db/prod/password")
	if err != nil {
		t.Fatalf("GetSecretUID: %v", err)
	}
	enc, err := fh.ReadFile(sm.GetSecretPath(uid))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	decCmd := exec.Command("age", "--decrypt", "-i", id2)
	decCmd.Stdin = strings.NewReader(enc)
	out, err := decCmd.Output()
	if err != nil {
		t.Fatalf("decrypt with id2: %v", err)
	}
	if !strings.Contains(string(out), "secret123") {
		t.Fatalf("decrypted content missing secret: %s", out)
	}
}

func TestResolveKeys(t *testing.T) {
	index := &map[string]string{
		"db/prod/password": "/db/prod/password",
		"x/a/y/b":          "/x/a/y/b",
		"db/z/b":           "/db/z/b",
	}
	d := &SecretManager{index: index}

	// Exact match with leading "/".
	got, err := d.ResolveKeys("/db/prod/password")
	if err != nil || !reflect.DeepEqual(got, []string{"/db/prod/password"}) {
		t.Errorf("ResolveKeys(/db/prod/password) = %v, %v", got, err)
	}

	// Exact miss with leading "/" -> not found.
	if _, err := d.ResolveKeys("/db/prod/missing"); err == nil {
		t.Error("ResolveKeys(/db/prod/missing) expected error")
	}

	// Fuzzy single match.
	got, err = d.ResolveKeys("password")
	if err != nil || !reflect.DeepEqual(got, []string{"/db/prod/password"}) {
		t.Errorf("ResolveKeys(password) = %v, %v", got, err)
	}

	// Fuzzy ambiguous is allowed: returns both matches sorted.
	got, err = d.ResolveKeys("b")
	if err != nil || !reflect.DeepEqual(got, []string{"/db/z/b", "/x/a/y/b"}) {
		t.Errorf("ResolveKeys(b) = %v, %v", got, err)
	}

	// No match.
	if _, err := d.ResolveKeys("nope"); err == nil {
		t.Error("ResolveKeys(nope) expected error")
	}

	// Glob: "*" matches a single path segment only (never crosses "/").
	index2 := &map[string]string{
		"server/web":         "/server/web",
		"server/db/password": "/server/db/password",
		"gitlab/foo":         "/gitlab/foo",
		"db/prod/password":   "/db/prod/password",
	}
	d2 := &SecretManager{index: index2}
	// "server/*" matches exactly one segment under server/.
	got, err = d2.ResolveKeys("server/*")
	if err != nil || !reflect.DeepEqual(got, []string{"/server/web"}) {
		t.Errorf("ResolveKeys(server/*) = %v, %v", got, err)
	}
	// "git*/*" matches "gitlab/foo" but not deeper/none.
	got, err = d2.ResolveKeys("git*/*")
	if err != nil || !reflect.DeepEqual(got, []string{"/gitlab/foo"}) {
		t.Errorf("ResolveKeys(git*/*) = %v, %v", got, err)
	}
	// Rooted glob "/server/*" anchors at root.
	got, err = d2.ResolveKeys("/server/*")
	if err != nil || !reflect.DeepEqual(got, []string{"/server/web"}) {
		t.Errorf("ResolveKeys(/server/*) = %v, %v", got, err)
	}
	// "*" alone matches only depth-1 ids (none here).
	if _, err := d2.ResolveKeys("*"); err == nil {
		t.Error("ResolveKeys(*) expected error (no depth-1 secrets)")
	}
}

func TestResolveFilterKeys(t *testing.T) {
	index := &map[string]string{
		"db/prod/password": "/db/prod/password",
		"x/a/y/b":          "/x/a/y/b",
		"db/z/b":           "/db/z/b",
	}
	d := &SecretManager{index: index}

	// Union of two filters, deduped and sorted. "password" matches 1 key,
	// "b" matches 2 (one of which overlaps with the exact "/db/prod/password").
	got, err := d.ResolveFilterKeys("password", "b", "/db/prod/password")
	if err != nil {
		t.Fatalf("ResolveFilterKeys: %v", err)
	}
	want := []string{"/db/prod/password", "/db/z/b", "/x/a/y/b"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ResolveFilterKeys = %v, want %v", got, want)
	}

	// A filter matching nothing is an error.
	if _, err := d.ResolveFilterKeys("nope"); err == nil {
		t.Error("ResolveFilterKeys(nope) expected error")
	}

	// Glob filters: union of "server/*" and "git*/*" across the index.
	d2 := &SecretManager{index: &map[string]string{
		"server/web":         "/server/web",
		"server/db/password": "/server/db/password",
		"gitlab/foo":         "/gitlab/foo",
		"db/prod/password":   "/db/prod/password",
	}}
	got, err = d2.ResolveFilterKeys("server/*", "git*/*")
	if err != nil {
		t.Fatalf("ResolveFilterKeys glob: %v", err)
	}
	want = []string{"/gitlab/foo", "/server/web"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ResolveFilterKeys glob = %v, want %v", got, want)
	}
}

func TestReencryptAllFiltered(t *testing.T) {
	if _, err := exec.LookPath("age"); err != nil {
		t.Skip("age not available; skipping reencrypt filter test")
	}
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not available; skipping reencrypt filter test")
	}

	root := t.TempDir()
	id1 := filepath.Join(root, "id1")
	id2 := filepath.Join(root, "id2")

	genKey := func(path string) string {
		if out, err := exec.Command("age-keygen", "-o", path).CombinedOutput(); err != nil {
			t.Fatalf("age-keygen: %v: %s", err, out)
		}
		out, err := exec.Command("age-keygen", "-y", path).Output()
		if err != nil {
			t.Fatalf("age-keygen -y: %v", err)
		}
		return strings.TrimSpace(string(out))
	}
	pub1 := genKey(id1)
	pub2 := genKey(id2)

	// Global recipients: only id1 initially.
	if err := os.WriteFile(filepath.Join(root, ".pw.yml"), []byte("recipients:\n  - "+pub1+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.ConfigType{
		RootDir:    root,
		Identities: id1,
		DataDir:    filepath.Join(root, "vault"),
		EnvSuffix:  ".age",
		IndexFile:  filepath.Join(root, "vault", "index.dat.age"),
		ConfigFile: ".pw.yml",
	}
	fh := filehandler.NewFileHandler(root, false)
	uc := config.NewUserConfig(cfg, fh)
	sm := NewSecretManager(cfg, uc, fh)

	dbVal := &Secret{Data: map[string]any{"__name": "password", "TOKEN": "dbpass"}}
	otherVal := &Secret{Data: map[string]any{"__name": "password", "TOKEN": "otherpass"}}
	if err := sm.SetSecret("/db/prod/password", dbVal); err != nil {
		t.Fatalf("SetSecret db: %v", err)
	}
	if err := sm.SetSecret("/other/secret", otherVal); err != nil {
		t.Fatalf("SetSecret other: %v", err)
	}
	dbUID, _ := sm.GetSecretUID("/db/prod/password")
	otherUID, _ := sm.GetSecretUID("/other/secret")

	canDecrypt := func(uid string) bool {
		enc, err := fh.ReadFile(sm.GetSecretPath(uid))
		if err != nil {
			return false
		}
		cmd := exec.Command("age", "--decrypt", "-i", id2)
		cmd.Stdin = strings.NewReader(enc)
		return cmd.Run() == nil
	}

	// Before adding a per-folder recipient and re-encrypting, id2 can decrypt neither.
	if canDecrypt(dbUID) || canDecrypt(otherUID) {
		t.Fatal("id2 should not decrypt before re-encrypt")
	}

	// Dry-run must not mutate: list targets, still not decryptable.
	targets, err := sm.ReencryptTargets("/db/prod/password")
	if err != nil || !reflect.DeepEqual(targets, []string{"/db/prod/password"}) {
		t.Fatalf("dry-run targets = %v, %v", targets, err)
	}
	if canDecrypt(dbUID) {
		t.Fatal("dry-run mutated the file")
	}

	// A filter matching nothing is an error.
	if _, err := sm.ReencryptTargets("/nope"); err == nil {
		t.Fatal("expected not-found error for /nope")
	}

	// Add a per-folder recipient for db/ and re-encrypt only the matched secret.
	// Rebuild the config/manager so the per-folder file is read fresh (a real
	// `pw reencrypt` is a fresh process; the merged config is cached per process).
	if err := os.MkdirAll(filepath.Join(root, "vault", "db"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "vault", "db", ".pw.yml"), []byte("recipients:\n  - "+pub2+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	uc = config.NewUserConfig(cfg, fh)
	sm = NewSecretManager(cfg, uc, fh)
	dbUID, _ = sm.GetSecretUID("/db/prod/password")
	otherUID, _ = sm.GetSecretUID("/other/secret")

	targets, err = sm.ReencryptAll("/db/prod/password")
	if err != nil {
		t.Fatalf("ReencryptAll filtered: %v", err)
	}
	if !reflect.DeepEqual(targets, []string{"/db/prod/password"}) {
		t.Fatalf("filtered targets = %v, want [/db/prod/password]", targets)
	}

	// Matched secret is now decryptable by id2; the non-matched one is not.
	if !canDecrypt(dbUID) {
		t.Fatal("matched secret should be decryptable by id2 after re-encrypt")
	}
	if canDecrypt(otherUID) {
		t.Fatal("non-matched secret must remain undecryptable by id2")
	}
}
