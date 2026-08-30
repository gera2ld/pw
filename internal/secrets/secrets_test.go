package secrets

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
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
