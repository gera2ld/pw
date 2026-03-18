package secrets

import (
	"fmt"
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
			value:       "__id: github-token\nTOKEN: ghp_abc123\n",
			wantID:      "github-token",
			wantData:    map[string]any{"TOKEN": "ghp_abc123"},
			wantPayload: "",
			wantErr:     false,
		},
		{
			name:        "with data and payload",
			value:       "__id: ssh-key\nKEY: value\n---\n-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----\n",
			wantID:      "ssh-key",
			wantData:    map[string]any{"KEY": "value"},
			wantPayload: "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----\n",
			wantErr:     false,
		},
		{
			name:   "with local and export vars",
			value:  "__id: my-api\n_base_url: https://api.example.com\nAPI_KEY: secret123\nENDPOINT: $_base_url/v1\n",
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
			name:    "missing __id",
			value:   "FOO: bar\nBAZ: qux\n",
			wantErr: true,
		},
		{
			name:        "just __id with payload",
			value:       "__id: test\n---\nraw payload data\n",
			wantID:      "test",
			wantData:    map[string]any{},
			wantPayload: "raw payload data\n",
			wantErr:     false,
		},
		{
			name:        "empty data with payload",
			value:       "__id: test\n---\n",
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
			if got.Data["__id"].(string) != tt.wantID {
				t.Errorf("Data[__id] = %v, want %v", got.Data["__id"], tt.wantID)
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
			t.Logf("Got: ID=%q, Data=%+v, Payload=%q", got.Data["__id"], got.Data, got.Payload)
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
				Data:    map[string]any{"__id": "github-token", "TOKEN": "ghp_abc123"},
				Payload: "",
			},
			wantContains: []string{"__id: github-token", "TOKEN: ghp_abc123"},
		},
		{
			name: "with payload",
			value: &Secret{
				Data:    map[string]any{"__id": "ssh-key", "KEY": "value"},
				Payload: "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----",
			},
			wantContains: []string{"__id: ssh-key", "KEY: value", "-----BEGIN OPENSSH PRIVATE KEY-----"},
		},
		{
			name: "just data",
			value: &Secret{
				Data: map[string]any{"__id": "test", "FOO": "bar"},
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

	parsed, err := d.ParseRawValue(`__id: my-api
_base_url: https://api.example.com
API_KEY: secret123
ENDPOINT: $_base_url/v1
`)
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
}
