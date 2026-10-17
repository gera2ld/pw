package secrets

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Secret bodies use a flat "KEY=VALUE" list, one pair per line, with `#`
// comments. A line containing only "---" separates the body from an optional
// raw payload. Values are always strings: there is no scalar typing, so a value
// like `0xdeadbeef` or `2026-01-02` is never coerced into a number, boolean or
// timestamp on a read/write round-trip.
//
// Quoting rules:
//   - KEY=VALUE      VALUE is trimmed of surrounding whitespace and taken literally.
//   - KEY="VALUE"    VALUE is trimmed, then unescaped (\n \t \r \\ \").
//   - KEY='VALUE'    VALUE is trimmed, then taken literally.
//
// A line whose first non-whitespace character is `#` is a comment. Comments and
// quoting are preserved verbatim because the original text is kept as-is.

const bodySeparator = "---"

// splitBody separates a secret's text into its body and optional payload. The
// payload is everything after the first line that is exactly "---".
func splitBody(text string) (body, payload string) {
	lines := strings.Split(text, "\n")
	i := indexOf(lines, bodySeparator, 0)
	if i < 0 {
		return text, ""
	}
	if i < len(lines)-1 {
		payload = strings.Join(lines[i+1:], "\n")
	}
	return strings.Join(lines[:i], "\n"), payload
}

// parseBody parses body as the KEY=VALUE format. The second result reports
// whether the body had to be read as legacy YAML instead, in which case the
// values are stringified with fmt's default formatting.
func parseBody(body string) (map[string]string, bool, error) {
	data, err := parseKV(body)
	if err == nil {
		return data, false, nil
	}
	legacy, legacyErr := parseLegacyYAML(body)
	if legacyErr != nil {
		return nil, false, err
	}
	return legacy, true, nil
}

func parseKV(body string) (map[string]string, error) {
	data := make(map[string]string)
	for _, line := range strings.Split(body, "\n") {
		if isBlankOrComment(line) {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			return nil, fmt.Errorf("invalid line %q: expected KEY=VALUE", strings.TrimSpace(line))
		}
		key := strings.TrimSpace(line[:eq])
		if key == "" || strings.ContainsAny(key, " \t") {
			return nil, fmt.Errorf("invalid key in line %q", strings.TrimSpace(line))
		}
		if _, dup := data[key]; dup {
			return nil, fmt.Errorf("duplicate key %q", key)
		}
		data[key] = parseValue(line[eq+1:])
	}
	return data, nil
}

func isBlankOrComment(line string) bool {
	t := strings.TrimSpace(line)
	return t == "" || strings.HasPrefix(t, "#")
}

func parseValue(raw string) string {
	v := strings.TrimSpace(raw)
	if len(v) >= 2 {
		switch {
		case v[0] == '"' && v[len(v)-1] == '"':
			return unescapeDouble(v[1 : len(v)-1])
		case v[0] == '\'' && v[len(v)-1] == '\'':
			return v[1 : len(v)-1]
		}
	}
	return v
}

func unescapeDouble(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		switch s[i+1] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case '\\':
			b.WriteByte('\\')
		case '"':
			b.WriteByte('"')
		default:
			b.WriteByte('\\')
			continue
		}
		i++ // consume the escaped character
	}
	return b.String()
}

func parseLegacyYAML(body string) (map[string]string, error) {
	var raw map[string]any
	if err := yaml.Unmarshal([]byte(body), &raw); err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, errors.New("empty body")
	}
	data := make(map[string]string, len(raw))
	for k, v := range raw {
		if v == nil {
			data[k] = ""
			continue
		}
		if s, ok := v.(string); ok {
			data[k] = s
			continue
		}
		data[k] = fmt.Sprintf("%v", v)
	}
	return data, nil
}

// formatBody renders data as canonical KEY=VALUE text: __name first, then the
// remaining keys sorted. It is only used when there is no original text to
// preserve (e.g. a programmatically built secret).
func formatBody(data map[string]string) string {
	keys := make([]string, 0, len(data))
	for k := range data {
		if k == keyName || k == keyLegacyID {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	if name, ok := data[keyName]; ok {
		writePair(&b, keyName, name)
	}
	for _, k := range keys {
		writePair(&b, k, data[k])
	}
	return b.String()
}

func writePair(b *strings.Builder, key, value string) {
	b.WriteString(key)
	b.WriteByte('=')
	b.WriteString(encodeValue(value))
	b.WriteByte('\n')
}

func encodeValue(v string) string {
	if v == "" {
		return ""
	}
	if strings.ContainsAny(v, "\n\r\t") ||
		strings.HasPrefix(v, " ") || strings.HasSuffix(v, " ") ||
		strings.HasPrefix(v, `"`) || strings.HasPrefix(v, `'`) {
		return quoteDouble(v)
	}
	return v
}

func quoteDouble(v string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\t':
			b.WriteString(`\t`)
		case '\r':
			b.WriteString(`\r`)
		default:
			b.WriteByte(v[i])
		}
	}
	b.WriteByte('"')
	return b.String()
}

// patchName rewrites a body so that it declares __name=name and carries no
// __id line. Every other line, including comments and quoting, is left
// untouched. A missing __name line is prepended.
func patchName(body, name string) string {
	if strings.TrimSpace(body) == "" {
		return ""
	}
	lines := strings.Split(body, "\n")
	out := make([]string, 0, len(lines)+1)
	replaced := false
	for _, line := range lines {
		if isBlankOrComment(line) {
			out = append(out, line)
			continue
		}
		switch keyOf(line) {
		case keyName:
			if !replaced {
				out = append(out, keyName+"="+encodeValue(name))
				replaced = true
			}
		case keyLegacyID:
			// Drop legacy ids; the id is reconstructed from the file location.
		default:
			out = append(out, line)
		}
	}
	if !replaced {
		out = append([]string{keyName + "=" + encodeValue(name)}, out...)
	}
	return strings.Join(out, "\n")
}

// keyOf returns the key of a KEY=VALUE line, or "" when the line has no "=".
func keyOf(line string) string {
	eq := strings.IndexByte(line, '=')
	if eq < 0 {
		return ""
	}
	return strings.TrimSpace(line[:eq])
}

// Index files map a file uid to its full id. Both sides are validated names
// without "=", so a simple KEY=VALUE listing is unambiguous.
func formatIndex(index map[string]string) string {
	uids := make([]string, 0, len(index))
	for uid := range index {
		uids = append(uids, uid)
	}
	sort.Strings(uids)

	var b strings.Builder
	for _, uid := range uids {
		b.WriteString(uid)
		b.WriteByte('=')
		b.WriteString(index[uid])
		b.WriteByte('\n')
	}
	return b.String()
}

func parseIndex(text string) (map[string]string, error) {
	index := make(map[string]string)
	for _, line := range strings.Split(text, "\n") {
		if isBlankOrComment(line) {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			return nil, fmt.Errorf("invalid index line %q", line)
		}
		index[line[:eq]] = line[eq+1:]
	}
	return index, nil
}
