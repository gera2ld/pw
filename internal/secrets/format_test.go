package secrets

import (
	"reflect"
	"testing"
)

// TestBodyRoundTripVerbatim is the core guarantee: parsing and re-formatting a
// secret body must not change a single byte the user wrote.
func TestBodyRoundTripVerbatim(t *testing.T) {
	d := &SecretManager{}
	cases := []string{
		"# leading comment\n__name=x\nB=2\nA=0xdeadbeef\n",
		"__name=x\nBASE=https://a.example.com/p?q=1\nSIG=a=b=c\n",
		"__name=x\n# comment between\nKEY=value  # not a comment\n",
		"__name=\"x\"\nA=\"  spaced  \"\nB='single'\n",
		"__name=x\nEMPTY=\n",
		"__name=x\n",
	}
	for _, in := range cases {
		parsed, err := d.ParseRawValue(in)
		if err != nil {
			t.Fatalf("ParseRawValue(%q) error = %v", in, err)
		}
		out, err := d.FormatValue(parsed)
		if err != nil {
			t.Fatalf("FormatValue error = %v", err)
		}
		if out != in {
			t.Errorf("round trip changed text:\n in: %q\nout: %q", in, out)
		}
	}
}

func TestValueForms(t *testing.T) {
	d := &SecretManager{}
	parsed, err := d.ParseRawValue("__name=x\nA=x y\nB=\"x y\"\nC='x y'\nD=\"a\\tb\\n\"\nE=\"q\\z\"\n")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"A": "x y", "B": "x y", "C": "x y",
		"D": "a\tb\n", "E": `q\z`,
	}
	for k, v := range want {
		if parsed.Data[k] != v {
			t.Errorf("Data[%q] = %q, want %q", k, parsed.Data[k], v)
		}
	}
}

func TestValueNeedingQuotesRoundTrips(t *testing.T) {
	d := &SecretManager{}
	data := map[string]string{
		"__name": "x",
		"SPACED": " lead",
		"TRAIL":  "trail ",
		"MULTI":  "a\nb",
		"QUOTED": `"already quoted"`,
		"SINGLE": "'single'",
		"EMPTY":  "",
		"PLAIN":  "plain",
	}
	out, err := d.FormatValue(&Secret{Data: data})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := d.ParseRawValue(out)
	if err != nil {
		t.Fatalf("reparse %q: %v", out, err)
	}
	for k, v := range data {
		if parsed.Data[k] != v {
			t.Errorf("Data[%q] = %q, want %q (formatted: %q)", k, parsed.Data[k], v, out)
		}
	}
}

func TestWithNamePreservesText(t *testing.T) {
	d := &SecretManager{}
	parsed, err := d.ParseRawValue("# keep me\n__name=old\nB=2\nA=1\n")
	if err != nil {
		t.Fatal(err)
	}
	out, err := d.FormatValue(parsed.WithName("new"))
	if err != nil {
		t.Fatal(err)
	}
	want := "# keep me\n__name=new\nB=2\nA=1\n"
	if out != want {
		t.Errorf("WithName out = %q, want %q", out, want)
	}
}

func TestWithNamePrependsWhenMissing(t *testing.T) {
	got := patchName("A=1\n", "x")
	if got != "__name=x\nA=1\n" {
		t.Errorf("patchName = %q", got)
	}
}

func TestWithNameDropsLegacyID(t *testing.T) {
	got := patchName("__id=old/path\n__name=x\nA=1\n", "new")
	if got != "__name=new\nA=1\n" {
		t.Errorf("patchName = %q", got)
	}
}

func TestFormatBodyOrder(t *testing.T) {
	got := formatBody(map[string]string{"B": "2", "__name": "n", "A": "1"})
	want := "__name=n\nA=1\nB=2\n"
	if got != want {
		t.Errorf("formatBody = %q, want %q", got, want)
	}
}

func TestParseBodyErrors(t *testing.T) {
	d := &SecretManager{}
	for _, in := range []string{
		"__name=x\nA=1\nA=2\n",    // duplicate
		"__name=x\njust a line\n", // no =
		"__name=x\n=1\n",          // empty key
	} {
		if _, err := d.ParseRawValue(in); err == nil {
			t.Errorf("ParseRawValue(%q) expected error", in)
		}
	}
}

func TestLegacyYAMLMigrates(t *testing.T) {
	d := &SecretManager{}
	parsed, err := d.ParseRawValue("__id: a/b\nTOKEN: 'v'\nN: 5\n")
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Data["__name"] != "a/b" {
		t.Errorf("__name = %q, want a/b", parsed.Data["__name"])
	}
	if _, ok := parsed.Data["__id"]; ok {
		t.Error("__id should be dropped")
	}
	if !parsed.legacy {
		t.Error("expected legacy to be reported")
	}
	// Raw is regenerated in the new format so the next write upgrades it.
	if parsed.Raw != "__name=a/b\nN=5\nTOKEN=v\n" {
		t.Errorf("Raw = %q", parsed.Raw)
	}
}

func TestIndexRoundTrip(t *testing.T) {
	index := map[string]string{
		"db/prod/password": "/db/prod/password",
		"other/secret":     "/other/secret",
	}
	text := formatIndex(index)
	want := "db/prod/password=/db/prod/password\nother/secret=/other/secret\n"
	if text != want {
		t.Errorf("formatIndex = %q, want %q", text, want)
	}
	got, err := parseIndex(text)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, index) {
		t.Errorf("parseIndex = %v, want %v", got, index)
	}
}

func TestParseIndexRejectsLegacyYAML(t *testing.T) {
	if _, err := parseIndex("db/prod/password: /db/prod/password\n"); err == nil {
		t.Error("expected legacy YAML index to be rejected so the YAML fallback runs")
	}
}
