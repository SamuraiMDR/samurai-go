package transmitter

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateCustomKV(t *testing.T) {
	cases := []struct {
		name    string
		key     string
		value   string
		wantErr bool
	}{
		{"both empty is ok", "", "", false},
		{"valid pair", "team", "blue", false},
		{"max length pair", strings.Repeat("a", 32), strings.Repeat("b", 32), false},
		{"underscore and hyphen", "source_type", "blue-team", false},
		{"single letter pair", "a", "b", false},
		{"max length with separators", "a" + strings.Repeat("_", 31), "b" + strings.Repeat("-", 31), false},
		{"trailing separators", "a-", "b_", false},
		{"leading underscore key", "_team", "blue", true},
		{"leading hyphen value", "team", "-blue", true},
		{"separator only key", "_", "blue", true},
		{"too long with separators", "a" + strings.Repeat("_", 32), "blue", true},
		{"space in value", "team", "blue team", true},
		{"key only", "team", "", true},
		{"value only", "", "blue", true},
		{"uppercase key", "Team", "blue", true},
		{"uppercase value", "team", "Blue", true},
		{"digit in value", "team", "blue1", true},
		{"key too long", strings.Repeat("a", 33), "blue", true},
		{"value too long", "team", strings.Repeat("b", 33), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateCustomKV(c.key, c.value)
			if (err != nil) != c.wantErr {
				t.Fatalf("validateCustomKV(%q, %q) error = %v, wantErr = %v", c.key, c.value, err, c.wantErr)
			}
		})
	}
}

func TestSASMarshalOmitsEmptyCustomFields(t *testing.T) {
	body, err := json.Marshal(sas{Payload: "bouncer", Profile: "azure", Suffix: "json", Filename: "f.json"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "customKey") || strings.Contains(string(body), "customValue") {
		t.Fatalf("expected custom fields omitted, got %s", body)
	}

	body, err = json.Marshal(sas{Payload: "bouncer", Profile: "azure", Suffix: "json", Filename: "f.json", CustomKey: "team", CustomValue: "blue"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"customKey":"team"`) || !strings.Contains(string(body), `"customValue":"blue"`) {
		t.Fatalf("expected custom fields present, got %s", body)
	}
}
