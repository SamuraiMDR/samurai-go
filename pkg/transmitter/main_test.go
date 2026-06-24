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
		{"max length pair", strings.Repeat("a", 20), strings.Repeat("b", 20), false},
		{"key only", "team", "", true},
		{"value only", "", "blue", true},
		{"uppercase key", "Team", "blue", true},
		{"uppercase value", "team", "Blue", true},
		{"digit in value", "team", "blue1", true},
		{"key too long", strings.Repeat("a", 21), "blue", true},
		{"value too long", "team", strings.Repeat("b", 21), true},
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
