package generator

import (
	"math"
	"testing"
	"time"
)

func validAlert() AlertV1 {
	alert := GetBaseAlertV1()
	alert.Action = "BLOCK"
	alert.Name = "name"
	alert.DevicePhysical = "physical"
	alert.DeviceVirtual = "virtual"
	alert.Src = "10.0.0.1"
	alert.Dst = "10.0.0.2"
	alert.Type = "type"
	alert.Vendor = "vendor"
	alert.Platform = "platform"
	alert.ShortDesc = "short"
	alert.SetBlobsProperties("site", "src")
	alert.AddJSONData([]byte(`{"a":1}`), "evidence", true)
	alert.AddTimeStampFields(time.Unix(1700000000, 0))
	return alert
}

func TestSetSha(t *testing.T) {
	alert := validAlert()
	if err := alert.SetSha(); err != nil {
		t.Fatal(err)
	}
	if len(alert.Sha) != 40 {
		t.Fatalf("Sha = %q, want 40 hex characters", alert.Sha)
	}
	if alert.Context["pcapid"] != alert.Sha {
		t.Fatalf("pcapid = %v, want the sha", alert.Context["pcapid"])
	}
	if err := alert.ValidateAlert(); err != nil {
		t.Fatal(err)
	}

	again := validAlert()
	if err := again.SetSha(); err != nil || again.Sha != alert.Sha {
		t.Fatalf("SetSha is not deterministic: %q vs %q (err %v)", again.Sha, alert.Sha, err)
	}
}

func TestSetShaReturnsMarshalError(t *testing.T) {
	alert := validAlert()
	alert.Context["score"] = math.NaN()

	if err := alert.SetSha(); err == nil {
		t.Fatal("SetSha must return an error for an alert that cannot be marshalled")
	}
	if alert.Sha != "" {
		t.Fatalf("Sha = %q, want it left unset", alert.Sha)
	}
	if err := alert.ValidateAlert(); err == nil {
		t.Fatal("ValidateAlert must reject an alert without a sha")
	}
}
