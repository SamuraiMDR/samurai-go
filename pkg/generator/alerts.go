package generator

import (
	"crypto/sha1"
	b64 "encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
)

type MetaData struct {
	Render bool `json:"render"`
}

type Data struct {
	Data     string    `json:"data"`
	Ext      string    `json:"ext"`
	Name     string    `json:"name"`
	Mime     string    `json:"mime"`
	MetaData *MetaData `json:"metadata,omitempty"`
}

type Alert struct {
	Action              string                 `json:"action"`
	Name                string                 `json:"name"`
	DevicePhysical      string                 `json:"devicephysical"`
	DeviceVirtual       string                 `json:"devicevirtual"`
	Dst                 string                 `json:"dst"`
	DestIp              string                 `json:"dest_ip,omitempty"`
	DstPort             string                 `json:"dstport,omitempty"`
	Dvc                 string                 `json:"dvc,omitempty"`
	Platform            string                 `json:"platform"`
	Protocol            string                 `json:"protocol"`
	SrcIp               string                 `json:"src_ip"`
	Src                 string                 `json:"src"`
	Sha                 string                 `json:"sha"`
	ShortDesc           string                 `json:"shortdesc"`
	SrcPort             string                 `json:"srcport,omitempty"`
	Type                string                 `json:"type"`
	Vendor              string                 `json:"vendor"`
	Blobs               *[]Data                `json:"blobs,omitempty"`
	Context             map[string]interface{} `json:"context,omitempty"`
	Date                string                 `json:"date"`
	Timestamp           float64                `json:"timestamp"`
	LongdescMD          string                 `json:"longdesc_md,omitempty"`
	SafeHtmlClickDesc   bool                   `json:"safe_html_click_desc"`
	SafeHtmlClickEvid   bool                   `json:"safe_html_click_evid"`
	SafeHtmlRenderDesc  bool                   `json:"safe_html_render_desc"`
	SafeHtmlRrenderEvid bool                   `json:"safe_html_render_evid"`
}

type Alerts struct {
	Alert []Alert
}

/*
	Generate basic alert with necessary fields set
*/
func GetBaseAlert() Alert {
	alert := Alert{
		Context:             make(map[string]interface{}),
		SafeHtmlClickDesc:   false,
		SafeHtmlClickEvid:   false,
		SafeHtmlRenderDesc:  true,
		SafeHtmlRrenderEvid: true,
	}
	return alert
}

func (a *Alert) SetSha() {
	outp, err := json.Marshal(a)
	if err != nil {
		log.Fatalf("Failed to run sha: '%v' on struct: %+v", err, a)
	}
	hasher := sha1.New()
	hasher.Write(outp)
	a.Sha = hex.EncodeToString(hasher.Sum(nil))

	if a.Blobs != nil {
		a.Context["pcapid"] = a.Sha
	}
}

func (a *Alert) SetBlobsProperties(site string, src string) {
	a.Context["src"] = src
	a.Context["haspacketdata"] = true

}

func (a *Alert) AddJSONData(json_dumped_to_bytes []byte, name string, render bool) {
	if a.Blobs == nil {
		a.Blobs = &[]Data{}
	}
	*a.Blobs = append(*a.Blobs, Data{
		Data: b64.StdEncoding.EncodeToString(json_dumped_to_bytes),
		Ext:  "json",
		Name: name,
		Mime: "application/json",
		MetaData: &MetaData{
			Render: render,
		},
	})
}

func (a *Alert) AddTimeStampFields(alert_time time.Time) {
	a.Timestamp = float64(alert_time.Unix())
	a.Date = alert_time.Format("2006-01-02T15:04:05")
}

func (a *Alert) ValidateAlert() error {
	req_fields := []string{"action",
		a.Action,
		"name",
		a.Name,
		"devicephysical",
		a.DevicePhysical,
		"devicevirtual",
		a.DeviceVirtual,
		"src",
		a.Src,
		"dst",
		a.Dst,
		"date",
		a.Date,
		"sha",
		a.Sha,
		"type",
		a.Type,
		"vendor",
		a.Vendor,
		"platform",
		a.Platform,
		"shortdesc",
		a.ShortDesc,
	}

	// Required but non-string handling
	if a.Timestamp == 0 {
		return fmt.Errorf("Required Field timestamp not set")
	}

	for i := 0; i < len(req_fields); i = i + 2 {
		if req_fields[i+1] == "" {
			return fmt.Errorf("Required Field '%s' not set", req_fields[i])
		}
	}

	if a.LongdescMD == "" && a.Blobs == nil {
		return fmt.Errorf("Either LongdescMD or blobs must be set")
	}

	if a.Blobs != nil {
		_, src := a.Context["src"]
		if !src {
			return fmt.Errorf("Missing context key src")
		}
		_, haspacketdata := a.Context["haspacketdata"]
		if !haspacketdata {
			return fmt.Errorf("Missing context key haspacketdata")
		}
		_, pcapid := a.Context["pcapid"]
		if !pcapid {
			return fmt.Errorf("Missing context key pcapid")
		}
	}

	if a.Action != "ACCEPT" && a.Action != "BLOCK" {
		return fmt.Errorf("Invalid action: %s", a.Action)
	}

	return nil
}
