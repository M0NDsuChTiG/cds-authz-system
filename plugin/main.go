package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/docker/go-plugins-helpers/authorization"
)

const daemonSocketPath = "/run/cds/cds.sock"

type CDSResponse struct {
	Allow  bool   `json:"Allow"`
	Digest string `json:"Digest"`
}

type cdsPlugin struct {
	httpClient *http.Client
}

func newCDSPlugin() *cdsPlugin {
	return &cdsPlugin{
		httpClient: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", daemonSocketPath)
				},
			},
			Timeout: 5 * time.Second,
		},
	}
}

func (p *cdsPlugin) AuthZReq(req authorization.Request) authorization.Response {
	isCritical := strings.Contains(req.RequestURI, "/containers/create") || 
	              strings.Contains(req.RequestURI, "/images/create")

	if !isCritical {
		return authorization.Response{Allow: true}
	}

	var image string
	if len(req.RequestBody) > 0 {
		var body map[string]interface{}
		if err := json.Unmarshal(req.RequestBody, &body); err == nil {
			if img, ok := body["Image"].(string); ok {
				image = img
			}
		}
	}
	if image == "" && strings.Contains(req.RequestURI, "fromImage=") {
		parts := strings.Split(req.RequestURI, "fromImage=")
		if len(parts) > 1 {
			image = strings.Split(parts[1], "&")[0]
		}
	}

	if image == "" {
		// Log why we are allowing it
		// log.Printf("CDS Plugin: Skipping check for %s (no image found)", req.RequestURI)
		return authorization.Response{Allow: true}
	}

	checkReq := map[string]string{"Image": image}
	jsonBody, _ := json.Marshal(checkReq)
	
	resp, err := p.httpClient.Post("http://localhost/v1/trust/check", "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return authorization.Response{Allow: false, Msg: "CDS: Daemon error"}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	var decision CDSResponse
	if err := json.Unmarshal(bodyBytes, &decision); err != nil {
		return authorization.Response{Allow: false, Msg: "CDS: JSON error"}
	}

	log.Printf("CDS Plugin: DEBUG_DECISION image=%s allow=%v digest=%s", image, decision.Allow, decision.Digest)

	if decision.Allow {
		return authorization.Response{Allow: true, Msg: "CDS: TRUSTED"}
	}

	return authorization.Response{
		Allow: false,
		Msg:   fmt.Sprintf("CDS Zero-Trust: Image '%s' is NOT TRUSTED. Decision was Allow=%v", image, decision.Allow),
	}
}

func (p *cdsPlugin) AuthZRes(req authorization.Request) authorization.Response {
	return authorization.Response{Allow: true}
}

func main() {
	plugin := newCDSPlugin()
	h := authorization.NewHandler(plugin)
	if err := h.ServeUnix("cds-authz", 0); err != nil {
		panic(err)
	}
}
