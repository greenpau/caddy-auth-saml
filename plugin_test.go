// Copyright 2020 Paul Greenberg (greenpau@outlook.com)

package saml

import (
	"github.com/caddyserver/caddy/v2/caddytest"
	"testing"
	"time"
)

func TestPlugin(t *testing.T) {
	//configFile := "assets/conf/azure/Caddyfile.json"
	configFile := "/etc/caddy/TestCaddyfile.json"
	config, err := readFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load configuration file %s: %s", configFile, err)
	}

	caddytest.InitServer(t, config, "json")

	caddytest.AssertGetResponse(t, "https://127.0.0.1:3443/health", 200, "OK")
	caddytest.AssertGetResponse(t, "https://127.0.0.1:3443/saml", 200, "1.0.0")
	caddytest.AssertGetResponse(t, "https://127.0.0.1:3443/version", 200, "1.0.0")

	time.Sleep(1 * time.Millisecond)
	time.Sleep(6000 * time.Second)
}
