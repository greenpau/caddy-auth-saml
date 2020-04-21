// Copyright 2020 Paul Greenberg (greenpau@outlook.com)

package saml

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/caddyserver/caddy/v2/caddytest"
	//"github.com/ma314smith/signedxml"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"text/template"
	"time"
)

func getSigningKey(fp string) (*rsa.PrivateKey, error) {
	fileContent, err := ioutil.ReadFile(fp)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(fileContent)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing RSA PRIVATE KEY")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func renderFlatString(b *bytes.Buffer) string {
	s := b.String()
	s = strings.Replace(s, "\n", "", -1)
	dups := regexp.MustCompile(`\s+`)
	s = dups.ReplaceAllString(s, " ")
	s = strings.Replace(s, "> <", "><", -1)

	s = strings.Replace(s, "<style> body", "<style>body", -1)
	s = strings.Replace(s, "} @media", "}@media", -1)
	s = strings.Replace(s, "{ body {", "{body {", -1)
	s = strings.Replace(s, "} } h2", "}}h2", -1)
	s = strings.Replace(s, "} hr", "}hr", -1)
	s = strings.Replace(s, "} hr:after", "}hr:after", -1)
	s = strings.Replace(s, "} </style>", "}</style>", -1)
	s = strings.Replace(s, "Office 365 </a>", "Office 365</a>", -1)
	return s
}

// creates a testing transport that forces call dialing connections to happen locally
func createTestingTransport() *http.Transport {

	dialer := net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 5 * time.Second,
		DualStack: true,
	}

	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		parts := strings.Split(addr, ":")
		destAddr := fmt.Sprintf("127.0.0.1:%s", parts[1])
		log.Printf("caddytest: redirecting the dialer from %s to %s", addr, destAddr)
		return dialer.DialContext(ctx, network, destAddr)
	}

	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}
}

func AssertPostResponse(t *testing.T, requestURI string, requestHeaders []string, requestBody *bytes.Buffer, statusCode int, expectedBody string) (*http.Response, string) {
	resp, body := AssertPostResponseBody(t, requestURI, requestHeaders, requestBody, statusCode)
	if !strings.Contains(body, expectedBody) {
		t.Errorf("requesting \"%s\" expected response body \"%s\" but got \"%s\"", requestURI, expectedBody, body)
	}
	return resp, body
}

func AssertPostResponseBody(t *testing.T, requestURI string, requestHeaders []string, requestBody *bytes.Buffer, expectedStatusCode int) (*http.Response, string) {
	client := &http.Client{
		Transport: createTestingTransport(),
	}

	requestMethod := "POST"

	t.Logf("%s Request URI %s", requestMethod, requestURI)
	req, err := http.NewRequest(requestMethod, requestURI, requestBody)
	if err != nil {
		t.Errorf("failed to create request %s", err)
		return nil, ""
	}

	ctx, cancel := context.WithTimeout(req.Context(), 5*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	requestContentType := ""
	for _, requestHeader := range requestHeaders {
		arr := strings.SplitAfterN(requestHeader, ":", 2)
		k := strings.TrimRight(arr[0], ":")
		v := strings.TrimSpace(arr[1])
		if k == "Content-Type" {
			requestContentType = v
		}
		t.Logf("Request header: %s => %s", k, v)
		req.Header.Set(k, v)
	}

	if requestContentType == "" {
		t.Errorf("Content-Type header not provided")
		return nil, ""
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Errorf("failed to call server %s", err)
		return nil, ""
	}

	defer resp.Body.Close()

	if expectedStatusCode != resp.StatusCode {
		t.Errorf("requesting \"%s\" expected status code: %d but got %d", requestURI, expectedStatusCode, resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("unable to read the response body %s", err)
		return nil, ""
	}

	return resp, string(body)
}

type authRequestParameters struct {
	SamlURL                           string // https://localhost:3443/saml
	SamlpResponseIssueInstantTime     string // 2020-04-19T01:25:12.362Z
	AssertionIssueTime                string // 2020-04-19T01:25:12.346Z
	AssertionConditionNotBefore       string // 2020-04-19T01:20:12.159Z
	AssertionConditionNotOnOrAfter    string // 2020-04-19T02:25:12.159Z
	TenantID                          string // 1b9e886b-8ff2-4378-b6c8-6771259a5f51
	AssertionSubject                  string // greenpau@contoso.com
	AssertionAudience                 string // urn:caddy:mygatekeeper
	AssertionAttributeDisplayName     string // Greenberg, Paul
	AssertionAttributeGivenName       string // Paul
	AssertionAttributeSurname         string // Greenberg
	AssertionAttributeEmailAddress    string // greenpau@contoso.com
	AssertionAttributeName            string // greenpau@contoso.com
	AssertionAttributeRoleSessionName string // greenpau@contoso.com
	AuthnStatementTime                string // 2020-02-16T20:37:20.667Z
}

func convertToAzureTimestamp(s string) string {
	arr := strings.Split(s, ".")
	if len(arr[1]) > 4 {
		return arr[0] + "." + arr[1][len(arr[1])-4:]
	}
	return s
}

func newAzureAuthRequestParameters() authRequestParameters {
	p := authRequestParameters{}

	assertionIssueTime := time.Now().UTC().Add(time.Duration(-5) * time.Second)
	assertionConditionNotBefore := time.Now().UTC().Add(time.Duration(-5) * time.Minute)
	assertionConditionNotOnOrAfter := time.Now().UTC().Add(time.Duration(60) * time.Minute)
	samlpResponseIssueInstantTime := time.Now().UTC().Add(time.Duration(-4) * time.Second)
	authnStatementTime := time.Now().UTC().Add(time.Duration(1) * time.Hour)

	p.AssertionIssueTime = convertToAzureTimestamp(assertionIssueTime.Format(time.RFC3339Nano))
	p.AssertionConditionNotBefore = convertToAzureTimestamp(assertionConditionNotBefore.Format(time.RFC3339Nano))
	p.AssertionConditionNotOnOrAfter = convertToAzureTimestamp(assertionConditionNotOnOrAfter.Format(time.RFC3339Nano))
	p.SamlpResponseIssueInstantTime = convertToAzureTimestamp(samlpResponseIssueInstantTime.Format(time.RFC3339Nano))
	p.AuthnStatementTime = convertToAzureTimestamp(authnStatementTime.Format(time.RFC3339Nano))

	return p
}

var authRequestTemplateBody = `<samlp:Response ID="_9eefb041-27fe-4014-bf4b-932cd5f7f5d5" Version="2.0" IssueInstant="{{ .SamlpResponseIssueInstantTime }}" Destination="{{ .SamlURL }}" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">https://sts.windows.net/{{ .TenantID }}/</Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <Assertion ID="_7298c1f7-4411-4bc6-b8e4-77622e935418" IssueInstant="{{ .AssertionIssueTime }}" Version="2.0" xmlns="urn:oasis:names:tc:SAML:2.0:assertion">
    <Issuer>https://sts.windows.net/{{ .TenantID }}/</Issuer>
    <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
      <SignedInfo>
        <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        <Reference URI="#_0369ee56-8152-4f92-b8c3-e1481fe74300">
          <Transforms>
            <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
            <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          </Transforms>
          <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
          <DigestValue>asdf</DigestValue>
        </Reference>
      </SignedInfo>
      <SignatureValue>asdf</SignatureValue>
    </Signature>
    <Subject>
      <NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{{ .AssertionSubject }}</NameID>
      <SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <SubjectConfirmationData NotOnOrAfter="{{ .AssertionConditionNotOnOrAfter }}" Recipient="{{ .SamlURL }}"/>
      </SubjectConfirmation>
    </Subject>
    <Conditions NotBefore="{{ .AssertionConditionNotBefore }}" NotOnOrAfter="{{ .AssertionConditionNotOnOrAfter }}">
      <AudienceRestriction>
		<Audience>{{ .AssertionAudience }}</Audience>
      </AudienceRestriction>
    </Conditions>
    <AttributeStatement>
      <Attribute Name="http://schemas.microsoft.com/identity/claims/tenantid">
        <AttributeValue>{{ .TenantID }}</AttributeValue>
      </Attribute>
      <Attribute Name="http://schemas.microsoft.com/identity/claims/objectidentifier">
        <AttributeValue>158d7011-cfd7-41b8-b456-8a8264ac5a04</AttributeValue>
      </Attribute>
      <Attribute Name="http://schemas.microsoft.com/identity/claims/displayname">
        <AttributeValue>{{ .AssertionAttributeDisplayName }}</AttributeValue>
      </Attribute>
      <Attribute Name="http://schemas.microsoft.com/identity/claims/identityprovider">
        <AttributeValue>https://sts.windows.net/{{ .TenantID }}/</AttributeValue>
      </Attribute>
      <Attribute Name="http://schemas.microsoft.com/claims/authnmethodsreferences">
        <AttributeValue>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</AttributeValue>
        <AttributeValue>http://schemas.microsoft.com/claims/multipleauthn</AttributeValue>
      </Attribute>
      <Attribute Name="http://schemas.microsoft.com/ws/2008/06/identity/claims/role">
        <AttributeValue>AzureAD_Editor</AttributeValue>
        <AttributeValue>AzureAD_Viewer</AttributeValue>
        <AttributeValue>AzureAD_Administrator</AttributeValue>
      </Attribute>
      <Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname">
        <AttributeValue>{{ .AssertionAttributeGivenName }}</AttributeValue>
      </Attribute>
      <Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname">
        <AttributeValue>{{ .AssertionAttributeSurname }}</AttributeValue>
      </Attribute>
      <Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress">
        <AttributeValue>{{ .AssertionAttributeEmailAddress }}</AttributeValue>
      </Attribute>
      <Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name">
        <AttributeValue>{{ .AssertionAttributeName }}</AttributeValue>
      </Attribute>
      <Attribute Name="http://claims.contoso.com/SAML/Attributes/RoleSessionName">
        <AttributeValue>{{ .AssertionAttributeRoleSessionName }}</AttributeValue>
      </Attribute>
      <Attribute Name="http://claims.contoso.com/SAML/Attributes/Role">
        <AttributeValue>AzureAD_Editor</AttributeValue>
        <AttributeValue>AzureAD_Viewer</AttributeValue>
        <AttributeValue>AzureAD_Administrator</AttributeValue>
      </Attribute>
      <Attribute Name="http://claims.contoso.com/SAML/Attributes/MaxSessionDuration">
        <AttributeValue>3600</AttributeValue>
      </Attribute>
    </AttributeStatement>
    <AuthnStatement AuthnInstant="{{ .AuthnStatementTime }}" SessionIndex="_7298c1f7-4411-4bc6-b8e4-77622e935418">
      <AuthnContext>
        <AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</AuthnContextClassRef>
      </AuthnContext>
    </AuthnStatement>
  </Assertion>
</samlp:Response>`

func TestPlugin(t *testing.T) {
	var expResponse string
	var authRequestHeaders []string
	var authRequestPayloadPlain *bytes.Buffer
	var authRequestPayload *bytes.Buffer

	// Define app parameters
	appName := "My Gatekeeper"
	appID := "623cae7c-e6b2-43c5-853c-2059c9b2cb58"
	tenantID := "1b9e886b-8ff2-4378-b6c8-6771259a5f51"

	// Define URL
	baseURL := "https://127.0.0.1:3443"

	// Load configuration file
	configFile := "assets/conf/Caddyfile.json"
	rawConfig, err := readFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load configuration file %s: %s", configFile, err)
	}

	// Setup User Interface
	ui := &UserInterface{}
	if err := ui.validate(); err != nil {
		t.Fatalf("Failed to validate UI: %s", err)
	}
	ui.AuthEndpoint = "/saml"
	link := userInterfaceLink{
		Link:  getAzureURL(appName, appID, tenantID),
		Title: "Office 365",
		Style: "fa-windows",
	}
	ui.Links = append(ui.Links, link)

	// Create a template for SAML POST requests
	authRequestTemplate := template.New("AzureAuthRequest")
	if authRequestTemplate, err = authRequestTemplate.Parse(authRequestTemplateBody); err != nil {
		t.Fatalf("error parsing auth request template: %s", err)
	}

	// Create new authentication request payload
	authRequestParams := newAzureAuthRequestParameters()
	authRequestParams.SamlURL = baseURL + "/saml"
	authRequestParams.TenantID = tenantID
	authRequestParams.AssertionSubject = "greenpau@contoso.com"
	authRequestParams.AssertionAudience = "urn:caddy:mygatekeeper"
	authRequestParams.AssertionAttributeDisplayName = "Greenberg, Paul"
	authRequestParams.AssertionAttributeGivenName = "Paul"
	authRequestParams.AssertionAttributeSurname = "Greenberg"
	authRequestParams.AssertionAttributeEmailAddress = "greenpau@contoso.com"
	authRequestParams.AssertionAttributeName = "greenpau@contoso.com"
	authRequestParams.AssertionAttributeRoleSessionName = "greenpau@contoso.com"

	caddytest.InitServer(t, rawConfig, "json")

	caddytest.AssertGetResponse(t, baseURL+"/health", 200, "OK")
	caddytest.AssertGetResponse(t, baseURL+"/version", 200, "1.0.0")

	t.Logf("Test getting to a sign in screen")
	uiArgs := ui.newUserInterfaceArgs()
	expResponseBytes, err := ui.getBytes(uiArgs)
	if err != nil {
		t.Fatalf("error generating UI response: %s", err)
	}
	expResponse = renderFlatString(expResponseBytes)
	caddytest.AssertGetResponse(t, baseURL+"/saml", 200, expResponse)

	// Test SAML validation with valid payload - Azure
	t.Logf("Test SAML validation with valid payload - Azure")
	authRequestHeaders = []string{
		"Content-Type: application/x-www-form-urlencoded",
		"Origin: https://login.microsoftonline.com",
		"Referer: https://login.microsoftonline.com/",
	}
	expResponseBytes, err = ui.getBytes(uiArgs)
	if err != nil {
		t.Fatalf("error generating UI response: %s", err)
	}
	expResponse = renderFlatString(expResponseBytes)
	authRequestPayloadPlain = bytes.NewBuffer(nil)
	if err := authRequestTemplate.Execute(authRequestPayloadPlain, authRequestParams); err != nil {
		t.Fatalf("error generating auth request payload: %s", err)
	}
	authRequestPayload = bytes.NewBuffer(nil)
	authRequestPayload.WriteString("SAMLResponse=")
	t.Logf("Payload bytes: %s", authRequestPayloadPlain.Bytes())

	// XML Signing
	/*
		signingKey, err := getSigningKey("assets/idp/azure_ad_app_signing_pkcs1_key.pem")
		if err != nil {
			t.Fatalf("error parsing signing key: %s", err)
		}
		signer, err := signedxml.NewSigner(authRequestPayloadPlain.String())
		if err != nil {
			t.Fatalf("error initializing XML signer: %s", err)
		}

		signedAuthRequestPayloadPlain, err := signer.Sign(signingKey)
		if err != nil {
			t.Fatalf("error signing XML doc: %s", err)
		}
		t.Logf("Signed payload: %s", signedAuthRequestPayloadPlain)
	*/

	encodedauthRequestPayload := base64.StdEncoding.EncodeToString(authRequestPayloadPlain.Bytes())
	encodedauthRequestPayload = url.QueryEscape(encodedauthRequestPayload)
	//t.Logf("Payload encoded: %s", encodedauthRequestPayload)

	authRequestPayload.WriteString(encodedauthRequestPayload)

	//AssertPostResponse(t, baseURL+"/saml", authRequestHeaders, authRequestPayload, 401, expResponse)

	// Test SAML validation with invalid payload - No SAMLResponse form field
	t.Logf("Test SAML validation with invalid payload - No SAMLResponse form field")
	uiArgs.Message = "Authentication failed"
	authRequestHeaders = []string{
		"Content-Type: application/x-www-form-urlencoded",
		"Origin: https://login.microsoftonline.com",
		"Referer: https://login.microsoftonline.com/",
	}
	expResponseBytes, err = ui.getBytes(uiArgs)
	if err != nil {
		t.Fatalf("error generating UI response: %s", err)
	}
	expResponse = renderFlatString(expResponseBytes)
	AssertPostResponse(t, baseURL+"/saml", authRequestHeaders, authRequestPayloadPlain, 400, expResponse)

	time.Sleep(1 * time.Millisecond)
	// Uncomment the below line to perform manual testing
	// time.Sleep(6000 * time.Second)
}
