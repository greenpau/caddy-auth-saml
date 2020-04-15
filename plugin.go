package saml

import (
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	"go.uber.org/zap"
	"net/http"
	"strings"
)

func init() {
	caddy.RegisterModule(AuthProvider{})
}

// AuthProvider authenticates requests the SAML Response to the SP Assertion
// Consumer Service using the HTTP-POST Binding.
type AuthProvider struct {
	Name string `json:"-"`
	CommonParameters
	Azure            *AzureIdp      `json:"azure,omitempty"`
	UI               *UserInterface `json:"ui,omitempty"`
	logger           *zap.Logger    `json:"-"`
	idpProviderCount uint64         `json:"-"`
}

// CommonParameters represent a common set of configuration settings, e.g.
// authentication URL, Success Redirect URL, JWT token name and secret, etc.
type CommonParameters struct {
	AuthURLPath    string          `json:"auth_url_path,omitempty"`
	SuccessURLPath string          `json:"success_url_path,omitempty"`
	Jwt            TokenParameters `json:"jwt,omitempty"`
}

// TokenParameters represent JWT parameters of CommonParameters.
type TokenParameters struct {
	TokenName   string `json:"token_name,omitempty"`
	TokenSecret string `json:"token_secret,omitempty"`
	TokenIssuer string `json:"token_issuer,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (AuthProvider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.authentication.providers.saml",
		New: func() caddy.Module { return new(AuthProvider) },
	}
}

// Provision provisions SAML authentication provider
func (m *AuthProvider) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	m.logger.Info("provisioning plugin instance")
	m.Name = "saml"
	m.logger.Error(fmt.Sprintf("azure is %v", m.Azure))
	return nil
}

// Validate implements caddy.Validator.
func (m *AuthProvider) Validate() error {
	m.logger.Info("validating plugin UI Settings")
	m.idpProviderCount = 0

	if m.AuthURLPath == "" {
		return fmt.Errorf("%s: authentication endpoint cannot be empty, try setting auth_url_path to /saml", m.Name)
	}

	// Validate UI settings
	if m.UI == nil {
		return fmt.Errorf("%s: UI settings not found", m.Name)
	}
	if err := m.UI.validate(); err != nil {
		return fmt.Errorf("%s: UI settings validation error: %s", m.Name, err)
	}

	// Validate Azure AD settings
	if m.Azure != nil {
		m.Azure.logger = m.logger
		m.Azure.Jwt = m.Jwt
		if err := m.Azure.Validate(); err != nil {
			return fmt.Errorf("%s: %s", m.Name, err)
		}
		m.idpProviderCount++
	}

	if m.idpProviderCount == 0 {
		return fmt.Errorf("%s: no valid IdP configuration found", m.Name)
	}

	// Validate UI settings
	if m.UI == nil {
		return fmt.Errorf("%s: UI settings not found", m.Name)
	}
	if err := m.UI.validate(); err != nil {
		return fmt.Errorf("%s: UI settings validation error: %s", m.Name, err)
	}

	m.UI.AuthEndpoint = m.AuthURLPath
	if m.Azure != nil {
		link := userInterfaceLink{
			Link:  m.Azure.LoginURL,
			Title: "Office 365",
			Style: "fa-windows",
		}
		m.UI.Links = append(m.UI.Links, link)
	}

	return nil
}

// Authenticate validates the user credentials in and returns a user identity, if valid.
func (m AuthProvider) Authenticate(w http.ResponseWriter, r *http.Request) (caddyauth.User, bool, error) {
	var userIdentity *caddyauth.User
	var userToken string
	var err error
	var userAuthenticated bool
	m.logger.Error(fmt.Sprintf("authenticating ... %v", r))
	uiArgs := m.UI.newUserInterfaceArgs()

	// Authentication Requests
	if r.Method == "POST" {
		if strings.Contains(r.Header.Get("Origin"), "login.microsoftonline.com") ||
			strings.Contains(r.Header.Get("Referer"), "windowsazure.com") {
			userIdentity, userToken, err = m.Azure.Authenticate(r)
			if err != nil {
				uiArgs.Message = err.Error()
			} else {
				userAuthenticated = true
				uiArgs.Authenticated = true
			}
		}

	}

	// Render UI
	uiErr := m.UI.render(w, uiArgs)
	if uiErr != nil {
		m.logger.Error(uiErr.Error())
	}

	// Wrap up
	if !userAuthenticated {
		return m.failAzureAuthentication(w, nil)
	}

	/*
		m.logger.Info(
			"Authenticated user",
			zap.String("token", userToken),
		)
		m.logger.Info(fmt.Sprintf("%v", userIdentity))
	*/

	w.Header().Set("Authorization", "Bearer "+userToken)
	return *userIdentity, true, nil
}

func (m AuthProvider) failAzureAuthentication(w http.ResponseWriter, err error) (caddyauth.User, bool, error) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	return caddyauth.User{}, false, err
}

// Interface guards
var (
	_ caddy.Provisioner       = (*AuthProvider)(nil)
	_ caddy.Validator         = (*AuthProvider)(nil)
	_ caddyauth.Authenticator = (*AuthProvider)(nil)
)
