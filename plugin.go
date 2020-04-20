package saml

import (
	"encoding/base64"
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	"go.uber.org/zap"
	"net/http"
	"os"
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

	if m.Jwt.TokenName == "" {
		m.Jwt.TokenName = "JWT_TOKEN"
	}
	m.logger.Info(
		"found JWT token name",
		zap.String("jwt.token_name", m.Jwt.TokenName),
	)

	if m.Jwt.TokenSecret == "" {
		if os.Getenv("JWT_TOKEN_SECRET") == "" {
			return fmt.Errorf("%s: jwt_token_secret must be defined either "+
				"via JWT_TOKEN_SECRET environment variable or "+
				"via jwt.token_secret configuration element",
				m.Name,
			)
		}
	}

	if m.Jwt.TokenIssuer == "" {
		m.logger.Warn(
			"JWT token issuer not found, using default",
			zap.String("jwt.token_issuer", "localhost"),
		)
		m.Jwt.TokenIssuer = "localhost"
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
		m.UI = &UserInterface{}
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

func validateRequestCompliance(r *http.Request) ([]byte, string, error) {
	if r.ContentLength > 30000 {
		return nil, "", fmt.Errorf("Request payload exceeded the limit of 30,000 bytes: %d", r.ContentLength)
	}
	if r.ContentLength < 500 {
		return nil, "", fmt.Errorf("Request payload is too small: %d", r.ContentLength)
	}
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/x-www-form-urlencoded" {
		return nil, "", fmt.Errorf("Request content type is not application/x-www-form-urlencoded")
	}
	if r.FormValue("SAMLResponse") == "" {
		return nil, "", fmt.Errorf("Request payload has no SAMLResponse field")
	}
	b, err := base64.StdEncoding.DecodeString(r.FormValue("SAMLResponse"))
	if err != nil {
		return nil, "", err
	}

	// Extract the Destination attribute of samlp:Response. It SHOULD be
	// one of the ACS endpoints registered with the plugin.
	acsURL := ""
	s := string(b)
	for _, elem := range []string{"Destination=\""} {
		i := strings.Index(s, elem)
		if i < 0 {
			continue
		}
		j := strings.Index(s[i+len(elem):], "\"")
		if j < 0 {
			continue
		}
		acsURL = s[i+len(elem) : i+len(elem)+j]
	}

	if acsURL == "" {
		return nil, "", fmt.Errorf("Failed to parse ACS URL")
	}

	return b, acsURL, nil
}

// Authenticate validates the user credentials in and returns a user identity, if valid.
func (m AuthProvider) Authenticate(w http.ResponseWriter, r *http.Request) (caddyauth.User, bool, error) {
	var userIdentity *caddyauth.User
	var userToken string
	var userAuthenticated bool
	m.logger.Error(fmt.Sprintf("authenticating ... %v", r))
	uiArgs := m.UI.newUserInterfaceArgs()

	// Authentication Requests
	if r.Method == "POST" {
		authFound := false
		if requestPayload, acsURL, err := validateRequestCompliance(r); err == nil {
			// Azure AD handler
			if strings.Contains(r.Header.Get("Origin"), "login.microsoftonline.com") ||
				strings.Contains(r.Header.Get("Referer"), "windowsazure.com") {
				authFound = true
				userIdentity, userToken, err = m.Azure.Authenticate(acsURL, requestPayload)
				if err != nil {
					uiArgs.Message = "Authentication failed"
					w.WriteHeader(http.StatusUnauthorized)
					m.logger.Warn(
						"Authentication failed",
						zap.String("reason", err.Error()),
						zap.String("remote_ip", r.RemoteAddr),
					)
				} else {
					userAuthenticated = true
					uiArgs.Authenticated = true
					w.WriteHeader(http.StatusOK)
					m.logger.Debug(
						"Authentication succeeded",
						zap.String("remote_ip", r.RemoteAddr),
					)
				}
			}
		} else {
			uiArgs.Message = "Authentication failed"
			m.logger.Warn(
				"Authentication failed",
				zap.String("reason", err.Error()),
				zap.String("remote_ip", r.RemoteAddr),
			)
		}

		if !authFound {
			w.WriteHeader(http.StatusBadRequest)
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
