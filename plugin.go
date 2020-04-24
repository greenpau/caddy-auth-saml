package saml

import (
	"encoding/base64"
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	"github.com/google/uuid"
	jwt "github.com/greenpau/caddy-auth-jwt"
	"go.uber.org/zap"
	"net/http"
	//"net/http/httputil"
	"github.com/greenpau/caddy-auth-ui"
	"net/url"
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
	UserInterface    *UserInterfaceParameters `json:"ui,omitempty"`
	Azure            *AzureIdp                `json:"azure,omitempty"`
	logger           *zap.Logger              `json:"-"`
	idpProviderCount uint64                   `json:"-"`
	uiFactory        *ui.UserInterfaceFactory `json:"-"`
}

// CommonParameters represent a common set of configuration settings, e.g.
// authentication URL, Success Redirect URL, JWT token name and secret, etc.
type CommonParameters struct {
	AuthURLPath     string          `json:"auth_url_path,omitempty"`
	AutoRedirect    bool            `json:"auto_redirect,omitempty"`
	AutoRedirectURL string          `json:"-"`
	Jwt             TokenParameters `json:"jwt,omitempty"`
}

// UserInterfaceParameters represent a common set of configuration settings
// for HTML UI.
type UserInterfaceParameters struct {
	TemplateLocation   string                 `json:"template_location,omitempty"`
	AllowRoleSelection bool                   `json:"allow_role_selection,omitempty"`
	Title              string                 `json:"title,omitempty"`
	LogoURL            string                 `json:"logo_url,omitempty"`
	LogoDescription    string                 `json:"logo_description,omitempty"`
	PrivateLinks       []ui.UserInterfaceLink `json:"private_links,omitempty"`
	AutoRedirectURL    string                 `json:"auto_redirect_url"`
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
	m.logger.Info("validating plugin settings")
	m.idpProviderCount = 0

	if m.AuthURLPath == "" {
		return fmt.Errorf("%s: authentication endpoint cannot be empty, try setting auth_url_path to /saml", m.Name)
	}

	m.logger.Info("validating plugin JWT settings")
	if m.Jwt.TokenName == "" {
		m.Jwt.TokenName = "access_token"
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
		m.Azure.AutoRedirect = m.AutoRedirect
		if err := m.Azure.Validate(); err != nil {
			return fmt.Errorf("%s: %s", m.Name, err)
		}
		if m.AutoRedirect && m.Azure.LoginURL != "" {
			m.AutoRedirectURL = m.Azure.LoginURL
		}
		m.idpProviderCount++
	}

	// Perform IdP-related checks
	if m.idpProviderCount == 0 {
		return fmt.Errorf("%s: no valid IdP configuration found", m.Name)
	}

	if m.idpProviderCount != 1 {
		m.AutoRedirect = false
	}

	if m.AutoRedirectURL == "" {
		m.AutoRedirect = false
	}

	if !m.AutoRedirect {
		m.AutoRedirectURL = ""
	}

	// Validate UI settings
	if m.UserInterface == nil {
		m.UserInterface = &UserInterfaceParameters{}
	}

	m.uiFactory = ui.NewUserInterfaceFactory()
	if m.UserInterface.Title == "" {
		m.uiFactory.Title = "Sign In"
	} else {
		m.uiFactory.Title = m.UserInterface.Title
	}
	if m.UserInterface.LogoURL != "" {
		m.uiFactory.LogoURL = m.UserInterface.LogoURL
		m.uiFactory.LogoDescription = m.UserInterface.LogoDescription
	}

	m.uiFactory.ActionEndpoint = m.AuthURLPath

	if m.Azure != nil {
		link := ui.UserInterfaceLink{
			Link:  m.Azure.LoginURL,
			Title: "Office 365",
			Style: "fa-windows",
		}
		m.uiFactory.PublicLinks = append(m.uiFactory.PublicLinks, link)
	}

	if len(m.UserInterface.PrivateLinks) > 0 {
		m.uiFactory.PrivateLinks = m.UserInterface.PrivateLinks
	}

	if m.UserInterface.TemplateLocation != "" {
		if err := m.uiFactory.AddTemplate("login", m.UserInterface.TemplateLocation); err != nil {
			return fmt.Errorf(
				"%s: UI settings validation error, failed loading template from %s: %s",
				m.Name, m.UserInterface.TemplateLocation, err,
			)
		}
	} else {
		if err := m.uiFactory.AddBuiltinTemplate("saml_login"); err != nil {
			return fmt.Errorf(
				"%s: UI settings validation error, failed loading built-in saml_login template: %s",
				m.Name, err,
			)
		}
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
	var reqID string
	var userClaims *jwt.UserClaims
	var userToken string
	var userAuthenticated bool

	//if rb, err := httputil.DumpRequest(r, true); err == nil {
	//	m.logger.Debug(fmt.Sprintf("%s", rb))
	//}

	uiArgs := m.uiFactory.GetArgs()

	// Generate request UUID
	reqID = uuid.New().String()

	m.logger.Debug(
		"Request received",
		zap.String("request_id", reqID),
		zap.String("method", r.Method),
		zap.String("http_proto", r.Proto),
		zap.String("remote_ip", r.RemoteAddr),
		zap.Int64("content_length", r.ContentLength),
		zap.String("host", r.Host),
	)

	// Handle query parameters
	if r.Method == "GET" {
		q := r.URL.Query()
		if _, exists := q["logout"]; exists {
			for _, k := range []string{"saml_plugin_redirect_url", m.Jwt.TokenName} {
				w.Header().Add("Set-Cookie", k+"=delete; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT")
			}
		} else {
			if redirectURL, exists := q["redirect_url"]; exists {
				w.Header().Set("Set-Cookie", "saml_plugin_redirect_url="+redirectURL[0])
			}
		}
	}

	// Auto-redirect to IdP
	if r.Method == "GET" && m.AutoRedirect {
		return m.redirectToIdentityProvider(w, r, m.AutoRedirectURL)
	}

	// Authentication Requests
	if r.Method == "POST" {
		authFound := false
		if requestPayload, acsURL, err := validateRequestCompliance(r); err == nil {
			// Azure AD handler
			if m.Azure != nil && (strings.Contains(r.Header.Get("Origin"), "login.microsoftonline.com") ||
				strings.Contains(r.Header.Get("Referer"), "windowsazure.com")) {
				authFound = true
				userClaims, userToken, err = m.Azure.Authenticate(reqID, acsURL, requestPayload)
				if err != nil {
					uiArgs.Message = "Authentication failed"
					w.WriteHeader(http.StatusUnauthorized)
					m.logger.Warn(
						"Authentication failed",
						zap.String("request_id", reqID),
						zap.String("error", err.Error()),
					)
				} else {
					userAuthenticated = true
					uiArgs.Authenticated = true
				}
			}
		} else {
			uiArgs.Message = "Authentication failed"
			m.logger.Warn(
				"Authentication failed",
				zap.String("request_id", reqID),
				zap.String("error", err.Error()),
			)
		}

		if !authFound {
			if uiArgs.Message == "" {
				uiArgs.Message = "Authentication failed"
				m.logger.Warn(
					"Authentication failed",
					zap.String("request_id", reqID),
					zap.String("error", "unsupported identity provider"),
				)
			}
			w.WriteHeader(http.StatusBadRequest)
		}
	}

	// Render UI
	contentType := "text/html"
	content, uiErr := m.uiFactory.Render("login", uiArgs)
	if uiErr != nil {
		m.logger.Error(
			"Failed UI",
			zap.String("request_id", reqID),
			zap.String("error", uiErr.Error()),
		)
		w.WriteHeader(500)
		w.Write([]byte(`Internal Server Error`))
		return caddyauth.User{}, false, uiErr
	}

	// Wrap up
	if !userAuthenticated {
		w.Header().Set("Content-Type", contentType)
		w.Write(content.Bytes())
		return caddyauth.User{}, false, nil
	}

	userIdentity := caddyauth.User{
		ID: userClaims.Email,
		Metadata: map[string]string{
			"name":  userClaims.Name,
			"email": userClaims.Email,
			"roles": strings.Join(userClaims.Roles, " "),
		},
	}

	m.logger.Debug(
		"Authentication succeeded",
		zap.String("request_id", reqID),
		zap.String("user_id", userIdentity.ID),
	)

	w.Header().Set("Authorization", "Bearer "+userToken)
	w.Header().Set("Set-Cookie", m.Jwt.TokenName+"="+userToken+" Secure; HttpOnly;")
	if cookie, err := r.Cookie("saml_plugin_redirect_url"); err == nil {
		if redirectURL, err := url.Parse(cookie.Value); err == nil {
			m.logger.Debug(
				"Cookie-based redirect",
				zap.String("request_id", reqID),
				zap.String("user_id", userIdentity.ID),
				zap.String("redirect_url", redirectURL.String()),
			)
			w.Header().Set("Location", redirectURL.String())
			w.Header().Add("Set-Cookie", "saml_plugin_redirect_url=delete; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT")
			w.WriteHeader(303)
			return userIdentity, true, nil
		}
	}

	if m.UserInterface.AutoRedirectURL != "" {
		w.Header().Set("Location", m.UserInterface.AutoRedirectURL)
		w.WriteHeader(303)
		return userIdentity, true, nil
	}

	w.Header().Set("Content-Type", contentType)
	w.Write(content.Bytes())
	return userIdentity, true, nil
}

func (m AuthProvider) redirectToIdentityProvider(w http.ResponseWriter, r *http.Request, to string) (caddyauth.User, bool, error) {
	http.Redirect(w, r, to, http.StatusPermanentRedirect)
	return caddyauth.User{}, false, nil
}

// Interface guards
var (
	_ caddy.Provisioner       = (*AuthProvider)(nil)
	_ caddy.Validator         = (*AuthProvider)(nil)
	_ caddyauth.Authenticator = (*AuthProvider)(nil)
)
