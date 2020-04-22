package saml

import (
	"bytes"
	"net/http"
	"text/template"
)

// UserInterface represents a set of configuration settings
// for user interface and associated methods
type UserInterface struct {
	TemplateLocation   string              `json:"template_location,omitempty"`
	AllowRoleSelection bool                `json:"allow_role_selection,omitempty"`
	Template           *template.Template  `json:"-"`
	Title              string              `json:"title,omitempty"`
	LogoURL            string              `json:"logo_url,omitempty"`
	LogoDescription    string              `json:"logo_description,omitempty"`
	Links              []userInterfaceLink `json:"-"`
	PortalLinks        []userInterfaceLink `json:"portal_links,omitempty"`
	AuthEndpoint       string              `json:"-"`
	LocalAuthEnabled   bool                `json:"local_auth_enabled,omitempty"`
	AutoRedirectURL    string              `json:"auto_redirect_url"`
}

type userInterfaceArgs struct {
	Title            string
	LogoURL          string
	LogoDescription  string
	AuthEndpoint     string
	Message          string
	MessageType      string
	Links            []userInterfaceLink
	PortalLinks      []userInterfaceLink
	LocalAuthEnabled bool
	Authenticated    bool
}

type userInterfaceLink struct {
	Link  string `json:"link,omitempty"`
	Title string `json:"title,omitempty"`
	Style string `json:"style,omitempty"`
}

func (ui *UserInterface) newUserInterfaceArgs() userInterfaceArgs {
	args := userInterfaceArgs{
		Title:            ui.Title,
		LogoURL:          ui.LogoURL,
		LogoDescription:  ui.LogoDescription,
		Links:            ui.Links,
		AuthEndpoint:     ui.AuthEndpoint,
		LocalAuthEnabled: ui.LocalAuthEnabled,
		PortalLinks:      ui.PortalLinks,
	}
	return args
}

func (ui *UserInterface) validate() error {
	if err := ui.loadTemplates(); err != nil {
		return err
	}
	if ui.Title == "" {
		ui.Title = "Sign In"
	}
	return nil
}

func (ui *UserInterface) loadTemplates() error {
	var templateBody string
	t := template.New("AuthForm")
	if ui.TemplateLocation != "" {
		templateBodyBytes, err := readFile(ui.TemplateLocation)
		if err != nil {
			return err
		}
		templateBody = string(templateBodyBytes)
	} else {
		templateBody = defaultUserInterface
	}
	t, err := t.Parse(templateBody)
	if err != nil {
		return err
	}
	ui.Template = t
	return nil
}

func (ui *UserInterface) getBytes(args userInterfaceArgs) (*bytes.Buffer, error) {
	b := bytes.NewBuffer(nil)
	err := ui.Template.Execute(b, args)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (ui *UserInterface) render(w http.ResponseWriter, args userInterfaceArgs) error {
	b, err := ui.getBytes(args)
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte(`Internal Server Error`))
		return err
	}

	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Content-Type", "text/html")
	w.Write(b.Bytes())
	return nil
}
