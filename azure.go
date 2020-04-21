package saml

import (
	"context"
	"encoding/xml"
	"fmt"
	//"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	samllib "github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	jwt "github.com/greenpau/caddy-auth-jwt"
	"go.uber.org/zap"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// AzureIdp authenticates request from Azure AD.
type AzureIdp struct {
	CommonParameters
	ServiceProviders    map[string]*samllib.ServiceProvider `json:"-"`
	IdpMetadataLocation string                              `json:"idp_metadata_location,omitempty"`
	IdpMetadataURL      *url.URL                            `json:"-"`
	IdpSignCertLocation string                              `json:"idp_sign_cert_location,omitempty"`
	TenantID            string                              `json:"tenant_id,omitempty"`
	ApplicationID       string                              `json:"application_id,omitempty"`
	ApplicationName     string                              `json:"application_name,omitempty"`

	// LoginURL is the link to Azure AD authentication portal.
	// The link is auto-generated based on Azure AD tenant and
	// application IDs.
	LoginURL string `json:"-"`
	// EntityID is the "Identifier (Entity ID)" an administrator
	// specifies in "Set up Single Sign-On with SAML" in Azure AD
	// Enterprise Applications.
	EntityID string `json:"entity_id,omitempty"`
	// AcsURL is the list of URLs server instance is listening on. These URLS
	// are known as SP Assertion Consumer Service endpoints. For example,
	// users may access a website via http://app.domain.local. At the
	// same time the users may access it by IP, e.g. http://10.10.10.10. or
	// by name, i.e. app. Each of the URLs is a separate endpoint.
	AssertionConsumerServiceURLs []string `json:"acs_urls,omitempty"`
	logger                       *zap.Logger
}

// Authenticate parses and validates SAML Response originating at Azure Active Directory.
func (az *AzureIdp) Authenticate(reqID, acsURL string, samlpResponse []byte) (*caddyauth.User, string, error) {
	// TODO: remove log
	//az.logger.Error(fmt.Sprintf("%s", samlpResponse))
	//az.logger.Error(fmt.Sprintf("ACS: %s", acsURL))
	sp, exists := az.ServiceProviders[acsURL]
	if !exists {
		return nil, "", fmt.Errorf("Unsupported ACS URL %s", acsURL)
	}

	samlAssertions, err := sp.ParseXMLResponse(samlpResponse, []string{""})
	if err != nil {
		return nil, "", err
	}

	claims := jwt.UserClaims{}
	claims.ExpiresAt = time.Now().Add(time.Duration(900) * time.Second).Unix()

	for _, attrStatement := range samlAssertions.AttributeStatements {
		for _, attrEntry := range attrStatement.Attributes {
			if len(attrEntry.Values) == 0 {
				continue
			}
			if strings.HasSuffix(attrEntry.Name, "Attributes/MaxSessionDuration") {
				multiplier, err := strconv.Atoi(attrEntry.Values[0].Value)
				if err != nil {
					az.logger.Error(
						"Failed parsing Attributes/MaxSessionDuration",
						zap.String("request_id", reqID),
						zap.String("error", err.Error()),
					)
					continue
				}
				claims.ExpiresAt = time.Now().Add(time.Duration(multiplier) * time.Second).Unix()
				continue
			}

			if strings.HasSuffix(attrEntry.Name, "identity/claims/displayname") {
				claims.Name = attrEntry.Values[0].Value
				continue
			}

			if strings.HasSuffix(attrEntry.Name, "identity/claims/emailaddress") {
				claims.Email = attrEntry.Values[0].Value
				continue
			}

			if strings.HasSuffix(attrEntry.Name, "identity/claims/identityprovider") {
				claims.Origin = attrEntry.Values[0].Value
				continue
			}

			if strings.HasSuffix(attrEntry.Name, "identity/claims/name") {
				claims.Subject = attrEntry.Values[0].Value
				continue
			}

			if strings.HasSuffix(attrEntry.Name, "Attributes/Role") {
				for _, attrEntryElement := range attrEntry.Values {
					claims.Roles = append(claims.Roles, attrEntryElement.Value)
				}
				continue
			}
		}
	}

	if claims.Email == "" || claims.Name == "" {
		return nil, "", fmt.Errorf("The Azure AD authorization failed, mandatory attributes not found: %v", claims)
	}

	if len(claims.Roles) == 0 {
		claims.Roles = append(claims.Roles, "anonymous")
	}

	if az.Jwt.TokenIssuer != "" {
		claims.Issuer = az.Jwt.TokenIssuer
	}

	user := &caddyauth.User{
		ID: claims.Email,
		Metadata: map[string]string{
			"name":  claims.Name,
			"email": claims.Email,
			"roles": strings.Join(claims.Roles, " "),
		},
	}

	token, err := jwt.GetToken("HS512", []byte(az.Jwt.TokenSecret), claims)
	if err != nil {
		return nil, "", fmt.Errorf("Failed to issue JWT token with %v claims: %s", claims, err)
	}

	return user, token, nil
}

// Validate performs configuration validation
func (az *AzureIdp) Validate() error {
	if len(az.AssertionConsumerServiceURLs) == 0 {
		return fmt.Errorf("ACS URLs are missing")
	}
	if az.TenantID == "" {
		return fmt.Errorf("Azure AD Tenant ID not found")
	}

	az.logger.Info(
		"validating Azure AD Tenant ID",
		zap.String("tenant_id", az.TenantID),
	)

	if az.ApplicationID == "" {
		return fmt.Errorf("Azure AD Application ID not found")
	}

	az.logger.Info(
		"validating Azure AD Application ID",
		zap.String("application_id", az.ApplicationID),
	)

	if az.ApplicationName == "" {
		return fmt.Errorf("Azure AD Application Name not found")
	}

	az.logger.Info(
		"validating Azure AD Application Name",
		zap.String("application_name", az.ApplicationID),
	)

	if az.IdpMetadataLocation == "" {
		az.IdpMetadataLocation = fmt.Sprintf(
			"https://login.microsoftonline.com/%s/federationmetadata/2007-06/federationmetadata.xml",
			az.TenantID,
		)
	}

	az.logger.Info(
		"validating Azure AD IdP Metadata Location",
		zap.String("idp_metadata_location", az.IdpMetadataLocation),
	)

	if az.IdpSignCertLocation == "" {
		return fmt.Errorf("Azure AD IdP Signing Certificate not found")
	}

	az.logger.Info(
		"validating Azure AD IdP Signing Certificate",
		zap.String("idp_signing_cert", az.IdpSignCertLocation),
	)

	idpSignCert, err := readCertFile(az.IdpSignCertLocation)
	if err != nil {
		return err
	}

	az.LoginURL = getAzureURL(az.ApplicationName, az.ApplicationID, az.TenantID)

	az.logger.Info(
		"validating Azure AD Login URL",
		zap.String("login_url", az.LoginURL),
	)

	azureOptions := samlsp.Options{}

	if strings.HasPrefix(az.IdpMetadataLocation, "http") {
		idpMetadataURL, err := url.Parse(az.IdpMetadataLocation)
		if err != nil {
			return err
		}
		az.IdpMetadataURL = idpMetadataURL
		azureOptions.URL = *idpMetadataURL
		idpMetadata, err := samlsp.FetchMetadata(
			context.Background(),
			http.DefaultClient,
			*idpMetadataURL,
		)
		if err != nil {
			return err
		}
		azureOptions.IDPMetadata = idpMetadata

	} else {
		metadataFileContent, err := ioutil.ReadFile(az.IdpMetadataLocation)
		if err != nil {
			return err
		}
		idpMetadata, err := samlsp.ParseMetadata(metadataFileContent)
		if err != nil {
			return err
		}
		azureOptions.IDPMetadata = idpMetadata
	}

	az.ServiceProviders = make(map[string]*samllib.ServiceProvider)
	for _, acsURL := range az.AssertionConsumerServiceURLs {
		sp := samlsp.DefaultServiceProvider(azureOptions)
		sp.AllowIDPInitiated = true
		//sp.EntityID = sp.IDPMetadata.EntityID

		cfgAcsURL, _ := url.Parse(acsURL)
		sp.AcsURL = *cfgAcsURL

		entityID, _ := url.Parse(az.EntityID)
		sp.MetadataURL = *entityID

		if az.IdpMetadataURL != nil {
			sp.MetadataURL = *az.IdpMetadataURL
		}

		for i := range sp.IDPMetadata.IDPSSODescriptors {
			idpSSODescriptor := &sp.IDPMetadata.IDPSSODescriptors[i]
			keyDescriptor := &samllib.KeyDescriptor{
				Use: "signing",
				KeyInfo: samllib.KeyInfo{
					XMLName: xml.Name{
						Space: "http://www.w3.org/2000/09/xmldsig#",
						Local: "KeyInfo",
					},
					Certificate: idpSignCert,
				},
			}
			idpSSODescriptor.KeyDescriptors = append(idpSSODescriptor.KeyDescriptors, *keyDescriptor)
			break
		}

		az.ServiceProviders[acsURL] = &sp
	}
	return nil
}

func getAzureURL(applicationName, applicationID, tenantID string) string {
	return fmt.Sprintf(
		"https://account.activedirectory.windowsazure.com/applications/signin/%s/%s?tenantId=%s",
		applicationName, applicationID, tenantID,
	)
}
