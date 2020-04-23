# caddy-auth-saml

<a href="https://github.com/greenpau/caddy-auth-saml/actions/" target="_blank"><img src="https://github.com/greenpau/caddy-auth-saml/workflows/build/badge.svg?branch=master"></a>
<a href="https://pkg.go.dev/github.com/greenpau/caddy-auth-saml" target="_blank"><img src="https://img.shields.io/badge/godoc-reference-blue.svg"></a>
<a href="https://caddy.community" target="_blank"><img src="https://img.shields.io/badge/community-forum-ff69b4.svg"></a>

SAML Authentication Plugin for [Caddy v2](https://github.com/caddyserver/caddy).

<!-- begin-markdown-toc -->

* [Getting Started](#getting-started)
  * [Time Synchronization](#time-synchronization)
  * [Authentication Endpoint](#authentication-endpoint)
  * [User Interface (UI)](#user-interface-ui)
  * [JWT Token](#jwt-token)
  * [Miscellaneous](#miscellaneous)

* [Azure Active Directory (Office 365) Applications](#azure-active-directory-office-365-applications)
  * [Plugin Configuration](#plugin-configuration)
  * [Set Up Azure AD Application](#set-up-azure-ad-application)
  * [Configure SAML Authentication](#configure-saml-authentication)
  * [Azure AD IdP Metadata and Certificate](#azure-ad-idp-metadata-and-certificate)
  * [User Interface Options](#user-interface-options)
  * [Development Notes](#development-notes)

<!-- end-markdown-toc -->

The plugin supports the following identity providers:

* [Azure Active Directory (Office 365) Applications](#azure-active-directory-office-365-applications)

## Getting Started

This plugin is an application in itself. It has a simple UI
and a routine that checks the validity of the SAML assertions
provided by an Identity Provider (IdP).

### Time Synchronization

Importantly, SAML assertion validation checks timestamps. It is
critical that the application validating the assertions maintains
accurate clock. The out of sync time WILL result in failed
authentications.

### Authentication Endpoint

Each instance of the plugin requires an endpoint. Let's examine
the endpoint `/saml` provided in a sample configuration file:

```bash
cat assets/conf/Caddyfile.json | jq '.apps.http.servers.srv0.routes'
```

The output is:

```json
{
  "handle": [
    {
      "handler": "authentication",
      "providers": {
        "saml": {
          "auth_url_path": "/saml",
          "jwt": {
            "token_name": "access_token",
            "token_secret": "383aca9a-1c39-4d7a-b4d8-67ba4718dd3f",
            "token_issuer": "7a50e023-2c6e-4a5e-913e-23ecd0e2b940"
          },
          "azure": {
            "idp_metadata_location": "/etc/caddy/auth/saml/idp/azure_ad_app_metadata.xml",
            "idp_sign_cert_location": "/etc/caddy/auth/saml/idp/azure_ad_app_signing_cert.pem",
            "tenant_id": "1b9e886b-8ff2-4378-b6c8-6771259a5f51",
            "application_id": "623cae7c-e6b2-43c5-853c-2059c9b2cb58",
            "application_name": "My Gatekeeper",
            "entity_id": "urn:caddy:mygatekeeper",
            "acs_urls": [
              "https://mygatekeeper/saml",
              "https://mygatekeeper.local/saml",
              "https://192.168.10.10:3443/saml",
              "https://localhost:3443/saml"
            ]
          },
          "ui": {
            "template_location": "assets/ui/ui.template",
            "allow_role_selection": false
          }
        }
      }
    }
  ],
  "match": [
    {
      "path": [
        "/saml*"
      ]
    }
  ],
  "terminal": true
}
```

### User Interface (UI)

The SAML endpoint `/saml` serves a UI. This is defined by the following
snippet of the above configuration. The `/saml*` ensures that anything
matching `/saml` would end at the above handler.

```json
  "match": [
    {
      "path": [
        "/saml*"
      ]
    }
  ],
```

The UI template is Golang template. The template in
`assets/ui/ui.template` is the default UI served by the plugin.

* `template_location`: The location of a custom UI template
* `auto_redirect_url`: If set, upon successful authentication,
  the plugin redirects the request to the URL.
* `allow_role_selection`: Enables or disables the ability to
  select a role after successful validation of a SAML assertion.

```json
          "ui": {
            "template_location": "assets/ui/ui.template",
            "allow_role_selection": false
          }
```

* `links`: If `auto_redirect_url` is not set upon successful
  authentication, the plugin displays a portal page.
  The portal page will have the links specified via this
  parameter.

```
  "ui": {
    "portal_links": [
      {
        "title": "Prometheus",
        "link": "/prometheus"
      },
      {
        "title": "Alertmanager",
        "link": "/alertmanager"
      }
    ]
```

The portal screen looks like this:

![Portal - Access Authorized](./assets/docs/_static/images/access_authorized.png)

### JWT Token

After a successful validation of a SAML assertion, the plugin issues
a JWT token.

* `token_name`: The name of the issues token (default: 'jwt_token`)
* `token_secret`: The token signing secret (symmetric, i.e. HMAC algo)
* `token_key`: (TODO: not supported) The token signing public/private
  key pair (asymmetric, i.e. RSA or ECDSA algo).
* `token_issuer`: The value of `iss` field inserted by the plugin.

```json
          "jwt": {
            "token_name": "access_token",
            "token_secret": "383aca9a-1c39-4d7a-b4d8-67ba4718dd3f",
            "token_issuer": "7a50e023-2c6e-4a5e-913e-23ecd0e2b940"
          },
```

The issued token will be passed to a requester via:

* The cookie specified in `token_name` key
* The `Authorization` header via `Bearer` directive

### Miscellaneous

The `auto_redirect` causes the plugin to redirect the user directly
to IdP URL, without first displaying the UI. This parameter is
disabled by default. If the configuration has a single IdP
configured, it makes sence to enable it.

```
   "providers": {
     "saml": {
       "auth_url_path": "/saml",
       "auto_redirect": true,
```

The addition of `?logout=true` to URL query causes the plugin to send cookie
delete signals to a client.

The addition of `?redirect_url=/alertmanager` to URL query causes the plugin
to redirect a client to the path upon a successful authentication.

```
https://app:3443/saml?redirect_url=/alertmanager
```

## Azure Active Directory (Office 365) Applications

### Plugin Configuration

First, fetch the Azure IdP plugin configuration:

```
cat assets/conf/Caddyfile.json | jq '.apps.http.servers.srv0.routes[0].handle[0].providers.saml.azure'
```

The Azure configuration:

```json
{
  "idp_metadata_location": "assets/idp/azure_ad_app_metadata.xml",
  "idp_sign_cert_location": "assets/idp/azure_ad_app_signing_cert.pem",
  "tenant_id": "1b9e886b-8ff2-4378-b6c8-6771259a5f51",
  "application_id": "623cae7c-e6b2-43c5-853c-2059c9b2cb58",
  "application_name": "My Gatekeeper",
  "entity_id": "urn:caddy:mygatekeeper",
  "acs_urls": [
    "https://mygatekeeper/saml",
    "https://mygatekeeper.local/saml",
    "https://192.168.10.10:3443/saml",
    "https://localhost:3443/saml"
  ]
}
```

The plugin supports the following parameters for Azure Active
Directory (Office 365) applications:

| **Parameter Name** | **Description** |
| --- | --- |
| `idp_metadata_location` | The url or path to Azure IdP Metadata |
| `idp_sign_cert_location` | The path to Azure IdP Signing Certificate |
| `tenant_id` | Azure Tenant ID |
| `application_id` | Azure Application ID |
| `application_name` | Azure Application Name |
| `entity_id` | Azure Application Identifier (Entity ID) |
| `acs_urls` | One of more Assertion Consumer Service URLs |

The `acs_urls` must list all URLs the users of the application
can reach it at.

### Set Up Azure AD Application

In Azure AD, you will have an application, e.g. "My Gatekeeper".

The application is a Caddy web server running on port 3443 on
`localhost`. This example meant to emphasize that the authorization
is asynchronious. That is when a user clicks on "My Gatekeeper" icon
in Office 365, the browser takes the user to a sign in page
at URL `https://localhost:3443/saml`.

![Azure AD App Registration - Overview](./assets/docs/_static/images/azure_app_registration_overview.png)

The Application Identifiers are as follows:

* Application (client) ID: `623cae7c-e6b2-43c5-853c-2059c9b2cb58`
* Directory (tenant) ID: `1b9e886b-8ff2-4378-b6c8-6771259a5f51`
* Object ID: `515d2e8b-7548-413f-abee-a23ece1ea576`

The "Branding" page configures "Home Page URL".

![Azure AD App Registration - Branding](./assets/docs/_static/images/azure_app_registration_branding.png)

For demostration purposes, we will create the following "Roles" in the application:

| **Azure Role Name** | **Role Name in SAML Assertion** |
| --- | --- |
| Viewer | AzureAD_Viewer |
| Editor | AzureAD_Editor |
| Administrator | AzureAD_Administrator |

Use "Manifest" tab to add roles in the manifest via `appRoles` key:

![Azure AD App Registration - Manifest - User Roles](./assets/docs/_static/images/azure_app_registration_user_roles.png)

```json
{
  "allowedMemberTypes": [
    "User"
  ],
  "description": "Administrator",
  "displayName": "Administrator",
  "id": "91287df2-7028-4d5f-b5ae-5d489ba217dd",
  "isEnabled": true,
  "lang": null,
  "origin": "Application",
  "value": "AzureAD_Administrator"
},
{
  "allowedMemberTypes": [
    "User"
  ],
  "description": "Editor",
  "displayName": "Editor",
  "id": "d482d827-1757-4f60-9bea-021c10037674",
  "isEnabled": true,
  "lang": null,
  "origin": "Application",
  "value": "AzureAD_Editor"
},
{
  "allowedMemberTypes": [
    "User"
  ],
  "description": "Viewer",
  "displayName": "Viewer",
  "id": "c69f7abd-0a88-401e-b515-92d74b6fff2f",
  "isEnabled": true,
  "lang": null,
  "origin": "Application",
  "value": "AzureAD_Viewer"
}
```

After, we added the roles, we could assign any of the roles to a user:

![Azure AD App - Users and Groups - Add User](./assets/docs/_static/images/azure_app_add_user.png)

The app is now available to the provisioned users in Office 365:

![Office 365 - Access Application](./assets/docs/_static/images/azure_app_user_access.png)

### Configure SAML Authentication

Go to "Enterprise Application" and browse to "My Gatekeeper" application.

There, click "Single Sign-On" and select "SAML" as the authentication method.

![Azure AD App - Enable SAML](./assets/docs/_static/images/azure_app_saml_enable.png)

Next, in the "Set up Single Sign-On with SAML", provide the following
"Basic SAML Configuration":

* Identifier (Entity ID): `urn:caddy:mygatekeeper`
* Reply URL (Assertion Consumer Service URL): `https://localhost:3443/saml`

![Azure AD App - Basic SAML Configuration](./assets/docs/_static/images/azure_app_saml_id.png)

Under "User Attributes & Claims", add the following claims to the list of
default claims:

| **Namespace** | **Claim name** | **Value** |
| --- | --- | --- |
| `http://claims.contoso.com/SAML/Attributes` | `RoleSessionName` | `user.userprincipalname` |
| `http://claims.contoso.com/SAML/Attributes` | `Role` | `user.assignedroles` |
| `http://claims.contoso.com/SAML/Attributes` | `MaxSessionDuration` | `3600` |

![Azure AD App - User Attributes and Claims](./assets/docs/_static/images/azure_app_saml_claims.png)

Next, record the following:
* App Federation Metadata Url
* Login URL

Further, download:
* Federation Metadata XML
* Certificate (Base64 and Raw)

![Azure AD App - SAML Signing Certificate](./assets/docs/_static/images/azure_app_saml_other.png)

### Azure AD IdP Metadata and Certificate

The following command downloads IdP metadata file for Azure AD Tenant with
ID `1b9e886b-8ff2-4378-b6c8-6771259a5f51`. Please note the `xmllint` utility
is a part of `libxml2` library.

```bash

curl -s -L -o /tmp/federationmetadata.xml https://login.microsoftonline.com/1b9e886b-8ff2-4378-b6c8-6771259a5f51/federationmetadata/2007-06/federationmetadata.xml
sudo mkdir -p /etc/caddy/auth/saml/idp/
cat /tmp/federationmetadata.xml | xmllint --format - | sudo tee /etc/caddy/auth/saml/idp/azure_ad_app_metadata.xml
```

The `/etc/caddy/auth/saml/idp/azure_ad_app_metadata.xml` contains IdP metadata.
This file contains the data necessary to verify the SAML claims received by this
service and signed by Azure AD. The `idp_metadata` argument is being used to
pass the location of IdP metadata.

Next, download the "Certificate (Base64)" and store it in
`/etc/caddy/auth/saml/idp/azure_ad_app_signing_cert.pem`.

### User Interface Options

First option is a login button on the login server web page. Once Azure AD has
been enabled, the `/saml` page will have "Sign in with Office 365" button

![Azure AD App - Login with Azure Button](./assets/docs/_static/images/login_with_azure_button.png?width=20px)

Second option is Office 365 applications. When a user click on the
application's icon in Office 365, the user gets redirected to the web
server by Office 365.

![Office 365 - Access Application](./assets/docs/_static/images/azure_app_user_access.png)

The URL is `https://localhost:3443/saml`.

### Development Notes

The below are the headers of the redirected `POST` request that the user's
browser makes upon clicking "My Gatekeeper" application:

```
Method: POST
URL: /saml
Protocol: HTTP/2.0
Host: localhost:3443
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ru;q=0.8
Cache-Control: max-age=0
Content-Length: 7561
Content-Type: application/x-www-form-urlencoded
Origin: https://login.microsoftonline.com
Referer: https://login.microsoftonline.com/
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: cross-site
Upgrade-Insecure-Requests: 1
```

The above redirect contains `login.microsoftonline.com` in the request's
`Referer` header. It is the trigger to perform SAML-based authorization.
