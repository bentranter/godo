package godo

import (
	"context"
	"errors"
	"net/http"

	"golang.org/x/oauth2"
)

// OAuth2 flow specific errors.
var (
	// ErrStateMismatch occurs when the state parameter in the callback URL does
	// not match the one provided in the auth code URL.
	ErrStateMismatch = errors.New("state tokens do not match")

	// ErrMissingCode occurs when the callback URL does not contain an
	// authorization code.
	ErrMissingCode = errors.New("missing authorization code")
)

// OAuth2Service defines the operatios for the OAuth2 authorization code flow.
type OAuth2Service interface {
	Authorize(w http.ResponseWriter, r *http.Request)
	Callback(nextURL string) http.HandlerFunc
	AuthCodeURL() string
	GetAuthCode(r *http.Request) (string, error)
	Exchange(code string) (*oauth2.Token, error)
	SaveTokenSource(token *oauth2.Token)
}

// OAuth2ServiceOp implements the OAuth2Service.
type OAuth2ServiceOp struct {
	client *Client
}

var _ OAuth2Service = &OAuth2ServiceOp{}

// Authorize is an HTTP handler that redirects the user to the OAuth2 consent
// page.
func (o *OAuth2ServiceOp) Authorize(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, o.AuthCodeURL(), http.StatusFound)
}

// Callback handles the callback portion of the OAuth2 authorization code
// flow. If an error occurs, an error response will be set, otherwise the
// user will be redirected to the given nextURL upon successful completion.
//
// Once completed, the current godo client instance can be used for any API
// request.
func (o *OAuth2ServiceOp) Callback(nextURL string) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		code, err := o.GetAuthCode(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		token, err := o.Exchange(code)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		o.SaveTokenSource(token)
		http.Redirect(w, r, nextURL, http.StatusFound)
	})
}

// AuthCodeURL returns a URL to DigitalOcean's OAuth2 consent page that asks
// for permissions for the required scopes explicitly.
func (o *OAuth2ServiceOp) AuthCodeURL() string {
	return o.client.oauth2Config.AuthCodeURL(o.client.state, oauth2.AccessTypeOffline)
}

// GetAuthCode gets the auth code from the callback URL during the OAuth2
// authorization flow. The state parameter will also be checked to ensure it
// matches the one set on the AuthCodeURL.
func (o *OAuth2ServiceOp) GetAuthCode(r *http.Request) (string, error) {
	state := r.URL.Query().Get("state")
	if state != o.client.state {
		return "", ErrStateMismatch
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		return "", ErrMissingCode
	}
	return code, nil
}

// Exchange exchanges a short lived authorization code for a long lived API token.
func (o *OAuth2ServiceOp) Exchange(code string) (*oauth2.Token, error) {
	return o.client.oauth2Config.Exchange(context.Background(), code, oauth2.AccessTypeOffline)
}

// SaveTokenSource sets the token source of the godo client instance to that
// of the given token. This allows the client to be used for any API request.
func (o *OAuth2ServiceOp) SaveTokenSource(token *oauth2.Token) {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(token)
	o.client = NewClient(oauth2.NewClient(ctx, ts))
}
