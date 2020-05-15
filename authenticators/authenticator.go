package authenticators

import (
	"github.com/clevergo/auth"
)

var (
	defaultTokenParam = "access_token"
	defaultRealm      = "api"
)

type authenticator struct {
	store     auth.IdentityStore
	tokenType string
}

func newAuthenticator(store auth.IdentityStore) *authenticator {
	return &authenticator{store: store}
}

func (a *authenticator) SetTokenType(v string) {
	a.tokenType = v
}

func (a *authenticator) GetIdentityByToken(token string) (auth.Identity, error) {
	return a.store.GetIdentityByToken(token, a.tokenType)
}
