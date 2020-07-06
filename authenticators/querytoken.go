// Copyright 2020 CleverGo. All rights reserved.
// Use of this source code is governed by a MIT style license that can be found
// in the LICENSE file.

package authenticators

import (
	"net/http"

	"clevergo.tech/auth"
)

var _ auth.Authenticator = &QueryToken{}

// QueryToken is an authenticator that retrieves token from URL query and authenticates an user.
type QueryToken struct {
	*authenticator
	param string
}

// NewQueryToken returns an instance of QueryToken authenticator with the given identity
// store and default token param.
func NewQueryToken(store auth.IdentityStore) *QueryToken {
	return NewQueryTokenParam(store, defaultTokenParam)
}

// NewQueryTokenParam returns an instance of QueryToken authenticator with the given identity
// store and param.
func NewQueryTokenParam(store auth.IdentityStore, param string) *QueryToken {
	return &QueryToken{authenticator: newAuthenticator(store), param: param}
}

// Authenticate implements Authenticator.Authenticate.
func (a *QueryToken) Authenticate(r *http.Request, w http.ResponseWriter) (auth.Identity, error) {
	token := r.URL.Query().Get(a.param)
	if token == "" {
		return nil, auth.ErrNoCredentials
	}

	return a.GetIdentityByToken(r.Context(), token)
}

// Challenge implements Authenticator.Challenge.
func (a *QueryToken) Challenge(r *http.Request, w http.ResponseWriter) {
}
