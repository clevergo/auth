// Copyright 2020 CleverGo. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

package authenticators

import (
	"net/http"

	"clevergo.tech/auth"
)

var _ auth.Authenticator = &CookieToken{}

// CookieToken is an authenticator that retrieves token from cookie and authenticates an user.
type CookieToken struct {
	*authenticator
	param string
}

// NewCookieToken returns an instance of CookieToken authenticator with the given store
// and default token param.
func NewCookieToken(store auth.IdentityStore) *CookieToken {
	return NewCookieTokenParam(store, defaultTokenParam)
}

// NewCookieTokenParam returns an instance of CookieToken authenticator with the given store
// and param.
func NewCookieTokenParam(store auth.IdentityStore, param string) *CookieToken {
	return &CookieToken{
		param:         param,
		authenticator: newAuthenticator(store),
	}
}

// Authenticate implements Authenticator.Authenticate.
func (a *CookieToken) Authenticate(r *http.Request, w http.ResponseWriter) (auth.Identity, error) {
	cookie, err := r.Cookie(a.param)
	if err == http.ErrNoCookie || cookie.Value == "" {
		return nil, auth.ErrNoCredentials
	}

	return a.GetIdentityByToken(r.Context(), cookie.Value)
}

// Challenge implements Authenticator.Challenge.
func (a *CookieToken) Challenge(r *http.Request, w http.ResponseWriter) {
}
