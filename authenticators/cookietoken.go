// Copyright 2020 CleverGo. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

package authenticators

import (
	"net/http"

	"github.com/clevergo/auth"
)

// CookieToken is an authenticator that retrieves token from cookie and authenticates an user.
type CookieToken struct {
	param string
	store auth.IdentityStore
}

// NewCookieToken returns an instance of CookieToken authenticator.
func NewCookieToken(param string, store auth.IdentityStore) *CookieToken {
	return &CookieToken{
		param: param,
		store: store,
	}
}

// Authenticate implements Authenticator.Authenticate.
func (ct *CookieToken) Authenticate(r *http.Request) (auth.Identity, error) {
	cookie, err := r.Cookie(ct.param)
	if err != nil {
		return nil, err
	}

	if cookie.Value == "" {
		return nil, ErrNoCredentials
	}

	return ct.store.GetIdentityByToken(cookie.Value)
}

// Challenge implements Authenticator.Challenge.
func (ct *CookieToken) Challenge(http.ResponseWriter) {
}
