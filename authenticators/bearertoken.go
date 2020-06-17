// Copyright 2020 CleverGo. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

package authenticators

import (
	"fmt"
	"net/http"
	"strings"

	"clevergo.tech/auth"
)

const (
	bearerPrefix = "Bearer "
)

var _ auth.Authenticator = &BearerToken{}

// BearerToken is an authenticator that retrieves bearer token from authorization header
// and authenticates an user.
type BearerToken struct {
	*authenticator
	realm string
}

// NewBearerToken returns an instance of BearerToken authticator with the given store
// and default realm.
func NewBearerToken(store auth.IdentityStore) *BearerToken {
	return NewBearerTokenRealm(store, defaultRealm)
}

// NewBearerTokenRealm returns an instance of BearerToken authticator with the given
// store and realm.
func NewBearerTokenRealm(store auth.IdentityStore, realm string) *BearerToken {
	return &BearerToken{realm: realm, authenticator: newAuthenticator(store)}
}

// Authenticate implements Authenticator.Authenticate.
func (a *BearerToken) Authenticate(r *http.Request, w http.ResponseWriter) (auth.Identity, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return nil, auth.ErrNoCredentials
	}
	token, ok := a.parseBearerToken(header)
	if !ok {
		return nil, auth.ErrInvalidCredentials
	}

	return a.GetIdentityByToken(r.Context(), token)
}

// Challenge implements Authenticator.Challenge.
func (a *BearerToken) Challenge(r *http.Request, w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Authorization realm="%s"`, a.realm))
}

func (a *BearerToken) parseBearerToken(header string) (token string, ok bool) {
	if len(header) <= len(bearerPrefix) || !strings.EqualFold(header[:len(bearerPrefix)], bearerPrefix) {
		return
	}

	return header[len(bearerPrefix):], true
}
