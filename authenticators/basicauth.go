// Copyright 2020 CleverGo. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

package authenticators

import (
	"fmt"
	"net/http"

	"github.com/clevergo/auth"
)

var _ auth.Authenticator = &BasicAuth{}

// BasicAuthValidator is a function that validates the given username and
// password is valid or not.
type BasicAuthValidator func(username, password string) bool

// BasicAuth is an authenticator that authenticates an user with the given username.
type BasicAuth struct {
	*authenticator
	realm     string
	validator BasicAuthValidator
}

// NewBasicAuth returns an instance of BasicAuth authticator.
func NewBasicAuth(store auth.IdentityStore, validator BasicAuthValidator) *BasicAuth {
	return NewBasicAuthRealm(store, validator, defaultRealm)
}

// NewBasicAuthRealm returns an instance of BasicAuth authticator.
func NewBasicAuthRealm(store auth.IdentityStore, validator BasicAuthValidator, realm string) *BasicAuth {
	return &BasicAuth{
		authenticator: newAuthenticator(store),
		validator:     validator,
		realm:         realm,
	}
}

// Authenticate implements Authenticator.Authenticate.
func (a *BasicAuth) Authenticate(r *http.Request, w http.ResponseWriter) (auth.Identity, error) {
	username, password, ok := r.BasicAuth()
	if !ok {
		return nil, auth.ErrNoCredentials
	}
	if !a.validator(username, password) {
		return nil, auth.ErrInvalidCredentials
	}

	return a.GetIdentityByToken(r.Context(), username)
}

// Challenge implements Authenticator.Challenge.
func (a *BasicAuth) Challenge(r *http.Request, w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, a.realm))
}
