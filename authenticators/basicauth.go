// Copyright 2020 CleverGo. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

package authenticators

import (
	"fmt"
	"net/http"

	"github.com/clevergo/auth"
)

// BasicAuth is an authenticator that authenticates an user with the given username.
type BasicAuth struct {
	realm    string
	validate func(username, password string) bool
	store    auth.IdentityStore
}

// NewBasicAuth returns an instance of BasicAuth authticator.
func NewBasicAuth(realm string, validate func(username, password string) bool, store auth.IdentityStore) *BasicAuth {
	return &BasicAuth{
		realm:    realm,
		validate: validate,
		store:    store,
	}
}

// Authenticate implements Authenticator.Authenticate.
func (ba *BasicAuth) Authenticate(r *http.Request) (auth.Identity, error) {
	username, password, ok := r.BasicAuth()
	if !ok || !ba.validate(username, password) {
		return nil, ErrNoCredentials
	}

	return ba.store.GetIdentityByToken(username)
}

// Challenge implements Authenticator.Challenge.
func (ba *BasicAuth) Challenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, ba.realm))
}
