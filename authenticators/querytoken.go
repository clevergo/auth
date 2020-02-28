// Copyright 2020 CleverGo. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

package authenticators

import (
	"net/http"

	"github.com/clevergo/auth"
)

// QueryToken is an authenticator that retrieves token from URL query and authenticate an user.
type QueryToken struct {
	param string
	store auth.IdentityStore
}

// NewQueryToken returns a instance of QueryToken authenticator.
func NewQueryToken(param string, store auth.IdentityStore) *QueryToken {
	return &QueryToken{param: param, store: store}
}

// Authenticate implements Authenticator.Authenticate.
func (qt *QueryToken) Authenticate(r *http.Request) (auth.Identity, error) {
	token := r.URL.Query().Get(qt.param)
	if token == "" {
		return nil, ErrNoCredentials
	}

	return qt.store.GetIdentityByToken(token)
}

// Challenge implements Authenticator.Challenge.
func (qt *QueryToken) Challenge(w http.ResponseWriter) {
}
