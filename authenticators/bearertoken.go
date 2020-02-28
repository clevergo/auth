// Copyright 2020 CleverGo. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

package authenticators

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/clevergo/auth"
)

// BearerToken is an authenticator that retrieves bearer token from authorization header
// and authenticate an user.
type BearerToken struct {
	realm string
	store auth.IdentityStore
}

// NewBearerToken returns an instance of BearerToken authticator.
func NewBearerToken(realm string, store auth.IdentityStore) *BearerToken {
	return &BearerToken{realm: realm, store: store}
}

// Authenticate implements Authenticator.Authenticate.
func (bt *BearerToken) Authenticate(r *http.Request) (auth.Identity, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return nil, ErrNoCredentials
	}
	token, ok := bt.parseBearerToken(header)
	if !ok {
		return nil, ErrNoCredentials
	}

	return bt.store.GetIdentityByToken(token)
}

// Challenge implements Authenticator.Challenge.
func (bt *BearerToken) Challenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Authorization realm="%s"`, bt.realm))
}

func (bt *BearerToken) parseBearerToken(header string) (token string, ok bool) {
	const prefix = "Bearer "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return
	}

	return header[len(prefix):], true
}
