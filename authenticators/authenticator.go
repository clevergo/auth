// Copyright 2020 CleverGo. All rights reserved.
// Use of this source code is governed by a MIT style license that can be found
// in the LICENSE file.

package authenticators

import (
	"context"

	"clevergo.tech/auth"
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

func (a *authenticator) GetIdentityByToken(ctx context.Context, token string) (auth.Identity, error) {
	return a.store.GetIdentityByToken(ctx, token, a.tokenType)
}
