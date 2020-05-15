// Copyright 2020 CleverGo. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

package authenticators

import (
	"testing"

	"github.com/clevergo/auth"
	"github.com/stretchr/testify/assert"
)

type nullIdentity struct {
	id string
}

func (i *nullIdentity) GetID() string {
	return i.id
}

type nullStore struct {
}

func (nullStore) GetIdentity(id string) (auth.Identity, error) {
	return &nullIdentity{id}, nil
}

func (nullStore) GetIdentityByToken(token, tokenType string) (auth.Identity, error) {
	return &nullIdentity{token}, nil
}

func TestAuthenticatorSetToken(t *testing.T) {
	a := &authenticator{}
	tokenType := "basic"
	a.SetTokenType(tokenType)
	assert.Equal(t, tokenType, a.tokenType)
}

func TestAuthenticatorGetIdentityByToken(t *testing.T) {
	a := &authenticator{store: &nullStore{}}
	token := "foobar"
	identity, _ := a.GetIdentityByToken(token)
	assert.Equal(t, token, identity.GetID())
}
