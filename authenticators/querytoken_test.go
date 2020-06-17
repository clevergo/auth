// Copyright 2020 CleverGo. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

package authenticators

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"clevergo.tech/auth"
	"github.com/stretchr/testify/assert"
)

func TestNewQueryToken(t *testing.T) {
	store := &nullStore{}
	a := NewQueryToken(store)
	assert.Equal(t, store, a.store)
	assert.Equal(t, defaultTokenParam, a.param)
}

func TestNewQueryTokenParam(t *testing.T) {
	param := "token"
	a := NewQueryTokenParam(nil, param)
	assert.Equal(t, param, a.param)
}

func TestQueryTokenAuthenticate(t *testing.T) {
	cases := []struct {
		token     string
		shouldErr bool
		err       error
	}{
		{"", true, auth.ErrNoCredentials},
		{"foo", false, auth.ErrInvalidCredentials},
		{"bar", false, nil},
	}

	a := NewQueryToken(&nullStore{})
	for _, test := range cases {
		r := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/?%s=%s", defaultTokenParam, test.token), nil)
		w := httptest.NewRecorder()
		identity, err := a.Authenticate(r, w)
		if test.shouldErr {
			assert.Equal(t, test.err, err)
			continue
		}
		assert.Nil(t, err)
		assert.Equal(t, test.token, identity.GetID())
	}
}

func TestQueryTokenChallenge(t *testing.T) {
	a := NewQueryToken(nil)
	w := httptest.NewRecorder()
	a.Challenge(nil, w)
}
