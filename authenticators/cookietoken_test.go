// Copyright 2020 CleverGo. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

package authenticators

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/clevergo/auth"
	"github.com/stretchr/testify/assert"
)

func TestNewCookieToken(t *testing.T) {
	store := &nullStore{}
	a := NewCookieToken(store)
	assert.Equal(t, store, a.store)
	assert.Equal(t, defaultTokenParam, a.param)
}

func TestNewCookieTokenParam(t *testing.T) {
	param := "token"
	a := NewCookieTokenParam(nil, param)
	assert.Equal(t, param, a.param)
}

func TestCookieTokenAuthenticate(t *testing.T) {
	cases := []struct {
		token     string
		shouldErr bool
		err       error
	}{
		{"", true, auth.ErrNoCredentials},
		{"foo", false, auth.ErrInvalidCredentials},
		{"bar", false, nil},
	}

	a := NewCookieToken(&nullStore{})
	for _, test := range cases {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(&http.Cookie{
			Name:  defaultTokenParam,
			Value: test.token,
		})
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

func TestCookieTokenChallenge(t *testing.T) {
	a := NewCookieToken(nil)
	w := httptest.NewRecorder()
	a.Challenge(nil, w)
}
