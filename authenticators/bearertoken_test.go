// Copyright 2020 CleverGo. All rights reserved.
// Use of this source code is governed by a MIT style license that can be found
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

func TestNewBearerToken(t *testing.T) {
	store := &nullStore{}
	a := NewBearerToken(store)
	assert.Equal(t, store, a.store)
	assert.Equal(t, defaultRealm, a.realm)
}

func TestNewBearerTokenRealm(t *testing.T) {
	realm := "foobar"
	a := NewBearerTokenRealm(nil, realm)
	assert.Equal(t, realm, a.realm)
}

func TestBearerTokenAuthenticate(t *testing.T) {
	cases := []struct {
		prefix    string
		token     string
		shouldErr bool
		err       error
	}{
		{"", "", true, auth.ErrNoCredentials},
		{"", "foo", true, auth.ErrInvalidCredentials},
		{"Bearer", "", true, auth.ErrInvalidCredentials},
		{"Bearer", "foobar", false, nil},
	}

	a := NewBearerToken(&nullStore{})
	for _, test := range cases {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if test.prefix != "" || test.token != "" {
			r.Header.Set("Authorization", fmt.Sprintf("%s %s", test.prefix, test.token))
		}
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

func TestBearerTokenChallenge(t *testing.T) {
	a := NewBearerToken(nil)
	w := httptest.NewRecorder()
	a.Challenge(nil, w)
	assert.Equal(t, fmt.Sprintf(`Authorization realm="%s"`, a.realm), w.Header().Get("WWW-Authenticate"))
}
