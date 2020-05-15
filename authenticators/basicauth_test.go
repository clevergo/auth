// Copyright 2020 CleverGo. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

package authenticators

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/clevergo/auth"
	"github.com/stretchr/testify/assert"
)

func TestNewBasicAuth(t *testing.T) {
	store := &nullStore{}
	a := NewBasicAuth(store, nil)
	assert.Equal(t, store, a.store)
	assert.Equal(t, defaultRealm, a.realm)
}

func TestNewBasicAuthRealm(t *testing.T) {
	realm := "foobar"
	a := NewBasicAuthRealm(nil, nil, realm)
	assert.Equal(t, realm, a.realm)
}

func TestBasicAuthAuthenticate(t *testing.T) {
	cases := []struct {
		username  string
		password  string
		shouldErr bool
		err       error
	}{
		{"", "", true, auth.ErrNoCredentials},
		{"foo", "", true, auth.ErrInvalidCredentials},
		{"", "bar", true, auth.ErrInvalidCredentials},
		{"foo", "bar", false, nil},
	}

	a := NewBasicAuth(&nullStore{}, func(username, password string) bool {
		return username == "foo" && password == "bar"
	})
	for _, test := range cases {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if test.username != "" || test.password != "" {
			r.SetBasicAuth(test.username, test.password)
		}
		w := httptest.NewRecorder()
		identity, err := a.Authenticate(r, w)
		if test.shouldErr {
			assert.Equal(t, test.err, err)
			continue
		}
		assert.Nil(t, err)
		assert.Equal(t, test.username, identity.GetID())
	}
}

func TestBasicAuthChallenge(t *testing.T) {
	a := NewBasicAuth(nil, nil)
	w := httptest.NewRecorder()
	a.Challenge(nil, w)
	assert.Equal(t, fmt.Sprintf(`Basic realm="%s"`, a.realm), w.Header().Get("WWW-Authenticate"))
}
