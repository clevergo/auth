// Copyright 2020 CleverGo. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

type nullIdentity struct{}

func (nullIdentity) GetID() string {
	return "null"
}

type nullAuthenticator struct {
	authenticated bool
	challenged    bool
}

func (na *nullAuthenticator) Authenticate(*http.Request, http.ResponseWriter) (Identity, error) {
	if na.authenticated {
		return nullIdentity{}, nil
	}
	return nil, errors.New("unauthenticated")
}

func (na *nullAuthenticator) Challenge(r *http.Request, w http.ResponseWriter) {
	na.challenged = true
}

func TestGetIdentity(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	identity := nullIdentity{}
	r = r.WithContext(context.WithValue(r.Context(), IdentityKey, identity))
	assert.Equal(t, identity, GetIdentity(r.Context()))
}

func TestNewMiddleware(t *testing.T) {
	cases := []struct {
		authenticated bool
	}{
		{false},
		{true},
	}
	for _, test := range cases {
		handled := false
		var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handled = true
		})
		a := &nullAuthenticator{authenticated: test.authenticated}
		handler = NewMiddleware(a)(handler)
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		assert.True(t, handled)
		identity := GetIdentity(r.Context())
		if test.authenticated {
			assert.NotNil(t, identity)
		} else {
			assert.True(t, a.challenged)
			assert.Nil(t, identity)
		}
	}
}
