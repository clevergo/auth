// Copyright 2020 CleverGo. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

package authenticators

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"clevergo.tech/auth"
	"github.com/stretchr/testify/assert"
)

func TestCompositeErrorError(t *testing.T) {
	cases := []struct {
		errs []error
	}{
		{nil},
		{[]error{errors.New("foo")}},
		{[]error{errors.New("foo"), errors.New("bar")}},
	}
	for _, test := range cases {
		err := CompositeError{
			errs: test.errs,
		}
		errMsg := err.Error()
		for _, e := range test.errs {
			assert.Contains(t, errMsg, e.Error())
		}
	}
}

func TestNewComposite(t *testing.T) {
	cases := []struct {
		authenticators []auth.Authenticator
	}{
		{nil},
		{[]auth.Authenticator{NewBearerToken(&nullStore{})}},
		{[]auth.Authenticator{NewBearerToken(&nullStore{}), NewQueryToken(&nullStore{})}},
	}
	for _, test := range cases {
		a := NewComposite(test.authenticators...)
		assert.Equal(t, test.authenticators, a.authenticators)
	}
}

func TestCompositeAuthenticate(t *testing.T) {
	cases := []struct {
		queryToken  string
		bearerToken string
		shouldErr   bool
		err         error
	}{
		{"", "", true, CompositeError{errs: []error{auth.ErrNoCredentials, auth.ErrNoCredentials}}},
		{"foo", "", false, nil},
		{"", "bar", false, nil},
	}
	bt := NewBearerToken(&nullStore{})
	qt := NewQueryToken(&nullStore{})
	a := NewComposite(bt, qt)
	for _, test := range cases {
		r := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/?%s=%s", defaultTokenParam, test.queryToken), nil)
		if test.bearerToken != "" {
			r.Header.Set("Authorization", bearerPrefix+test.bearerToken)
		}
		identity, err := a.Authenticate(r, nil)
		if test.shouldErr {
			assert.Equal(t, test.err, err)
			continue
		}
		assert.Nil(t, err)
		if test.queryToken != "" {
			assert.Equal(t, test.queryToken, identity.GetID())
		} else {
			assert.Equal(t, test.bearerToken, identity.GetID())
		}
	}
}

func TestCompositeChallenge(t *testing.T) {
	bt := NewBearerToken(nil)
	a := NewComposite(bt)
	w := httptest.NewRecorder()
	a.Challenge(nil, w)
	assert.Equal(t, fmt.Sprintf(`Authorization realm="%s"`, bt.realm), w.Header().Get("WWW-Authenticate"))
}
