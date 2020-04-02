// Copyright 2020 CleverGo. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

package authenticators

import (
	"errors"
	"net/http"
	"strings"

	"github.com/clevergo/auth"
)

// Errors
var (
	ErrNoCredentials = errors.New("no credentials provided")
)

type CompositeError struct {
	errs []error
}

func (e CompositeError) Error() (s string) {
	errs := make([]string, len(e.errs))
	for i, err := range e.errs {
		errs[i] = err.Error()
	}
	return strings.Join(errs, "; ")
}

// Composite is a set of authenticators.
type Composite struct {
	authenticators []auth.Authenticator
}

// NewComposite returns an instance of composite authenticator.
func NewComposite(authenticators ...auth.Authenticator) *Composite {
	return &Composite{
		authenticators: authenticators,
	}
}

// Authenticate implements Authenticator.Authenticate.
func (c *Composite) Authenticate(r *http.Request) (auth.Identity, error) {
	var errs []error
	for _, authenticator := range c.authenticators {
		identity, err := authenticator.Authenticate(r)
		if err == nil {
			return identity, nil
		}
		errs = append(errs, err)
	}

	return nil, CompositeError{errs: errs}
}

// Challenge implements Challenge.Authenticate.
func (c *Composite) Challenge(w http.ResponseWriter) {
	for _, authenticator := range c.authenticators {
		authenticator.Challenge(w)
	}
}
