// Copyright 2020 CleverGo. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

package authenticators

import (
	"errors"
	"net/http"

	"github.com/clevergo/auth"
)

// Errors
var (
	ErrNoCredentials = errors.New("no credentials provided")
)

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
	for _, authenticator := range c.authenticators {
		if identity, err := authenticator.Authenticate(r); err == nil {
			return identity, nil
		}
	}

	return nil, ErrNoCredentials
}

// Challenge implements Challenge.Authenticate.
func (c *Composite) Challenge(w http.ResponseWriter) {
	for _, authenticator := range c.authenticators {
		authenticator.Challenge(w)
	}
}
