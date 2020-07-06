// Copyright 2020 CleverGo. All rights reserved.
// Use of this source code is governed by a MIT style license that can be found
// in the LICENSE file.

package authenticators

import (
	"net/http"
	"strings"

	"clevergo.tech/auth"
)

// CompositeError contains errors that returned by authenticators.
type CompositeError struct {
	errs []error
}

// Error returns error message.
func (e CompositeError) Error() (s string) {
	errs := make([]string, len(e.errs))
	for i, err := range e.errs {
		errs[i] = err.Error()
	}
	return strings.Join(errs, "; ")
}

var _ auth.Authenticator = &Composite{}

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
func (a *Composite) Authenticate(r *http.Request, w http.ResponseWriter) (auth.Identity, error) {
	var errs []error
	for _, authenticator := range a.authenticators {
		identity, err := authenticator.Authenticate(r, w)
		if err == nil {
			return identity, nil
		}
		errs = append(errs, err)
	}

	return nil, CompositeError{errs: errs}
}

// Challenge implements Challenge.Authenticate.
func (a *Composite) Challenge(r *http.Request, w http.ResponseWriter) {
	for _, authenticator := range a.authenticators {
		authenticator.Challenge(r, w)
	}
}
