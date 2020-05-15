// Copyright 2020 CleverGo. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

package auth

import (
	"net/http"
)

// Authenticator is an interface that authenticates an user.
type Authenticator interface {
	// Authenticates the current user.
	Authenticate(*http.Request, http.ResponseWriter) (Identity, error)

	// Challenge generates challenges upon authentication failure.
	Challenge(*http.Request, http.ResponseWriter)
}
