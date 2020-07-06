// Copyright 2020 CleverGo. All rights reserved.
// Use of this source code is governed by a MIT style license that can be found
// in the LICENSE file.

package auth

import "errors"

// Errors
var (
	ErrNoCredentials      = errors.New("no credentials provided")
	ErrInvalidCredentials = errors.New("invalid credentials")
)
