// Copyright 2020 CleverGo. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

package auth

// Identity is an interface that should be implemented by an user instance.
type Identity interface {
	GetID() string
}

// IdentityStore is a store interface for retrieving identity by ID or token.
type IdentityStore interface {
	// Gets identity by ID.
	GetIdentity(id string) (Identity, error)

	// Gets identity by the given token and token type.
	GetIdentityByToken(token string, tokenType interface{}) (Identity, error)
}
