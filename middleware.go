// Copyright 2020 CleverGo. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

package auth

import (
	"context"
	"log"
	"net/http"
)

type contextKey int

// IdentityKey is the context key of identity.
const IdentityKey contextKey = 1

// GetIdentity retrieves the identity from context.
func GetIdentity(ctx context.Context) Identity {
	identity, _ := ctx.Value(IdentityKey).(Identity)
	return identity
}

// NewMiddleware returns a middleware with the given authenticator.
func NewMiddleware(authenticator Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity, err := authenticator.Authenticate(r, w)
			if err != nil {
				log.Println(err)
				authenticator.Challenge(r, w)
			} else {
				*r = *r.WithContext(context.WithValue(r.Context(), IdentityKey, identity))
			}
			next.ServeHTTP(w, r)
		})
	}
}
