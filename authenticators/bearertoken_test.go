// Copyright 2020 CleverGo. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

package authenticators

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewBearerToken(t *testing.T) {
	a := NewBearerToken(nil)
	assert.Equal(t, defaultRealm, a.realm)
}

func TestNewBearerTokenRealm(t *testing.T) {
	realm := "foobar"
	a := NewBearerTokenRealm(nil, realm)
	assert.Equal(t, realm, a.realm)
}
