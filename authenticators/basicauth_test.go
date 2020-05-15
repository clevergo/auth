// Copyright 2020 CleverGo. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

package authenticators

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewBasicAuth(t *testing.T) {
	a := NewBasicAuth(nil, nil)
	assert.Equal(t, defaultRealm, a.realm)
}

func TestNewBasicAuthRealm(t *testing.T) {
	realm := "foobar"
	a := NewBasicAuthRealm(nil, nil, realm)
	assert.Equal(t, realm, a.realm)
}
