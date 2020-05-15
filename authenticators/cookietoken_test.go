// Copyright 2020 CleverGo. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

package authenticators

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewCookieToken(t *testing.T) {
	a := NewCookieToken(nil)
	assert.Equal(t, defaultTokenParam, a.param)
}

func TestNewCookieTokenParam(t *testing.T) {
	param := "token"
	a := NewCookieTokenParam(nil, param)
	assert.Equal(t, param, a.param)
}
