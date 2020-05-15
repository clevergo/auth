// Copyright 2020 CleverGo. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

package authenticators

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewQueryToken(t *testing.T) {
	a := NewQueryToken(nil)
	assert.Equal(t, defaultTokenParam, a.param)
}

func TestNewQueryTokenParam(t *testing.T) {
	param := "token"
	a := NewQueryTokenParam(nil, param)
	assert.Equal(t, param, a.param)
}
