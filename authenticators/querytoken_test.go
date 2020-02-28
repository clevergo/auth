// Copyright 2020 CleverGo. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

package authenticators

import "testing"

func TestNewQueryToken(t *testing.T) {
	param := "token"
	qt := NewQueryToken(param, nil)
	if qt.param != param {
		t.Errorf("expected param %q, got %q", param, qt.param)
	}
}
