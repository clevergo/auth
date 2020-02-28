// Copyright 2020 CleverGo. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

package authenticators

import "testing"

func TestNewCookieToken(t *testing.T) {
	param := "token"
	ct := NewCookieToken(param, nil)
	if ct.param != param {
		t.Errorf("expected param %q, got %q", param, ct.param)
	}
}
