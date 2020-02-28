// Copyright 2020 CleverGo. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

package authenticators

import "testing"

func TestNewBearerToken(t *testing.T) {
	realm := "token"
	bt := NewBearerToken(realm, nil)
	if bt.realm != realm {
		t.Errorf("expected realm %q, got %q", realm, bt.realm)
	}
}
