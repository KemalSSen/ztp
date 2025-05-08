package transport

import "testing"

func TestReplayBuffer_DetectsReplays(t *testing.T) {
	rb := NewReplayBuffer(3)

	nonces := []string{"A", "B", "C"}

	for _, n := range nonces {
		if rb.Seen(n) {
			t.Errorf("Nonce %s incorrectly marked as seen initially", n)
		}
	}

	// Repeating should now be seen
	for _, n := range nonces {
		if !rb.Seen(n) {
			t.Errorf("Nonce %s not detected as replay", n)
		}
	}
}

func TestReplayBuffer_EvictsOldEntries(t *testing.T) {
	rb := NewReplayBuffer(2)

	// Insert X, Y, Z
	_ = rb.Seen("X") // X in
	_ = rb.Seen("Y") // Y in
	_ = rb.Seen("Z") // Z in, X evicted

	// Confirm X was evicted
	if rb.Seen("X") {
		t.Error("X should have been evicted and accepted as new")
	}

	// Now trigger replays
	_ = rb.Seen("Y") // 1st: false
	if !rb.Seen("Y") {
		t.Error("Y should be detected as replay (2nd call)")
	}

	_ = rb.Seen("Z") // 1st: false
	if !rb.Seen("Z") {
		t.Error("Z should be detected as replay (2nd call)")
	}
}
