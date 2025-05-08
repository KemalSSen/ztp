package transport

type ReplayBuffer struct {
	size  int
	queue []string
	seen  map[string]struct{}
	index int
}

func NewReplayBuffer(size int) *ReplayBuffer {
	return &ReplayBuffer{
		size:  size,
		queue: make([]string, size),
		seen:  make(map[string]struct{}),
	}
}

func (rb *ReplayBuffer) Seen(nonce string) bool {
	if _, exists := rb.seen[nonce]; exists {
		return true // 🚫 replay
	}

	// 👇 Evict oldest
	old := rb.queue[rb.index]
	if old != "" {
		delete(rb.seen, old)
	}
	rb.queue[rb.index] = nonce
	rb.seen[nonce] = struct{}{}
	rb.index = (rb.index + 1) % rb.size

	return false
}
