// Package bus is the in-process replacement for the Redis pubsub channel
// "logs:<run_id>". WebSocket subscribers attach here for live updates.
package bus

import (
	"encoding/json"
	"sync"
)

// Message is one pubsub payload ({"type": "log"|"status"|"step"|"done", ...}).
type Message struct {
	Type       string          `json:"type"`
	Status     string          `json:"status,omitempty"`
	Message    string          `json:"message,omitempty"`
	Steps      json.RawMessage `json:"steps,omitempty"`
	ElapsedS   *float64        `json:"elapsed_s,omitempty"`
	Returncode *int            `json:"returncode,omitempty"`
	Error      string          `json:"error,omitempty"`
	Total      int             `json:"total,omitempty"` // log_meta
}

type channel struct {
	ch     chan Message
	closed bool
}

type Bus struct {
	mu       sync.Mutex
	channels map[string][]*channel
}

func New() *Bus {
	return &Bus{channels: map[string][]*channel{}}
}

// Subscribe returns a channel receiving everything published to runID from now
// on, plus a cancel function.
func (b *Bus) Subscribe(runID string) (<-chan Message, func()) {
	c := &channel{ch: make(chan Message, 512)}
	b.mu.Lock()
	b.channels[runID] = append(b.channels[runID], c)
	b.mu.Unlock()
	return c.ch, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		list := b.channels[runID]
		for i, x := range list {
			if x == c {
				b.channels[runID] = append(list[:i], list[i+1:]...)
				break
			}
		}
	}
}

// Publish delivers msg to every subscriber; slow consumers drop messages
// rather than block the runner.
func (b *Bus) Publish(runID string, msg Message) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, c := range b.channels[runID] {
		select {
		case c.ch <- msg:
		default:
		}
	}
}
