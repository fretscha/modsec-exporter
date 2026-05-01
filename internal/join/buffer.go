// Package join correlates ModSecurity error events with their access-log
// entry by Apache unique_id, with bounded memory.
//
// The buffer is bidirectional: it holds either pending error events (waiting
// for the access entry) OR a recent access summary (waiting for late error
// events). In production, error events almost always arrive first, but
// concurrent log replay (and pathological flush ordering) can reverse that —
// so the buffer joins regardless of order.
package join

import (
	"container/list"
	"time"
)

// Pending is one error event waiting for its access-log entry.
// Hostname is carried so orphan emission still gets a useful label.
type Pending struct {
	RuleID   string
	Severity string
	Hostname string
}

// AccessSummary is the access-side data we hold while waiting for late error events.
type AccessSummary struct {
	StatusClass string
	Hostname    string
}

// Orphan is an entry whose access event never arrived (TTL expired).
type Orphan struct {
	UniqueID string
	Pending  []Pending
}

// slot holds either pending error events OR a remembered access summary.
// Only one of `events` / `access` is non-empty at a time.
type slot struct {
	uniqueID string
	added    time.Time
	events   []Pending
	access   *AccessSummary
}

// Buffer is a bounded LRU keyed by unique_id with TTL eviction.
// Not safe for concurrent use; callers serialize.
type Buffer struct {
	maxSize int
	ttl     time.Duration
	now     func() time.Time
	order   *list.List // front = newest, back = oldest
	index   map[string]*list.Element
	evicted uint64
}

// NewBuffer creates a Buffer with the given size cap, TTL, and clock.
// Pass nil for now to use time.Now.
func NewBuffer(maxSize int, ttl time.Duration, now func() time.Time) *Buffer {
	if now == nil {
		now = time.Now
	}
	return &Buffer{
		maxSize: maxSize,
		ttl:     ttl,
		now:     now,
		order:   list.New(),
		index:   make(map[string]*list.Element),
	}
}

// Append adds an error event to the slot for unique_id, creating it if absent.
// On overflow, evicts the oldest slot (LRU) and increments OrphansEvicted.
func (b *Buffer) Append(uid string, ev Pending) {
	if el, ok := b.index[uid]; ok {
		s := el.Value.(*slot)
		// If the slot already has an access summary remembered, the caller
		// should have used TakeAccess; defensively, reset to events mode.
		if s.access != nil {
			s.access = nil
		}
		s.events = append(s.events, ev)
		b.order.MoveToFront(el)
		return
	}
	s := &slot{uniqueID: uid, added: b.now(), events: []Pending{ev}}
	el := b.order.PushFront(s)
	b.index[uid] = el
	b.enforceSize()
}

// Drain returns and removes all error events for unique_id, or nil if absent.
// If the slot is currently holding an AccessSummary (no events), returns nil.
func (b *Buffer) Drain(uid string) []Pending {
	el, ok := b.index[uid]
	if !ok {
		return nil
	}
	s := el.Value.(*slot)
	if len(s.events) == 0 {
		return nil
	}
	b.order.Remove(el)
	delete(b.index, uid)
	return s.events
}

// RememberAccess stores access-side data for unique_id, so a late error event
// can still join. If the slot already has pending error events, this is a no-op
// (the caller should drain them on the access side instead).
func (b *Buffer) RememberAccess(uid string, summary AccessSummary) {
	if el, ok := b.index[uid]; ok {
		s := el.Value.(*slot)
		if len(s.events) > 0 {
			// Errors already pending — caller is expected to drain via Drain().
			return
		}
		s.access = &summary
		b.order.MoveToFront(el)
		return
	}
	s := &slot{uniqueID: uid, added: b.now(), access: &summary}
	el := b.order.PushFront(s)
	b.index[uid] = el
	b.enforceSize()
}

// PeekAccess returns the remembered AccessSummary for unique_id without
// removing it, or nil if none. Used when an error event arrives after its
// access entry — multiple late errors for the same uid all consume the same
// summary; cleanup happens via TTL eviction.
func (b *Buffer) PeekAccess(uid string) *AccessSummary {
	el, ok := b.index[uid]
	if !ok {
		return nil
	}
	s := el.Value.(*slot)
	if s.access == nil {
		return nil
	}
	return s.access
}

// SweepExpired removes and returns slots older than ttl.
// Slots holding only access summaries (not pending errors) are dropped silently
// — they don't represent rule firings, just unmatched access bookkeeping.
func (b *Buffer) SweepExpired() []Orphan {
	cutoff := b.now().Add(-b.ttl)
	var out []Orphan
	for {
		back := b.order.Back()
		if back == nil {
			break
		}
		s := back.Value.(*slot)
		if !s.added.Before(cutoff) {
			break
		}
		b.order.Remove(back)
		delete(b.index, s.uniqueID)
		if len(s.events) > 0 {
			out = append(out, Orphan{UniqueID: s.uniqueID, Pending: s.events})
		}
	}
	return out
}

// Size returns the current number of slots (events + access).
func (b *Buffer) Size() int { return b.order.Len() }

// OrphansEvicted is the lifetime count of slots evicted due to size overflow.
func (b *Buffer) OrphansEvicted() uint64 { return b.evicted }

func (b *Buffer) enforceSize() {
	for b.order.Len() > b.maxSize {
		oldest := b.order.Back()
		if oldest == nil {
			break
		}
		b.order.Remove(oldest)
		delete(b.index, oldest.Value.(*slot).uniqueID)
		b.evicted++
	}
}
