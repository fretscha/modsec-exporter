package tail

import (
	"bufio"
	"os"
)

// Replay reads a file once start→EOF, emits each line, then closes.
// Used for development, smoke tests, and the --replay CLI flag.
type Replay struct {
	f      *os.File
	lines  chan string
	errors chan error
	done   chan struct{}
}

// NewReplay opens path and starts pumping lines into the channel.
func NewReplay(path string) (*Replay, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	r := &Replay{
		f:      f,
		lines:  make(chan string, 1024),
		errors: make(chan error, 1),
		done:   make(chan struct{}),
	}
	go r.pump()
	return r, nil
}

// Lines returns the line channel; closed when EOF reached or Close() called.
func (r *Replay) Lines() <-chan string { return r.lines }

// Errors returns the error channel.
func (r *Replay) Errors() <-chan error { return r.errors }

// Close stops the pump and releases the file handle.
func (r *Replay) Close() error {
	select {
	case <-r.done:
	default:
		close(r.done)
	}
	return r.f.Close()
}

func (r *Replay) pump() {
	defer close(r.lines)
	sc := bufio.NewScanner(r.f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024) // ModSec error lines can exceed 64K
	for sc.Scan() {
		select {
		case <-r.done:
			return
		case r.lines <- sc.Text():
		}
	}
	if err := sc.Err(); err != nil {
		select {
		case r.errors <- err:
		default:
		}
	}
}
