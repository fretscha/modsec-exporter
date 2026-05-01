package tail

import (
	"github.com/nxadm/tail"
)

// File is a rotation-aware tailer backed by github.com/nxadm/tail.
type File struct {
	t      *tail.Tail
	lines  chan string
	errors chan error
	done   chan struct{}
}

// NewFile opens path and tails it. If the file doesn't exist yet, the tail
// library will retry. Returns immediately; lines stream asynchronously.
func NewFile(path string) (*File, error) {
	t, err := tail.TailFile(path, tail.Config{
		Follow:    true,
		ReOpen:    true,
		Poll:      false,
		MustExist: false,
		Logger:    tail.DiscardingLogger,
		Location:  &tail.SeekInfo{Whence: 2}, // SEEK_END — start at EOF
	})
	if err != nil {
		return nil, err
	}
	f := &File{
		t:      t,
		lines:  make(chan string, 1024),
		errors: make(chan error, 1),
		done:   make(chan struct{}),
	}
	go f.pump()
	return f, nil
}

// Lines returns the line channel.
func (f *File) Lines() <-chan string { return f.lines }

// Errors returns the error channel.
func (f *File) Errors() <-chan error { return f.errors }

// Close stops the underlying tailer.
func (f *File) Close() error {
	select {
	case <-f.done:
	default:
		close(f.done)
	}
	return f.t.Stop()
}

func (f *File) pump() {
	defer close(f.lines)
	for {
		select {
		case <-f.done:
			return
		case line, ok := <-f.t.Lines:
			if !ok {
				return
			}
			if line.Err != nil {
				select {
				case f.errors <- line.Err:
				default:
				}
				continue
			}
			f.lines <- line.Text
		}
	}
}
