// Package tail abstracts file tailing so production (file watch) and replay
// (read-once) share the same aggregator code path.
package tail

import "context"

// Tailer emits log lines on Lines until ctx is cancelled or, in replay mode,
// EOF is reached. Implementations must close Lines when done. Errors emitted
// on Errors are non-fatal; the caller increments a counter and continues.
type Tailer interface {
	Lines() <-chan string
	Errors() <-chan error
	Close() error
}

// Run wires a Tailer to onLine / onError callbacks until ctx is cancelled
// or the lines channel closes. Used by main.go.
func Run(ctx context.Context, t Tailer, onLine func(string), onError func(error)) {
	defer t.Close()
	for {
		select {
		case <-ctx.Done():
			return
		case line, ok := <-t.Lines():
			if !ok {
				return
			}
			onLine(line)
		case err, ok := <-t.Errors():
			if !ok {
				continue
			}
			onError(err)
		}
	}
}
