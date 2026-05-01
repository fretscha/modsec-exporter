package tail

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReplay_ReadsAllLinesThenCloses(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "log")
	if err := os.WriteFile(p, []byte("a\nb\nc\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	tl, err := NewReplay(p)
	if err != nil {
		t.Fatal(err)
	}

	var got []string
	for line := range tl.Lines() {
		got = append(got, line)
	}
	if len(got) != 3 || got[0] != "a" || got[2] != "c" {
		t.Fatalf("got %#v", got)
	}
}

func TestReplay_MissingFileError(t *testing.T) {
	if _, err := NewReplay("/no/such/file"); err == nil {
		t.Fatal("expected error for missing file")
	}
}
