package evidence

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteBodyWindowsLongPath(t *testing.T) {
	dir := t.TempDir()
	for len(dir) < 300 {
		dir = filepath.Join(dir, "nested-evidence-directory")
	}
	s := &Store{Dir: dir}
	hash, err := s.writeBody(strings.NewReader("body"), 4, "")
	if err != nil {
		t.Fatal(err)
	}
	path, err := hashPath(dir, hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyFile(path, hash, 4); err != nil {
		t.Fatal(err)
	}
	assertEmptyStaging(t, dir)
}
