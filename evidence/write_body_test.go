package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteBodyDurableCommit(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	body := []byte("complete evidence body\x00\xff")
	sum := sha256.Sum256(body)
	want := hex.EncodeToString(sum[:])
	for i := 0; i < 2; i++ {
		got, err := s.writeBody(bytes.NewReader(body), int64(len(body)), want)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("hash = %q, want %q", got, want)
		}
		path, err := hashPath(s.Dir, got)
		if err != nil {
			t.Fatal(err)
		}
		if err := verifyFile(path, want, int64(len(body))); err != nil {
			t.Fatal(err)
		}
	}
	assertEmptyStaging(t, s.Dir)
}

type failedBodyReader struct{ err error }

func (r failedBodyReader) Read([]byte) (int, error) { return 0, r.err }

func TestWriteBodyFailuresLeaveNoPartialBlob(t *testing.T) {
	readErr := errors.New("body read interrupted")
	for _, name := range []string{"reader_error", "length_mismatch", "hash_mismatch", "destination_failure"} {
		t.Run(name, func(t *testing.T) {
			s := &Store{Dir: t.TempDir()}
			var reader io.Reader = strings.NewReader("body")
			length, hash := int64(4), ""
			switch name {
			case "reader_error":
				reader = io.MultiReader(reader, failedBodyReader{readErr})
			case "length_mismatch":
				length++
			case "hash_mismatch":
				hash = strings.Repeat("0", 64)
			case "destination_failure":
				if err := os.WriteFile(filepath.Join(s.Dir, "blobs"), []byte("blocked"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := s.writeBody(reader, length, hash)
			if err == nil || got != "" {
				t.Fatalf("writeBody = %q, %v; want failure without a hash", got, err)
			}
			if name == "reader_error" && !errors.Is(err, readErr) {
				t.Fatalf("read error lost: %v", err)
			}
			assertEmptyStaging(t, s.Dir)
			if name != "destination_failure" {
				if _, err := os.Stat(filepath.Join(s.Dir, "blobs")); !os.IsNotExist(err) {
					t.Fatalf("partial blob published: %v", err)
				}
			}
		})
	}
}

func assertEmptyStaging(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, ".staging"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("staging files remain: %v, %v", entries, err)
	}
}

func TestWriteBodyRejectsCorruptedStoredBlob(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	body := []byte("original body")
	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	path, err := hashPath(s.Dir, hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := s.writeBody(bytes.NewReader(body), int64(len(body)), hash); err == nil || got != "" {
		t.Fatalf("accepted corrupted stored blob: %q, %v", got, err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "corrupt" {
		t.Fatalf("overwrote corrupted stored blob: %q, %v", got, err)
	}
	assertEmptyStaging(t, s.Dir)
}

func TestCommitBodyFilePropagatesMoveFailure(t *testing.T) {
	dir := t.TempDir()
	staged, target := filepath.Join(dir, "staged"), filepath.Join(dir, "target")
	if err := os.WriteFile(staged, []byte("complete body"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := commitBodyFile(staged, target); err == nil {
		t.Fatal("move into an existing directory reported success")
	}
	if got, err := os.ReadFile(staged); err != nil || string(got) != "complete body" {
		t.Fatalf("failed move damaged staging: %q, %v", got, err)
	}
}
