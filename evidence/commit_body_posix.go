//go:build !windows

package evidence

import (
	"os"
	"path/filepath"
)

func commitBodyFile(staged, target string) error {
	if err := os.Rename(staged, target); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(target))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
