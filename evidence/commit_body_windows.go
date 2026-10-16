package evidence

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// The staged file has already been synced and closed. Windows cannot sync the
// read-only directory handle used on POSIX; commit its rename with write-through
// instead. Omitting COPY_ALLOWED keeps cross-volume moves from becoming copies.
// https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-movefileexw
func commitBodyFile(staged, target string) error {
	from, err := bodyFileWindowsPath(staged)
	if err != nil {
		return err
	}
	to, err := bodyFileWindowsPath(target)
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return &os.LinkError{Op: "rename", Old: staged, New: target, Err: err}
	}
	return nil
}

// Preserve os.Rename's long-path support when calling the Windows API directly.
func bodyFileWindowsPath(name string) (*uint16, error) {
	path, err := filepath.Abs(name)
	if err != nil {
		return nil, err
	}
	if len(path) >= 248 && !strings.HasPrefix(path, `\\?\`) {
		if strings.HasPrefix(path, `\\`) {
			path = `\\?\UNC\` + path[2:]
		} else {
			path = `\\?\` + path
		}
	}
	return windows.UTF16PtrFromString(path)
}
