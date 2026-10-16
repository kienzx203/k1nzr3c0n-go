//go:build linux || darwin

package api

import "syscall"

type syscallStatfs = syscall.Statfs_t

func statfsRaw(path string, st *syscallStatfs) error {
	return syscall.Statfs(path, st)
}
