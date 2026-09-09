//go:build windows

package alicloud

import (
	"os"

	"golang.org/x/sys/windows"
)

// saeDeployLockFile takes an advisory exclusive lock on the journal lock
// file. LockFileEx is the Windows counterpart of flock(2); the lock is
// released by the OS when the process dies.
func saeDeployLockFile(f *os.File, blocking bool) error {
	flags := uint32(windows.LOCKFILE_EXCLUSIVE_LOCK)
	if !blocking {
		flags |= windows.LOCKFILE_FAIL_IMMEDIATELY
	}
	overlapped := &windows.Overlapped{}
	return windows.LockFileEx(windows.Handle(f.Fd()), flags, 0, 1, 0, overlapped)
}

func saeDeployUnlockFile(f *os.File) {
	overlapped := &windows.Overlapped{}
	windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, overlapped)
}
