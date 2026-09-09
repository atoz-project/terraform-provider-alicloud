//go:build !windows

package alicloud

import (
	"os"
	"syscall"
)

// saeDeployLockFile takes an advisory exclusive lock on the journal lock
// file. The kernel releases the lock when the process dies, so a killed
// provider can never wedge later runs on the same runner.
func saeDeployLockFile(f *os.File, blocking bool) error {
	how := syscall.LOCK_EX
	if !blocking {
		how |= syscall.LOCK_NB
	}
	return syscall.Flock(int(f.Fd()), how)
}

func saeDeployUnlockFile(f *os.File) {
	syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
