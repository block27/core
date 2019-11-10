package utils

import (
	"fmt"
	"os"
)

// MkDataDir creates a data directory of appropriate (paranoid) permissions if
// it does not exist, and validates that existing directories have the intended
// permissions if it does exist.
func MkDataDir(f string) error {
	const dirMode = os.ModeDir | 0700

	if fi, err := os.Lstat(f); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to stat() dir: %v", err)
		}
		if err = os.Mkdir(f, dirMode); err != nil {
			return fmt.Errorf("failed to create dir: %v", err)
		}
	} else {
		if !fi.IsDir() {
			return fmt.Errorf("dir '%v' is not a directory", f)
		}
		if fi.Mode() != dirMode {
			return fmt.Errorf("dir '%v' has invalid permissions '%v", f, fi.Mode())
		}
	}
	return nil
}
