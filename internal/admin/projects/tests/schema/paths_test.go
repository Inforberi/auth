package platform_test

import (
	"path/filepath"
	"runtime"
)

func migrationPath(name string) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "../../../../../migrations", name)
}
