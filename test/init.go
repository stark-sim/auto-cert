package test

import (
	"os"
)

// This file exists to set environment variables BEFORE any other code imports
// The init() runs before any package imports that reference this package
func init() {
	os.Setenv("AUTO_CERT_SKIP_INIT", "true")
}
