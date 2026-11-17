// Command portcullis is the Portcullis CLI (contract §18): `portcullis
// login` for people and `portcullis host …` for hosts. It imports nothing
// from the Hub but internal/cliapi (deps_test.go).
package main

import (
	"fmt"
	"os"

	"github.com/portcullis/hub/internal/cliapi"
)

// version is set at build time (-ldflags "-X main.version=…").
var version = "dev"

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Printf("portcullis %s (api %d)\n", version, cliapi.APIVersion)
		return
	}
	fmt.Fprintln(os.Stderr, "usage: portcullis version")
	os.Exit(2)
}
