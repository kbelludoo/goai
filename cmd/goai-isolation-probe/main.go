// goai-isolation-probe is a trusted helper, built with CGO_ENABLED=0, that
// observes namespace IDs and controlled host resources from INSIDE bwrap.
// Do not let agents replace this executable or influence its arguments.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/kbelludoo/goai/internal/isolationprobe"
)

func main() {
	url := flag.String("host-url", "", "trusted host canary endpoint")
	sentinel := flag.String("sentinel", "", "trusted host sentinel file")
	flag.Parse()
	obs, err := isolationprobe.Run(*url, *sentinel)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := json.NewEncoder(os.Stdout).Encode(obs); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
}
