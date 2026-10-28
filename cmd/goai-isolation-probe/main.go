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
	processAudit := flag.Bool("process-audit", false, "trusted process containment check")
	daemon := flag.Bool("canary-daemon", false, "internal canary descendant")
	canaryID := flag.String("canary-id", "", "trusted correlation nonce")
	control := flag.String("control", "", "private canary coordination directory")
	flag.Parse()
	if *daemon || *processAudit {
		var err error
		if *daemon {
			err = isolationprobe.RunDaemonChild(*canaryID, *control)
		} else {
			err = isolationprobe.RunDaemonParent(*canaryID, *control)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(4)
		}
		return
	}
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
