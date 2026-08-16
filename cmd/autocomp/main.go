package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/adhamelmahallawi/autocomp/pkg/seccomp"
	"github.com/adhamelmahallawi/autocomp/pkg/tracer"
)

const banner = `
             __                                
  ____ ___  / /_____  _________  ____ ___  ____ 
 / __ '/ / / / __/ __ \/ ___/ __ \/ __ '__ \/ __ \
/ /_/ / /_/ /_/ /_/ / /__/ /_/ / / / / / / /_/ /
\__,_/\__,_/\__/\____/\___/\____/_/ /_/ /_/ .___/ 
                                         /_/      
           Automated Seccomp Profiler
`

func main() {
	var output string
	var appendMode bool

	flag.StringVar(&output, "o", "profile.json", "Output path for the Seccomp profile")
	flag.StringVar(&output, "output", "profile.json", "Output path for the Seccomp profile")
	flag.BoolVar(&appendMode, "a", false, "Append detected syscalls to an existing profile")
	flag.BoolVar(&appendMode, "append", false, "Append detected syscalls to an existing profile")

	flag.Usage = func() {
		fmt.Println(banner)
		fmt.Println("Usage: autocomp [flags] -- <command> [args...]")
		fmt.Println("\nFlags:")
		flag.PrintDefaults()
		fmt.Println("\nExample:")
		fmt.Println("  autocomp -o custom.json -a -- curl https://example.com")
	}

	flag.Parse()

	targetCmd := flag.Args()
	if len(targetCmd) < 1 {
		flag.Usage()
		os.Exit(1)
	}

	fmt.Println(banner)
	fmt.Printf("[*] Output Target : %s\n", output)
	fmt.Printf("[*] Append Mode   : %v\n", appendMode)
	fmt.Printf("[*] Command       : %s\n\n", strings.Join(targetCmd, " "))

	detectedSyscalls, err := tracer.Trace(targetCmd)
	if err != nil {
		fmt.Printf("[!] Tracing failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[*] Generating Seccomp profile...")

	err = seccomp.GenerateProfile(detectedSyscalls, output, appendMode)
	if err != nil {
		fmt.Printf("[!] Error generating profile: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[+] Success. Profile written to %s\n", output)
}
