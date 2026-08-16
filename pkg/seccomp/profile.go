package seccomp

import (
	"encoding/json"
	"os"
	"sort"
)

type SeccompProfile struct {
	DefaultAction string    `json:"defaultAction"`
	Architectures []string  `json:"architectures"`
	Syscalls      []Syscall `json:"syscalls"`
}

type Syscall struct {
	Names  []string `json:"names"`
	Action string   `json:"action"`
}

func GenerateProfile(newSyscalls []string, outputPath string, appendMode bool) error {
	syscallSet := make(map[string]bool)

	if appendMode {
		if data, err := os.ReadFile(outputPath); err == nil {
			var existingProfile SeccompProfile
			if err := json.Unmarshal(data, &existingProfile); err == nil {
				if len(existingProfile.Syscalls) > 0 {
					for _, sc := range existingProfile.Syscalls[0].Names {
						syscallSet[sc] = true
					}
				}
			}
		}
	}

	for _, sc := range newSyscalls {
		syscallSet[sc] = true
	}

	var finalSyscalls []string
	for sc := range syscallSet {
		finalSyscalls = append(finalSyscalls, sc)
	}

	sort.Strings(finalSyscalls)

	profile := SeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{
			"SCMP_ARCH_X86_64",
		},
		Syscalls: []Syscall{
			{
				Names:  finalSyscalls,
				Action: "SCMP_ACT_ALLOW",
			},
		},
	}

	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(outputPath, data, 0644)
}
