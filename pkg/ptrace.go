//go:build linux && amd64

package tracer

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

func Trace(command []string) ([]string, error) {
	fmt.Printf("[~] Initializing ptrace supervisor for PID execution...\n")

	cmd := exec.Command(command[0], command[1:]...)

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Ptrace: true,
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start command: %v", err)
	}

	pid := cmd.Process.Pid
	var ws syscall.WaitStatus

	_, err := syscall.Wait4(pid, &ws, 0, nil)
	if err != nil {
		return nil, err
	}

	// Relentlessly follow threads, forks, vforks, and sub-executions
	options := syscall.PTRACE_O_TRACESYSGOOD | 
		syscall.PTRACE_O_TRACECLONE | 
		syscall.PTRACE_O_TRACEFORK | 
		syscall.PTRACE_O_TRACEVFORK | 
		syscall.PTRACE_O_TRACEEXEC
		
	syscall.PtraceSetOptions(pid, options)

	syscallIDs := make(map[uint64]bool)

	fmt.Println("[~] Tracing active. Forwarding target stdout/stderr...")
	fmt.Println("-------------------------------------------------------")

	syscall.PtraceSyscall(pid, 0)

	for {
		wpid, err := syscall.Wait4(-1, &ws, 0, nil)
		if err != nil {
			break
		}

		if ws.Exited() {
			if wpid == pid {
				break
			}
			continue
		}

		if ws.Stopped() && ws.StopSignal() == (syscall.SIGTRAP|0x80) {
			var regs syscall.PtraceRegs

			err = syscall.PtraceGetRegs(wpid, &regs)
			if err == nil {
				syscallIDs[regs.Orig_rax] = true
			}
		}

		err = syscall.PtraceSyscall(wpid, 0)
		if err != nil {
			break
		}
	}

	fmt.Println("\n-------------------------------------------------------")
	fmt.Printf("[+] Trace complete. Captured %d distinct system calls.\n", len(syscallIDs))

	var allowedSyscalls []string
	for id := range syscallIDs {
		name, exists := SyscallNames[id]
		if exists {
			allowedSyscalls = append(allowedSyscalls, name)
		} else {
			fmt.Printf("[!] Warning: Unmapped syscall ID detected: %d\n", id)
		}
	}

	return allowedSyscalls, nil
}
