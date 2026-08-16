# autocomp 
*Automated Seccomp Profiling for Cloud-Native Developers*

`autocomp` is a lightweight, zero-dependency local CLI tool that safely automates Seccomp profile generation for Docker and Kubernetes workloads. 

Instead of deploying heavy eBPF cluster operators to production, `autocomp` uses native `ptrace` in your local dev or CI/CD environment to trace your application, capture its exact system calls (including threads and child processes), and generate a strict, production-ready `profile.json`.

## Features
- **Zero Infrastructure:** Runs entirely locally or in CI/CD pipelines.
- **Deep Process Tracking:** Native support for tracing goroutines, background threads, forks, and child processes.
- **Test Suite Merging:** Append mode (`-a`) allows you to run your entire integration test suite and merge the syscalls into a single deduplicated, alphabetically sorted profile.
- **Production Ready:** Outputs the exact JSON schema required by Docker runtimes and the Kubernetes Security Profiles Operator.

## Installation
Make sure you have Go installed, then run:
```bash
go install [github.com/adhamelmahallawi/autocomp/cmd/autocomp@latest](https://github.com/adhamelmahallawi/autocomp/cmd/autocomp@latest)
```

## Usage
Trace a standard binary:
```bash
autocomp -o profile.json -- ls /tmp
```

Merge multiple test runs into one profile:
```bash
autocomp -o profile.json -a -- curl [https://api.my-app.com/test1](https://api.my-app.com/test1)
autocomp -o profile.json -a -- curl [https://api.my-app.com/test2](https://api.my-app.com/test2)
```
