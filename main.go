package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"syscall"
)

var (
	sshConfigPodmanProxy = ""
	sshPodmanProxyPID    = ""
	podmanSocket         string
	podmanHost           string
	podmanUser           string
	podmanPort           string
	podmanIdent          string
	localForward         string
	sshProxyPID          int
	prevSSHConfigSHA1    string
)

func main() {
	// Construct paths using HOMEDRIVE and HOMEPATH
	homeDrive := os.Getenv("HOMEDRIVE")
	homePath := os.Getenv("HOMEPATH")
	home := homeDrive + homePath

	sshConfigPodmanProxy = filepath.Join(home, ".ssh/config_podman_proxy")
	sshPodmanProxyPID = filepath.Join(home, ".ssh/ssh_podman_proxy.pid")

	fmt.Println("## Starting Podman Proxy")
	setupSignalHandler()
	findPodmanRootSocket()
	startProxySSHDaemon()
	go monitorPodmanStartStopEvents()

	select {} // Keep the main function running
}

func logFunctionName() {
	pc, _, _, ok := runtime.Caller(1)
	if ok {
		funcName := runtime.FuncForPC(pc).Name()
		fmt.Println("## ", funcName)
	}
}

func setupSignalHandler() {
	logFunctionName()
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-c
		cleanup()
		os.Exit(0)
	}()
}

func cleanup() {
	logFunctionName()
	fmt.Println("## Cleaning up resources")
	killProxySSHDaemon()
	os.Remove(sshPodmanProxyPID)
}

func findPodmanRootSocket() {
	logFunctionName()
	fmt.Println("## Finding Podman root socket")
	cmd := exec.Command("podman", "system", "connection", "list", "--format={{.Name}}|{{.URI}}")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Error finding Podman root socket:", err)
		return
	}

	lines := bytes.Split(output, []byte{'\n'})
	for _, line := range lines {
		if bytes.Contains(line, []byte("default-root")) {
			parts := bytes.Split(line, []byte{'|'})
			if len(parts) == 2 {
				podmanSocket = string(parts[1])
				break
			}
		}
	}

	// Use regex to extract host, user, port, and identity
	re := regexp.MustCompile(`ssh://([^@]+)@([^:]+):([0-9]+)`)
	matches := re.FindStringSubmatch(podmanSocket)
	if len(matches) == 4 {
		podmanUser = matches[1] // Extract user
		podmanHost = matches[2] // Extract host without user
		podmanPort = matches[3] // Extract port
		fmt.Printf("## Podman Host: %s, User: %s, Port: %s\n", podmanHost, podmanUser, podmanPort)
	}

	podmanIdent = extractPodmanIdent()
}

func extractPodmanIdent() string {
	logFunctionName()
	fmt.Println("## Extracting Podman identity")
	cmd := exec.Command("podman", "system", "connection", "list", "--format={{.Name}}|{{.Identity}}")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Error finding Podman identity:", err)
		return ""
	}

	lines := bytes.Split(output, []byte{'\n'})
	for _, line := range lines {
		if bytes.Contains(line, []byte("default-root")) {
			parts := bytes.Split(line, []byte{'|'})
			if len(parts) == 2 {
				return string(parts[1])
			}
		}
	}
	return ""
}

func startProxySSHDaemon() {
	logFunctionName()
	fmt.Println("## Starting SSH Proxy Daemon")
	localForward = getLocalForward()
	sshConfig := fmt.Sprintf(`Host podman-proxy-ssh
	User %s
	IdentitiesOnly=yes
	StrictHostKeyChecking no
	UserKnownHostsFile=/dev/null
	HostName %s
	Port %s
	IdentityFile %s
	%s`, podmanUser, podmanHost, podmanPort, podmanIdent, localForward)

	currentSSHConfigSHA1 := calculateSHA1(sshConfig)

	if currentSSHConfigSHA1 != prevSSHConfigSHA1 {
		if err := os.WriteFile(sshConfigPodmanProxy, []byte(sshConfig), 0644); err != nil {
			fmt.Println("Error writing SSH config:", err)
			return
		}

		cmd := exec.Command("ssh", "-N", "-T", "-F", sshConfigPodmanProxy, "podman-proxy-ssh")

		// Set up pipes for stdout and stderr
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			fmt.Println("Error setting up stdout pipe:", err)
			return
		}
		stderr, err := cmd.StderrPipe()
		if err != nil {
			fmt.Println("Error setting up stderr pipe:", err)
			return
		}

		if err := cmd.Start(); err != nil {
			fmt.Println("Error starting SSH proxy:", err)
			return
		}
		sshProxyPID = cmd.Process.Pid
		if err := os.WriteFile(sshPodmanProxyPID, []byte(fmt.Sprintf("%d", sshProxyPID)), 0644); err != nil {
			fmt.Println("Error writing SSH proxy PID:", err)
		}
		fmt.Println("## SSH proxy started with PID:", sshProxyPID)

		// Goroutine to read stdout
		go func() {
			scanner := bufio.NewScanner(stdout)
			for scanner.Scan() {
				fmt.Println("## SSH stdout:", scanner.Text())
			}
		}()

		// Goroutine to read stderr
		go func() {
			scanner := bufio.NewScanner(stderr)
			for scanner.Scan() {
				fmt.Println("## SSH stderr:", scanner.Text())
			}
		}()

		prevSSHConfigSHA1 = currentSSHConfigSHA1
	} else {
		fmt.Println("## No changes in SSH configuration. Proxy not restarted.")
	}
}
func calculateSHA1(data string) string {
	h := sha1.New()
	h.Write([]byte(data))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func getLocalForward() string {
	logFunctionName()
	var localForward string
	cmd := exec.Command("podman", "ps", "--format", "{{.ID}}")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Error finding running containers:", err)
		return ""
	}

	containers := bytes.Split(output, []byte{'\n'})
	for _, container := range containers {
		if len(container) == 0 {
			continue
		}
		portMappings := getPortMappings(string(container))
		for _, mapping := range portMappings {
			fmt.Printf("## port mapping: HostIp=%s, HostPort=%s\n", mapping.HostIp, mapping.HostPort) // Log the port mapping
			localForward += fmt.Sprintf("LocalForward %s:%s %s:%s\n", mapping.HostIp, mapping.HostPort, mapping.HostIp, mapping.HostPort)
		}
	}
	return localForward
}
func getPortMappings(containerID string) []PortMapping {
	var portMappings []PortMapping
	cmd := exec.Command("podman", "inspect", containerID, "--format", "{{ range  $value := .HostConfig.PortBindings }}{{ json $value }} {{end}}")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Error inspecting container:", err)
		return portMappings
	}

	// Use regex to extract HostIp and HostPort
	re := regexp.MustCompile(`"HostIp":"([^"]*)","HostPort":"([^"]*)"`)
	matches := re.FindAllStringSubmatch(string(output), -1)

	for _, match := range matches {
		if len(match) == 3 {
			portMappings = append(portMappings, PortMapping{
				HostIp:   match[1],
				HostPort: match[2],
			})
		}
	}
	return portMappings
}

type PortMapping struct {
	HostIp   string
	HostPort string
}

func killProxySSHDaemon() {
	logFunctionName()
	if sshProxyPID > 0 {
		process, err := os.FindProcess(sshProxyPID)
		if err == nil {
			process.Kill()
			fmt.Println("## Killed SSH proxy daemon with PID:", sshProxyPID)
		}
	}
}

func monitorPodmanStartStopEvents() {
	logFunctionName()
	fmt.Println("## Monitoring Podman start/stop events")
	cmd := exec.Command("podman", "events", "-f", "event=start", "-f", "event=died", "--format={{ .TimeNano }}|{{ .ID }}|{{ .Status }}")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Println("Error setting up stdout pipe:", err)
		return
	}

	if err := cmd.Start(); err != nil {
		fmt.Println("Error starting podman events command:", err)
		return
	}
	defer cmd.Wait()

	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			if line != "" {
				fmt.Println("## Filtered event:", line)
				restartProxySSHDaemon()
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Println("Error reading from stdout:", err)
		}
	}()
}

func restartProxySSHDaemon() {
	logFunctionName()
	fmt.Println("## Restarting SSH proxy daemon...")
	killProxySSHDaemon()
	startProxySSHDaemon()
}
