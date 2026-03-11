package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type ConsentRequest struct {
	Action  string            `json:"action"`
	Context map[string]string `json:"context"`
}
type ConsentResponse struct {
	Allowed bool   `json:"allowed"`
	Token   string `json:"token"`
	Reason  string `json:"reason"`
}

func main() {
	args := os.Args[1:]
	real := findRealExecutable()
	action, ctx := inferAction(args)

	allowed, token := true, ""
	if highRisk(action, ctx) {
		allowed, token = askConsent(action, ctx)
	}
	if !allowed {
		fmt.Fprintln(os.Stderr, "被阻断：", ctx["summary"])
		os.Exit(130)
	}
	if token != "" {
		os.Setenv("OC_PROTECT_TOKEN", token)
	}
	cmd := exec.Command(real, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		fmt.Fprintln(os.Stderr, "执行失败：", err)
		os.Exit(1)
	}
	os.Exit(cmd.ProcessState.ExitCode())
}

func findRealExecutable() string {
	self, _ := os.Executable()
	dir := filepath.Dir(self)
	candidates := []string{
		filepath.Join(dir, "openclaw-real.exe"),
		filepath.Join(dir, "openclaw-real"),
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	// fallback: echo-like command to prove flow works
	return os.Getenv("ComSpec")
}

func inferAction(args []string) (string, map[string]string) {
	joined := strings.ToLower(strings.Join(args, " "))
	ctx := map[string]string{
		"target": joined,
		"source": "openclaw",
		"summary": fmt.Sprintf("将执行：%s", safeTrunc(joined, 120)),
	}
	has := func(tokens ...string) bool {
		for _, t := range tokens {
			if strings.Contains(joined, t) {
				return true
			}
		}
		return false
	}
	if has("netsh advfirewall", "ufw ", "firewall-cmd", "pfctl") {
		return "firewall_change", ctx
	}
	if has(" route ", "ip route", "route add", "route delete") {
		return "route_change", ctx
	}
	if has("ipconfig /flushdns", "nmcli", "resolv.conf", "scutil --dns", "set-dnsclientserveraddress") {
		return "dns_change", ctx
	}
	if has("netsh winhttp", " proxy ", "scutil --proxy") {
		return "proxy_change", ctx
	}
	if has("netsh", " ip ", "ifconfig", "networksetup") {
		return "network_change", ctx
	}
	if has("reg add", "reg delete", "reg.exe", "set-itemproperty", "new-itemproperty", "hkey_current_user\\software\\microsoft\\windows\\currentversion\\run") {
		return "registry_change", ctx
	}
	if has("runonce", " shell:startup", " startup", "bcdedit") {
		return "startup_change", ctx
	}
	if has("schtasks", " at ", "crontab") {
		return "scheduled_task", ctx
	}
	if has("sc create", "sc delete", "sc.exe", "systemctl", "launchctl", " service ", "dism /online /enable-feature") {
		return "service_change", ctx
	}
	if has("certutil", "import-certificate", "openssl", "pkcs12", "pkcs7") {
		return "certificate_change", ctx
	}
	if has("msiexec", "dism /online /add-package", "winget ", "choco ", "apt ", "yum ", "dnf ", "rpm ", "brew install") {
		return "package_install", ctx
	}
	if has("invoke-webrequest", " iwr ", "curl ", "wget ") {
		return "download_script", ctx
	}
	if has(".ps1", ".bat", ".cmd", ".sh") || has("http://", "https://") {
		return "run_script", ctx
	}
	if has(" del ", " erase ", " rd ", " rmdir ", " rm -", " mv ", " move ", "robocopy /mir") {
		return "delete", ctx
	}
	return "other", ctx
}

func highRisk(action string, ctx map[string]string) bool {
	switch action {
	case "other":
		return false
	default:
		return true
	}
}

func askConsent(action string, ctx map[string]string) (bool, string) {
	req := ConsentRequest{Action: action, Context: ctx}
	b, _ := json.Marshal(req)
	httpClient := &http.Client{Timeout: 30 * time.Second}
	url := "http://127.0.0.1:48231/api/consent"
	resp, err := httpClient.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		// if agent not running, fail-closed by default
		fmt.Fprintln(os.Stderr, "同意代理不可用，默认阻断：", err)
		return false, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var ans ConsentResponse
	if err := json.Unmarshal(body, &ans); err != nil {
		return false, ""
	}
	return ans.Allowed, ans.Token
}

func safeTrunc(s string, n int) string {
	if len(s) <= n { return s }
	return s[:n] + "…"
}
