package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Rule struct {
	ID        string            `json:"id"`
	Match     map[string]string `json:"match"`   // action, source, path_pattern (simple substring for PoC)
	Decision  string            `json:"decision"`// allow/alert/wait/block
	Remember  *Remember         `json:"remember,omitempty"`
	Threshold map[string]string `json:"when,omitempty"` // file_count, total_size_mb etc (not fully implemented in PoC)
}

type Remember struct {
	Scope string `json:"scope"` // script_path_prefix/app_path_prefix
	TTL   string `json:"ttl"`   // e.g., 10m
}

type Rules struct {
	Rules []Rule `json:"rules"`
}

type ConsentRequest struct {
	Action  string            `json:"action"`
	Context map[string]string `json:"context"` // e.g., target, source, count, size
}

type ConsentResponse struct {
	Allowed bool   `json:"allowed"`
	Token   string `json:"token,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

var (
	rulesMu     sync.RWMutex
	rulesStore  = Rules{Rules: []Rule{}}
	secretKey   []byte
	dataDir     string
)

type NotifyConfig struct {
	Webhook        string   `json:"webhook"`
	FeishuWebhook  string   `json:"feishuWebhook"`
	TgToken        string   `json:"tgToken"`
	TgChatId       string   `json:"tgChatId"`
	WaToken        string   `json:"waToken"`
	WaPhoneId      string   `json:"waPhoneId"`
	WaTo           string   `json:"waTo"`
	Enabled        []string `json:"enabled,omitempty"`
}

var (
	notifyMu    sync.RWMutex
	notifyStore = NotifyConfig{}
)

type pendingItem struct {
	Code    string
	Key     string
	Req     ConsentRequest
	Expires time.Time
}

var (
	pendingMu     sync.Mutex
	pendingByCode = map[string]*pendingItem{}
	preApproveMu  sync.Mutex
	preApproved   = map[string]time.Time{} // key -> expiry
)

func main() {
	dataDir = ensureDataDir()
	secretKey = loadOrCreateKey(filepath.Join(dataDir, "secret.key"))
	loadRules(filepath.Join(dataDir, "rules.json"))
	loadNotify(filepath.Join(dataDir, "notify.json"))

	mux := http.NewServeMux()
	mux.HandleFunc("/", serveIndex)
	mux.HandleFunc("/api/rules", handleRules)
	mux.HandleFunc("/api/consent", handleConsent)
	mux.HandleFunc("/api/notify-config", handleNotifyConfig)
	mux.HandleFunc("/api/notify-test", handleNotifyTest)
	mux.HandleFunc("/api/approve", handleApprove)
	mux.HandleFunc("/api/install/systemd", handleInstallSystemd)
	mux.HandleFunc("/api/install/launchd", handleInstallLaunchd)

	addr := "127.0.0.1:48231"
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen %s: %v", addr, err)
	}
	log.Printf("protector agent listening on http://%s", addr)
	log.Fatal(http.Serve(ln, logMiddleware(mux)))
}

func ensureDataDir() string {
	base := filepath.Join(os.Getenv("ProgramData"), "OpenClawProtector")
	if base == "" || base == "\\OpenClawProtector" {
		home, _ := os.UserConfigDir()
		base = filepath.Join(home, "OpenClawProtector")
	}
	_ = os.MkdirAll(base, 0o755)
	return base
}

func loadOrCreateKey(path string) []byte {
	if b, err := os.ReadFile(path); err == nil && len(b) >= 32 {
		return b
	}
	seed := time.Now().Format(time.RFC3339Nano) + "|" + randomString(32)
	key := sha256.Sum256([]byte(seed))
	if err := os.WriteFile(path, key[:], 0o600); err != nil {
		log.Printf("warn: write key: %v", err)
	}
	return key[:]
}

func loadRules(path string) {
	rulesMu.Lock()
	defer rulesMu.Unlock()
	b, err := os.ReadFile(path)
	if err != nil {
		// seed default rules
		rulesStore = Rules{Rules: []Rule{
			{ID: "modify-network", Match: map[string]string{"action": "network_change"}, Decision: "alert"},
			{ID: "bulk-delete", Match: map[string]string{"action": "delete"}, Decision: "wait"},
			{ID: "run-remote-script", Match: map[string]string{"action": "run_script", "source": "remote"}, Decision: "alert"},
		}}
		saveRules(path)
		return
	}
	_ = json.Unmarshal(b, &rulesStore)
}

func saveRules(path string) {
	b, _ := json.MarshalIndent(rulesStore, "", "  ")
	_ = os.WriteFile(path, b, 0o644)
}

func loadNotify(path string) {
	notifyMu.Lock()
	defer notifyMu.Unlock()
	b, err := os.ReadFile(path)
	if err != nil {
		notifyStore = NotifyConfig{}
		saveNotify(path)
		return
	}
	_ = json.Unmarshal(b, &notifyStore)
}

func saveNotify(path string) {
	notifyMu.RLock()
	defer notifyMu.RUnlock()
	b, _ := json.MarshalIndent(notifyStore, "", "  ")
	_ = os.WriteFile(path, b, 0o644)
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, indexHTML)
}

func handleRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rulesMu.RLock()
		defer rulesMu.RUnlock()
		enc := json.NewEncoder(w)
		_ = enc.Encode(rulesStore)
	case http.MethodPost:
		var in Rules
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		rulesMu.Lock()
		rulesStore = in
		rulesMu.Unlock()
		saveRules(filepath.Join(dataDir, "rules.json"))
		w.WriteHeader(204)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func handleConsent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req ConsentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	decision := decide(req)
	switch decision {
	case "allow":
		writeDecision(w, true, "", "policy allow")
	case "block":
		writeDecision(w, false, "", "policy block")
	case "alert", "wait":
		key := hashConsentKey(req)
		// fast path: pre-approved within TTL
		if isPreApproved(key) {
			token := issueToken(req)
			writeDecision(w, true, token, "pre-approved")
			return
		}
		// create pending code and notify
		code := newApprovalCode()
		storePending(code, key, req, 5*time.Minute)
		link := fmt.Sprintf("http://127.0.0.1:48231/api/approve?code=%s", code)
		go func() {
			msg := buildMessage(req) + "\n验证码: " + code + "\n或点击链接批准: " + link
			_ = sendNotify("高危操作审批(等待)", msg)
		}()
		msg := buildMessage(req)
		// For "wait", default deny and rely on remote approval; for "alert", show local prompt
		if decision == "wait" {
			writeDecision(w, false, "", "pending-approval")
			return
		}
		allowed := promptUserCrossPlatform(msg, true)
		if !allowed {
			writeDecision(w, false, "", "user rejected")
			return
		}
		token := issueToken(req)
		writeDecision(w, true, token, "user approved")
	default:
		writeDecision(w, false, "", "unknown decision")
	}
}

func handleNotifyConfig(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join(dataDir, "notify.json")
	switch r.Method {
	case http.MethodGet:
		notifyMu.RLock()
		defer notifyMu.RUnlock()
		_ = json.NewEncoder(w).Encode(notifyStore)
	case http.MethodPost:
		var in NotifyConfig
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		notifyMu.Lock()
		notifyStore = in
		notifyMu.Unlock()
		saveNotify(path)
		w.WriteHeader(204)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func handleNotifyTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	errs := sendNotify("通知测试", "这是一条来自 OpenClaw 保护层的测试消息")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":     len(errs) == 0,
		"errors": errs,
	})
}

func decide(req ConsentRequest) string {
	rulesMu.RLock()
	defer rulesMu.RUnlock()
	for _, rule := range rulesStore.Rules {
		match := true
		for k, v := range rule.Match {
			// simple match: exact equality for PoC; path_pattern could be substring on context.target
			if k == "path_pattern" {
				if !substring(req.Context["target"], v) {
					match = false
					break
				}
				continue
			}
			if (k == "action" && req.Action != v) || (k != "action" && req.Context[k] != v) {
				match = false
				break
			}
		}
		if match {
			return rule.Decision
		}
	}
	return "allow"
}

func substring(s, sub string) bool {
	if sub == "" { return true }
	return strings.Contains(s, sub)
}

func issueToken(req ConsentRequest) string {
	body, _ := json.Marshal(req)
	ts := time.Now().Add(2 * time.Minute).Unix()
	payload := fmt.Sprintf("%d.%s", ts, base64.StdEncoding.EncodeToString(body))
	m := hmac.New(sha256.New, secretKey)
	m.Write([]byte(payload))
	sig := base64.StdEncoding.EncodeToString(m.Sum(nil))
	return payload + "." + sig
}

func writeDecision(w http.ResponseWriter, allowed bool, token string, reason string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ConsentResponse{Allowed: allowed, Token: token, Reason: reason})
}

func randomString(n int) string {
	const table = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	now := time.Now().UnixNano()
	for i := 0; i < n; i++ {
		now = (now*1664525 + 1013904223) & 0xffffffff
		b[i] = table[int(now)%len(table)]
	}
	return string(b)
}

func buildMessage(req ConsentRequest) string {
	target := req.Context["target"]
	source := req.Context["source"]
	summary := req.Context["summary"]
	return fmt.Sprintf("动作: %s\n目标: %s\n来源: %s\n摘要: %s\n是否允许？", req.Action, target, source, summary)
}

func promptUserCrossPlatform(message string, modal bool) bool {
	switch detectPlatform() {
	case "windows":
		return messageBoxConfirmWindows(message)
	case "darwin":
		// osascript dialog; return 0 when OK
		cmd := exec.Command("osascript", "-e", fmt.Sprintf(`display dialog %q with title %q buttons {"Cancel","OK"} default button "OK"`, message, "OpenClaw 保护确认"))
		if err := cmd.Run(); err != nil {
			return false
		}
		return true
	default:
		// Linux: try zenity
		if _, err := exec.LookPath("zenity"); err == nil {
			cmd := exec.Command("zenity", "--question", "--title=OpenClaw 保护确认", "--text="+message)
			if err := cmd.Run(); err != nil {
				return false
			}
			return true
		}
		// Fallback: no GUI prompt available, deny by default for safety
		return false
	}
}

func detectPlatform() string {
	switch strings.ToLower(os.Getenv("GOOS")) {
	case "windows", "darwin", "linux":
		return strings.ToLower(os.Getenv("GOOS"))
	}
	// fallback using runtime
	if isWindows() {
		return "windows"
	}
	if isDarwin() {
		return "darwin"
	}
	return "linux"
}

func isWindows() bool {
	return filepath.Separator == '\\'
}
func isDarwin() bool {
	// a weak heuristic; prefer GOOS env when injected by build
	return strings.Contains(strings.ToLower(os.Getenv("OSTYPE")), "darwin")
}

func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

func sendNotify(title, message string) []string {
	notifyMu.RLock()
	cfg := notifyStore
	notifyMu.RUnlock()
	errs := []string{}
	enabled := map[string]bool{}
	if len(cfg.Enabled) == 0 {
		// default: all configured channels
		if cfg.Webhook != "" {
			enabled["webhook"] = true
		}
		if cfg.FeishuWebhook != "" {
			enabled["feishu"] = true
		}
		if cfg.TgToken != "" && cfg.TgChatId != "" {
			enabled["telegram"] = true
		}
		if cfg.WaToken != "" && cfg.WaPhoneId != "" && cfg.WaTo != "" {
			enabled["whatsapp"] = true
		}
	} else {
		for _, k := range cfg.Enabled {
			enabled[k] = true
		}
	}
	bodyText := title + "\n" + message
	client := &http.Client{Timeout: 10 * time.Second}
	if enabled["webhook"] && cfg.Webhook != "" {
		if err := postJSON(client, cfg.Webhook, map[string]string{"text": bodyText}); err != nil {
			errs = append(errs, "webhook: "+err.Error())
		}
	}
	if enabled["feishu"] && cfg.FeishuWebhook != "" {
		if err := postJSON(client, cfg.FeishuWebhook, map[string]any{
			"msg_type": "text",
			"content":  map[string]string{"text": bodyText},
		}); err != nil {
			errs = append(errs, "feishu: "+err.Error())
		}
	}
	if enabled["telegram"] && cfg.TgToken != "" && cfg.TgChatId != "" {
		url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", cfg.TgToken)
		form := "chat_id=" + cfg.TgChatId + "&text=" + urlEncode(bodyText)
		req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if _, err := client.Do(req); err != nil {
			errs = append(errs, "telegram: "+err.Error())
		}
	}
	if enabled["whatsapp"] && cfg.WaToken != "" && cfg.WaPhoneId != "" && cfg.WaTo != "" {
		url := fmt.Sprintf("https://graph.facebook.com/v18.0/%s/messages", cfg.WaPhoneId)
		reqBody := map[string]any{
			"messaging_product": "whatsapp",
			"to":                cfg.WaTo,
			"type":              "text",
			"text":              map[string]string{"body": bodyText},
		}
		b, _ := json.Marshal(reqBody)
		req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(string(b)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+cfg.WaToken)
		if _, err := client.Do(req); err != nil {
			errs = append(errs, "whatsapp: "+err.Error())
		}
	}
	return errs
}

func postJSON(client *http.Client, url string, body any) error {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

func urlEncode(s string) string {
	repl := strings.NewReplacer(
		" ", "+",
		"\n", "%0A",
		"\r", "",
	)
	return repl.Replace(s)
}

func hashConsentKey(req ConsentRequest) string {
	b, _ := json.Marshal(req)
	h := sha256.Sum256(b)
	return fmt.Sprintf("%x", h[:])
}

func newApprovalCode() string {
	now := time.Now().UnixNano()
	code := int(now % 1000000)
	return fmt.Sprintf("%06d", code)
}

func storePending(code, key string, req ConsentRequest, ttl time.Duration) {
	pendingMu.Lock()
	defer pendingMu.Unlock()
	pendingByCode[code] = &pendingItem{
		Code:    code,
		Key:     key,
		Req:     req,
		Expires: time.Now().Add(ttl),
	}
}

func isPreApproved(key string) bool {
	preApproveMu.Lock()
	defer preApproveMu.Unlock()
	exp, ok := preApproved[key]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(preApproved, key)
		return false
	}
	return true
}

func approveKey(key string, ttl time.Duration) {
	preApproveMu.Lock()
	defer preApproveMu.Unlock()
	preApproved[key] = time.Now().Add(ttl)
}

func handleApprove(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "code required", 400)
		return
	}
	pendingMu.Lock()
	item, ok := pendingByCode[code]
	if ok && time.Now().After(item.Expires) {
		ok = false
		delete(pendingByCode, code)
	}
	if ok {
		delete(pendingByCode, code)
	}
	pendingMu.Unlock()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if !ok {
		fmt.Fprint(w, "<h3>审批失败或已过期</h3>")
		return
	}
	approveKey(item.Key, 2*time.Minute)
	fmt.Fprint(w, "<h3>已批准</h3><p>请在 2 分钟内重试操作。</p>")
}

func handleInstallSystemd(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	const unit = `[Unit]
Description=OpenClaw Protector Agent
After=network-online.target

[Service]
ExecStart=/opt/openclaw-protector/consent-agent
Restart=on-failure
User=openclaw
WorkingDirectory=/opt/openclaw-protector

[Install]
WantedBy=multi-user.target
`
	fmt.Fprint(w, unit)
}

func handleInstallLaunchd(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>ai.openclaw.protector</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Users/yourname/openclaw-protector/consent-agent</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>WorkingDirectory</key><string>/Users/yourname/openclaw-protector</string>
  <key>StandardOutPath</key><string>/tmp/oc-protector.out</string>
  <key>StandardErrorPath</key><string>/tmp/oc-protector.err</string>
</dict>
</plist>`
	fmt.Fprint(w, plist)
}

const indexHTML = `<!doctype html>
<html lang="zh">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>OpenClaw 保护层</title>
  <style>
    body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 24px; }
    h1 { font-size: 20px; }
    .rule { border: 1px solid #ddd; padding: 12px; margin: 8px 0; border-radius: 6px; }
    .row { display: flex; gap: 8px; margin: 6px 0; flex-wrap: wrap; }
    input, select { padding: 6px; }
    button { padding: 6px 10px; }
    .card { border: 1px solid #ddd; padding: 12px; border-radius: 6px; margin: 12px 0; }
    .muted { color: #666; font-size: 12px; }
    .actions { margin-top: 12px; }
    .small { color: #666; font-size: 12px; }
  </style>
</head>
<body>
  <h1>OpenClaw 高危操作保护层</h1>
  <p>选择预设或编辑规则，所有改动即时生效。</p>
  <div class="actions">
    <button onclick="preset('mild')">温和</button>
    <button onclick="preset('standard')">标准</button>
    <button onclick="preset('strict')">严格</button>
    <button onclick="save()">保存规则</button>
    <span id="status" class="small"></span>
  <div class="card">
    <h3 style="margin:0 0 8px 0;">通知渠道</h3>
    <div class="row">
      <label><input type="checkbox" id="chkWebhook" onchange="renderNotify()"> Webhook</label>
      <label><input type="checkbox" id="chkFeishu" onchange="renderNotify()"> Lark/Feishu</label>
      <label><input type="checkbox" id="chkTg" onchange="renderNotify()"> Telegram</label>
      <label><input type="checkbox" id="chkWa" onchange="renderNotify()"> WhatsApp</label>
    </div>
    <div class="row" id="rowWebhook">
      <label style="min-width:360px;">Webhook <input id="webhook" style="min-width:340px;" placeholder="https://hooks.slack.com/services/..."/></label>
    </div>
    <div class="row" id="rowFeishu">
      <label style="min-width:360px;">Feishu Webhook <input id="feishuWebhook" style="min-width:340px;" placeholder="https://open.feishu.cn/open-apis/bot/v2/hook/..."/></label>
    </div>
    <div class="row" id="rowTg">
      <label>Bot Token <input id="tgToken" style="min-width:260px;" placeholder="123456:ABC-DEF..."/></label>
      <label>Chat ID <input id="tgChatId" style="min-width:180px;" placeholder="123456789"/></label>
    </div>
    <div class="row" id="rowWa">
      <label>WA Token <input id="waToken" style="min-width:260px;" placeholder="EAAG..."/></label>
      <label>Phone ID <input id="waPhoneId" style="min-width:180px;" placeholder="1234567890"/></label>
      <label>To <input id="waTo" style="min-width:180px;" placeholder="+11234567890"/></label>
    </div>
    <div class="row">
      <button onclick="saveNotify()">保存</button>
      <button onclick="testNotify()">发送测试</button>
      <span id="notifyStatus" class="muted"></span>
    </div>
    <div class="muted">配置后，“提示/等待”审批会向勾选的渠道发送摘要通知（动作/目标/来源）。</div>
  </div>
  </div>
  <div id="rules"></div>
  <script>
  function renderNotify(){
    const on = (id) => document.getElementById(id).checked;
    document.getElementById('rowWebhook').style.display = on('chkWebhook') ? '' : 'none';
    document.getElementById('rowFeishu').style.display = on('chkFeishu') ? '' : 'none';
    document.getElementById('rowTg').style.display = on('chkTg') ? '' : 'none';
    document.getElementById('rowWa').style.display = on('chkWa') ? '' : 'none';
  }
  async function saveNotify(){
    const payload = {
      webhook: document.getElementById('webhook').value || '',
      feishuWebhook: document.getElementById('feishuWebhook').value || '',
      tgToken: document.getElementById('tgToken').value || '',
      tgChatId: document.getElementById('tgChatId').value || '',
      waToken: document.getElementById('waToken').value || '',
      waPhoneId: document.getElementById('waPhoneId').value || '',
      waTo: document.getElementById('waTo').value || '',
      enabled: [
        document.getElementById('chkWebhook').checked ? 'webhook' : null,
        document.getElementById('chkFeishu').checked ? 'feishu' : null,
        document.getElementById('chkTg').checked ? 'telegram' : null,
        document.getElementById('chkWa').checked ? 'whatsapp' : null
      ].filter(Boolean)
    };
    const res = await fetch('/api/notify-config',{method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
    document.getElementById('notifyStatus').textContent = res.ok ? '已保存' : '保存失败';
    if(res.ok) setTimeout(()=>document.getElementById('notifyStatus').textContent='',1500);
  }
  async function loadNotify(){
    try {
      const r = await fetch('/api/notify-config'); const c = await r.json();
      document.getElementById('webhook').value = c.webhook || '';
      document.getElementById('feishuWebhook').value = c.feishuWebhook || '';
      document.getElementById('tgToken').value = c.tgToken || '';
      document.getElementById('tgChatId').value = c.tgChatId || '';
      document.getElementById('waToken').value = c.waToken || '';
      document.getElementById('waPhoneId').value = c.waPhoneId || '';
      document.getElementById('waTo').value = c.waTo || '';
      const en = Array.isArray(c.enabled) ? c.enabled : [];
      document.getElementById('chkWebhook').checked = en.length ? en.includes('webhook') : !!c.webhook;
      document.getElementById('chkFeishu').checked = en.length ? en.includes('feishu') : !!c.feishuWebhook;
      document.getElementById('chkTg').checked = en.length ? en.includes('telegram') : (!!c.tgToken && !!c.tgChatId);
      document.getElementById('chkWa').checked = en.length ? en.includes('whatsapp') : (!!c.waToken && !!c.waPhoneId && !!c.waTo);
      renderNotify();
    } catch (e) {}
  }
  async function testNotify(){
    const res = await fetch('/api/notify-test', {method:'POST'});
    let msg = '发送失败';
    if (res.ok) {
      const j = await res.json();
      msg = j.ok ? '已发送' : ('发送失败: ' + ((j.errors||[]).join('; ') || 'unknown'));
    }
    document.getElementById('notifyStatus').textContent = msg;
    if(res.ok) setTimeout(()=>document.getElementById('notifyStatus').textContent='',1500);
  }
  </script>
  <script>
  let rules = [];
  async function fetchRules() {
    await loadNotify();
    const res = await fetch('/api/rules'); rules = (await res.json()).rules || [];
    render();
  }
  function render() {
    const root = document.getElementById('rules'); root.innerHTML = '';
    rules.forEach((r, idx) => {
      const div = document.createElement('div'); div.className = 'rule';
      var html = '';
      html += '<div class=\"row\">';
      html += '  <label>ID <input value=\"' + (r.id||'') + '\" onchange=\"update(' + idx + ', \\'id\\', this.value)\"/></label>';
      html += '  <label>动作 <select onchange=\"updateMatch(' + idx + ', \\'action\\', this.value)\">';
      html += '    <option value=\"\">未选</option>';
      html += '    <option ' + sel(r.match?.action,'run_script') + '>脚本执行</option>';
      html += '    <option ' + sel(r.match?.action,'delete') + '>批量删除</option>';
      html += '    <option ' + sel(r.match?.action,'network_change') + '>网络变更</option>';
      html += '    <option ' + sel(r.match?.action,'screenshot') + '>截屏</option>';
      html += '    <option ' + sel(r.match?.action,'clipboard_read') + '>剪贴板读取</option>';
      html += '  </select></label>';
      html += '  <label>决策 <select onchange=\"update(' + idx + ', \\'decision\\', this.value)\">';
      html += '    <option ' + sel(r.decision,'allow') + '>允许</option>';
      html += '    <option ' + sel(r.decision,'alert') + '>提示</option>';
      html += '    <option ' + sel(r.decision,'wait') + '>等待</option>';
      html += '    <option ' + sel(r.decision,'block') + '>阻断</option>';
      html += '  </select></label>';
      html += '</div>';
      html += '<div class=\"row\">';
      html += '  <label>来源 <input value=\"' + (r.match?.source||'') + '\" placeholder=\"local/remote\" onchange=\"updateMatch(' + idx + ', \\'source\\', this.value)\"/></label>';
      html += '  <label>路径包含 <input value=\"' + (r.match?.path_pattern||'') + '\" placeholder=\"子串匹配\" onchange=\"updateMatch(' + idx + ', \\'path_pattern\\', this.value)\"/></label>';
      html += '</div>';
      html += '<div class=\"row small\">规则简化演示：match 字段采用等值或子串匹配。</div>';
      html += '<div class=\"row\"><button onclick=\"removeRule(' + idx + ')\">删除规则</button></div>';
      div.innerHTML = html;
      root.appendChild(div);
    });
    const add = document.createElement('div'); add.className='actions';
    add.innerHTML = '<button onclick=\"addRule()\">添加规则</button>';
    root.appendChild(add);
  }
  function sel(a,b){return a===b?'selected':''}
  function update(i, k, v){ rules[i][k]=v; }
  function updateMatch(i, k, v){ rules[i].match = rules[i].match||{}; rules[i].match[k]=v; }
  function addRule(){ rules.push({id:'rule-'+Date.now(), match:{}, decision:'alert'}); render(); }
  function removeRule(i){ rules.splice(i,1); render(); }
  async function save(){
    const res = await fetch('/api/rules', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({rules})});
    document.getElementById('status').textContent = res.ok ? '已保存' : '保存失败';
    if(res.ok) setTimeout(()=>document.getElementById('status').textContent='',1500);
  }
  function preset(name){
    if(name==='mild'){
      rules = [
        {id:'modify-network', match:{action:'network_change'}, decision:'alert'},
      ];
    } else if(name==='standard'){
      rules = [
        {id:'modify-network', match:{action:'network_change'}, decision:'alert'},
        {id:'bulk-delete', match:{action:'delete'}, decision:'wait'},
        {id:'run-remote-script', match:{action:'run_script', source:'remote'}, decision:'alert'},
      ];
    } else {
      rules = [
        {id:'modify-network', match:{action:'network_change'}, decision:'wait'},
        {id:'bulk-delete', match:{action:'delete'}, decision:'wait'},
        {id:'run-remote-script', match:{action:'run_script'}, decision:'wait'},
        {id:'sensitive-clipboard', match:{action:'clipboard_read'}, decision:'block'}
      ];
    }
    render();
  }
  fetchRules();
  </script>
</body>
</html>`
