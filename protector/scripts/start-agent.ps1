$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
$prefix = 'http://127.0.0.1:48231/'
$dataDir = Join-Path $env:ProgramData 'OpenClawProtector'
if (-not (Test-Path $dataDir)) { New-Item -ItemType Directory -Path $dataDir | Out-Null }
$rulesPath = Join-Path $dataDir 'rules.json'
$notifyPath = Join-Path $dataDir 'notify.json'
try {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} catch {}
function Get-DefaultRulesJson {
@'
{"rules":[
 {"id":"modify-network","match":{"action":"network_change"},"decision":"alert"},
 {"id":"bulk-delete","match":{"action":"delete"},"decision":"wait"},
 {"id":"run-remote-script","match":{"action":"run_script","source":"remote"},"decision":"alert"}
]}
'@
}
function Get-DefaultNotifyJson {
@'
{"webhook":"","feishuWebhook":"","tgToken":"","tgChatId":"","waToken":"","waPhoneId":"","waTo":""}
'@
}
function Get-Rules {
 if (Test-Path $rulesPath) {
  try { return (Get-Content $rulesPath -Raw | ConvertFrom-Json) } catch {}
 }
 $j = Get-DefaultRulesJson
 $j | Out-File -FilePath $rulesPath -Encoding utf8
 return ($j | ConvertFrom-Json)
}
function Save-Rules($body) {
 $body | Out-File -FilePath $rulesPath -Encoding utf8
}
function Get-Notify {
 if (Test-Path $notifyPath) {
  try { return (Get-Content $notifyPath -Raw | ConvertFrom-Json) } catch {}
 }
 $j = Get-DefaultNotifyJson
 $j | Out-File -FilePath $notifyPath -Encoding utf8
 return ($j | ConvertFrom-Json)
}
function Save-Notify($body) {
 $body | Out-File -FilePath $notifyPath -Encoding utf8
}
function Send-Notify($title, $message) {
 $cfg = Get-Notify
 $bodyText = "$title`n$message"
 $ok = $false
 $errs = @()
 $enabled = @()
 try {
  if ($cfg.PSObject.Properties.Name -contains 'enabled') {
   if ($cfg.enabled -is [System.Array]) { $enabled = @($cfg.enabled) } elseif ($cfg.enabled) { $enabled = @($cfg.enabled) }
  }
 } catch {}
 function Should-Send($key) {
  if ($enabled.Count -eq 0) { return $true } # default: all configured
  return ($enabled -contains $key)
 }
 try {
  if (Should-Send 'webhook' -and $cfg.webhook -and $cfg.webhook -ne "") {
   $payload = @{ text = $bodyText } | ConvertTo-Json -Depth 4
   Invoke-RestMethod -Method Post -Uri $cfg.webhook -Body $payload -ContentType 'application/json' | Out-Null
   $ok = $true
  }
 } catch { $errs += "webhook: $($_.Exception.Message)" }
 try {
  if (Should-Send 'feishu' -and $cfg.feishuWebhook -and $cfg.feishuWebhook -ne "") {
   $payload = @{ msg_type = 'text'; content = @{ text = $bodyText } } | ConvertTo-Json -Depth 6
   Invoke-RestMethod -Method Post -Uri $cfg.feishuWebhook -Body $payload -ContentType 'application/json' | Out-Null
   $ok = $true
  }
 } catch { $errs += "feishu: $($_.Exception.Message)" }
 try {
  if (Should-Send 'telegram' -and $cfg.tgToken -and $cfg.tgChatId) {
   $tgUrl = "https://api.telegram.org/bot$($cfg.tgToken)/sendMessage"
   $tgBody = @{ chat_id=$cfg.tgChatId; text=$bodyText }
   Invoke-RestMethod -Method Post -Uri $tgUrl -Body $tgBody -ContentType 'application/x-www-form-urlencoded' | Out-Null
   $ok = $true
  }
 } catch { $errs += "telegram: $($_.Exception.Message)" }
 try {
  if (Should-Send 'whatsapp' -and $cfg.waToken -and $cfg.waPhoneId -and $cfg.waTo) {
   $waUrl = "https://graph.facebook.com/v18.0/$($cfg.waPhoneId)/messages"
   $waPayload = @{
     messaging_product = 'whatsapp'
     to = $cfg.waTo
     type = 'text'
     text = @{ body = $bodyText }
   } | ConvertTo-Json -Depth 6
   Invoke-RestMethod -Method Post -Uri $waUrl -Body $waPayload -Headers @{ Authorization = "Bearer $($cfg.waToken)" } -ContentType 'application/json' | Out-Null
   $ok = $true
  }
 } catch { $errs += "whatsapp: $($_.Exception.Message)" }
 return @{ ok = $ok; errors = $errs }
}
$indexHtml = @'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>OpenClaw Protector</title>
  <style>
    body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 24px; }
    h1 { font-size: 20px; }
    button, select, input { padding: 6px 10px; margin-right: 6px; }
    .row { display: flex; gap: 8px; margin: 6px 0; flex-wrap: wrap; }
    .card { border: 1px solid #e5e5e5; border-radius: 8px; padding: 12px; margin: 8px 0; }
    .table { width: 100%; border-collapse: collapse; margin-top: 8px; }
    .table th, .table td { border-bottom: 1px solid #eee; padding: 8px; text-align: left; }
    .muted { color: #666; font-size: 12px; }
    .toolbar { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
    .tag { background: #f1f5f9; color: #0f172a; padding: 2px 6px; border-radius: 4px; font-size: 12px; }
  </style>
</head>
<body data-lang="zh">
  <div class="toolbar">
    <h1 id="title" style="margin:0; margin-right:12px;">OpenClaw High-Risk Action Guard</h1>
    <label>
      <span id="langLabel">Language</span>
      <select id="lang" onchange="setLang(this.value)">
        <option value="zh">Simplified Chinese</option>
        <option value="en">English</option>
      </select>
    </label>
  </div>

  <div class="card">
    <div class="toolbar">
      <span class="tag" id="presetLabel">Presets</span>
      <button onclick="preset('mild')" id="presetMild">Mild</button>
      <button onclick="preset('standard')" id="presetStandard">Standard</button>
      <button onclick="preset('strict')" id="presetStrict">Strict</button>
      <button onclick="save()" id="saveBtn">Save Rules</button>
      <span id="status" class="muted"></span>
    </div>
  </div>

  <div class="card">
    <div class="toolbar" style="justify-content: space-between;">
      <div><span class="tag" id="rulesLabel">Rules</span></div>
      <div>
        <button onclick="addRule()" id="addRuleBtn">Add Rule</button>
        <label style="margin-left:8px;">
          <span id="osLabel">OS</span>
          <select id="osSelect" onchange="render()">
            <option value="win">Windows</option>
            <option value="linux">Linux</option>
            <option value="mac">macOS</option>
          </select>
        </label>
      </div>
    </div>
    <table class="table" id="rulesTable">
      <thead>
        <tr>
          <th>ID</th>
          <th id="actionTh">Action</th>
          <th id="sourceTh">Source</th>
          <th id="pathTh">Path Contains</th>
          <th id="decisionTh">Decision</th>
          <th id="examplesTh">Examples</th>
          <th id="opsTh">Operations</th>
        </tr>
      </thead>
      <tbody id="rulesTbody"></tbody>
    </table>
    <div class="muted" id="hint">Changes apply immediately. Save persists to disk.</div>
  </div>

  <div class="card">
    <div class="toolbar"><span class="tag" id="notifyTitleTag">Notifications</span></div>
    <div class="row">
      <label><input type="checkbox" id="chkWebhook" onchange="toggleChannel('webhook', this.checked)"> Webhook</label>
      <label><input type="checkbox" id="chkFeishu" onchange="toggleChannel('feishu', this.checked)"> Lark/Feishu</label>
      <label><input type="checkbox" id="chkTg" onchange="toggleChannel('telegram', this.checked)"> Telegram</label>
      <label><input type="checkbox" id="chkWa" onchange="toggleChannel('whatsapp', this.checked)"> WhatsApp</label>
    </div>
    <div class="row" id="rowWebhook">
      <label style="min-width:360px;">
        <span id="lblWebhook">Webhook (Slack/Generic)</span>
        <input id="webhook" placeholder="https://hooks.slack.com/services/..." style="min-width:340px;" />
      </label>
    </div>
    <div class="row" id="rowFeishu">
      <label style="min-width:360px;">
        <span id="lblFeishu">Lark/Feishu Webhook</span>
        <input id="feishuWebhook" placeholder="https://open.feishu.cn/open-apis/bot/v2/hook/..." style="min-width:340px;" />
      </label>
    </div>
    <div class="row" id="rowTg">
      <label>
        <span id="lblTgToken">Telegram Bot Token</span>
        <input id="tgToken" placeholder="123456:ABC-DEF..." style="min-width:260px;" />
      </label>
      <label>
        <span id="lblTgChatId">Telegram Chat ID</span>
        <input id="tgChatId" placeholder="123456789" style="min-width:180px;" />
      </label>
    </div>
    <div class="row" id="rowWa">
      <label>
        <span id="lblWaToken">WhatsApp Token</span>
        <input id="waToken" placeholder="EAAG..." style="min-width:260px;" />
      </label>
      <label>
        <span id="lblWaPhoneId">WhatsApp Phone ID</span>
        <input id="waPhoneId" placeholder="1234567890" style="min-width:180px;" />
      </label>
      <label>
        <span id="lblWaTo">WhatsApp To</span>
        <input id="waTo" placeholder="+11234567890" style="min-width:180px;" />
      </label>
    </div>
    <div class="toolbar">
      <button id="notifySaveBtn" onclick="saveNotify()">Save</button>
      <button id="notifyTestBtn" onclick="testNotify()">Send Test</button>
    </div>
    <div class="muted" id="notifyHint">After configuring, alert/wait approvals also send summary notifications to the configured channels (includes action, target, source).</div>
  </div>

  <div class="card">
    <div class="toolbar"><span class="tag" id="ocQuickLabel">OpenClaw Quick Setup</span></div>
    <div class="row">
      <label>
        <span id="ocGatewayLabel">Gateway control</span>
        <select id="ocGatewayDecision" onchange="quickSetGateway(this.value)">
          <option value="allow">Allow</option>
          <option value="alert" selected>Alert</option>
          <option value="wait">Wait</option>
          <option value="block">Block</option>
        </select>
      </label>
      <label style="min-width:280px;">
        <span id="ocConfigLabel">Config path contains</span>
        <input id="ocConfigPath" placeholder="%OPENCLAW_CONFIG_PATH%" style="min-width:260px;" />
      </label>
      <label>
        <span id="ocConfigDecisionLabel">Decision</span>
        <select id="ocConfigDecision">
          <option value="allow">Allow</option>
          <option value="alert">Alert</option>
          <option value="wait" selected>Wait</option>
          <option value="block">Block</option>
        </select>
      </label>
      <button onclick="quickApplyConfig()" id="ocApplyConfigBtn">Apply</button>
    </div>
    <div class="row">
      <label style="min-width:280px;">
        <span id="ocStateLabel">State dir contains</span>
        <input id="ocStatePath" placeholder="%OPENCLAW_STATE_DIR%" style="min-width:260px;" />
      </label>
      <label>
        <span id="ocStateDecisionLabel">Decision</span>
        <select id="ocStateDecision">
          <option value="allow">Allow</option>
          <option value="alert">Alert</option>
          <option value="wait" selected>Wait</option>
          <option value="block">Block</option>
        </select>
      </label>
      <button onclick="quickApplyState()" id="ocApplyStateBtn">Apply</button>
    </div>
    <div class="row">
      <label>
        <span id="ocDMLabel">DM approvals auto-accept</span>
        <select id="ocDMDecision" onchange="quickSetDM(this.value)">
          <option value="allow">Allow</option>
          <option value="alert">Alert</option>
          <option value="wait" selected>Wait</option>
          <option value="block">Block</option>
        </select>
      </label>
      <label>
        <span id="ocChannelLabel">Channel actions</span>
        <select id="ocChannelDecision" onchange="quickSetChannel(this.value)">
          <option value="allow">Allow</option>
          <option value="alert" selected>Alert</option>
          <option value="wait">Wait</option>
          <option value="block">Block</option>
        </select>
      </label>
    </div>
    <div class="muted" id="ocHint">
      Tip: Use environment variables OPENCLAW_HOME / OPENCLAW_STATE_DIR / OPENCLAW_CONFIG_PATH to locate OpenClaw files. Set matching substrings above for quick protection.
    </div>
  </div>
  <script>
  const i18n = {
    zh: {
      title: 'OpenClaw \u9ad8\u5371\u64cd\u4f5c\u4fdd\u62a4\u5c42',
      lang: '\u8bed\u8a00',
      preset: '\u9884\u8bbe',
      mild: '\u6e29\u548c',
      standard: '\u6807\u51c6',
      strict: '\u4e25\u683c',
      save: '\u4fdd\u5b58\u89c4\u5219',
      rules: '\u89c4\u5219',
      addRule: '\u6dfb\u52a0\u89c4\u5219',
      action: '\u52a8\u4f5c',
      source: '\u6765\u6e90',
      pathContains: '\u8def\u5f84\u5305\u542b',
      decision: '\u51b3\u7b56',
      ops: '\u64cd\u4f5c',
      remove: '\u5220\u9664',
      hint: '\u6240\u6709\u6539\u52a8\u5373\u65f6\u751f\u6548\uff0c\u4fdd\u5b58\u4f1a\u6301\u4e45\u5316\u5230\u672c\u673a\u3002',
      saved: '\u5df2\u4fdd\u5b58',
      saveFailed: '\u4fdd\u5b58\u5931\u8d25',
      allow: '\u5141\u8bb8',
      alert: '\u63d0\u793a',
      wait: '\u7b49\u5f85',
      block: '\u963b\u65ad',
      os: 'OS',
      examples: '\u793a\u4f8b',
      notify: {
        title: '\u901a\u77e5\u901a\u9053',
        webhook: 'Webhook (Slack/\u901a\u7528)',
        feishu: 'Lark/Feishu Webhook',
        tgToken: 'Telegram Bot Token',
        tgChatId: 'Telegram Chat ID',
        waToken: 'WhatsApp Token',
        waPhoneId: 'WhatsApp Phone ID',
        waTo: 'WhatsApp \u63a5\u6536\u53f7\u7801',
        save: '\u4fdd\u5b58',
        test: '\u53d1\u9001\u6d4b\u8bd5',
        hint: '\u914d\u7f6e\u540e\uff0c\u7b49\u5f85/\u63d0\u793a\u7c7b\u5ba1\u6279\u4f1a\u540c\u6b65\u5411\u4ee5\u4e0a\u901a\u9053\u53d1\u9001\u6458\u8981\u901a\u77e5\uff08\u5185\u5bb9\u542b\u52a8\u4f5c\u3001\u76ee\u6807\u3001\u6765\u6e90\uff09\u3002'
      },
      ocQuick: 'OpenClaw \u5feb\u901f\u914d\u7f6e',
      ocGateway: 'Gateway \u63a7\u5236',
      ocConfig: '\u914d\u7f6e\u8def\u5f84\u5305\u542b',
      ocConfigDecision: '\u51b3\u7b56',
      ocState: '\u72b6\u6001\u6587\u4ef6\u8def\u5f84\u5305\u542b',
      ocStateDecision: '\u51b3\u7b56',
      ocApply: '\u5e94\u7528',
      ocDM: 'DM \u6279\u51c6\u81ea\u52a8',
      ocChannel: '\u6e20\u9053\u64cd\u4f5c',
      ocTip: '\u4f7f\u7528 OPENCLAW_HOME / OPENCLAW_STATE_DIR / OPENCLAW_CONFIG_PATH \u5b9a\u4f4d\u6587\u4ef6\uff0c\u8bbe\u5b9a\u4e0a\u65b9\u5339\u914d\u5b57\u4e32\u4ee5\u5feb\u901f\u62a4\u6807\u3002',
      actions: {
        run_script: '\u811a\u672c\u6267\u884c',
        delete: '\u6279\u91cf\u5220\u9664',
        network_change: '\u7f51\u7edc\u53d8\u66f4',
        screenshot: '\u622a\u5c4f',
        clipboard_read: '\u526a\u8d34\u677f\u8bfb\u53d6',
        gateway_control: 'Gateway \u63a7\u5236',
        config_change: '\u914d\u7f6e\u4fee\u6539',
        state_write: '\u72b6\u6001\u6587\u4ef6\u5199\u5165',
        channel_action: '\u6e20\u9053\u64cd\u4f5c',
        dm_approval: 'DM \u6279\u51c6'
      },
      sources: { '': '\u4e0d\u9650', local: '\u672c\u5730', remote: '\u8fdc\u7a0b' }
    },
    en: {
      title: 'OpenClaw High-Risk Action Guard',
      lang: 'Language',
      preset: 'Presets',
      mild: 'Mild',
      standard: 'Standard',
      strict: 'Strict',
      save: 'Save Rules',
      rules: 'Rules',
      addRule: 'Add Rule',
      action: 'Action',
      source: 'Source',
      pathContains: 'Path Contains',
      decision: 'Decision',
      ops: 'Operations',
      remove: 'Remove',
      hint: 'Changes apply immediately. Save persists to disk.',
      saved: 'Saved',
      saveFailed: 'Save failed',
      allow: 'Allow',
      alert: 'Alert',
      wait: 'Wait',
      block: 'Block',
      os: 'OS',
      examples: 'Examples',
      notify: {
        title: 'Notifications',
        webhook: 'Webhook (Slack/Generic)',
        feishu: 'Lark/Feishu Webhook',
        tgToken: 'Telegram Bot Token',
        tgChatId: 'Telegram Chat ID',
        waToken: 'WhatsApp Token',
        waPhoneId: 'WhatsApp Phone ID',
        waTo: 'WhatsApp To',
        save: 'Save',
        test: 'Send Test',
        hint: 'After configuring, alert/wait approvals also send summary notifications to the configured channels (includes action, target, source).'
      },
      ocQuick: 'OpenClaw Quick Setup',
      ocGateway: 'Gateway control',
      ocConfig: 'Config path contains',
      ocConfigDecision: 'Decision',
      ocState: 'State dir contains',
      ocStateDecision: 'Decision',
      ocApply: 'Apply',
      ocDM: 'DM approvals auto-accept',
      ocChannel: 'Channel actions',
      ocTip: 'Use OPENCLAW_HOME / OPENCLAW_STATE_DIR / OPENCLAW_CONFIG_PATH to locate files; set substrings above for quick protection.',
      actions: {
        run_script: 'Run Script',
        delete: 'Bulk Delete',
        network_change: 'Network Change',
        screenshot: 'Screenshot',
        clipboard_read: 'Clipboard Read',
        gateway_control: 'Gateway Control',
        config_change: 'Config Change',
        state_write: 'State Write',
        channel_action: 'Channel Action',
        dm_approval: 'DM Approval'
      },
      sources: { '': 'Any', local: 'Local', remote: 'Remote' }
    }
  };

  let rules = [];
  let lang = localStorage.getItem('ocp_lang') || 'zh';
  const examples = {
    firewall_change: {
      win: ['netsh advfirewall set allprofiles state off'],
      linux: ['ufw enable','firewall-cmd --reload','iptables -A ...','nft add rule ...'],
      mac: ['pfctl -E','pfctl -f /etc/pf.conf']
    },
    route_change: {
      win: ['route add 10.0.0.0 mask 255.0.0.0 10.0.0.1'],
      linux: ['ip route add 10.0.0.0/8 via 10.0.0.1','route add -net ...'],
      mac: ['route -n add 10.0.0.0/8 10.0.0.1']
    },
    dns_change: {
      win: ['ipconfig /flushdns','Set-DnsClientServerAddress ...'],
      linux: ['nmcli con mod ... ipv4.dns ...','edit /etc/resolv.conf'],
      mac: ['scutil --dns','networksetup -setdnsservers ...']
    },
    proxy_change: {
      win: ['netsh winhttp set proxy ...'],
      linux: ['export http_proxy=...','gsettings set ... proxy ...'],
      mac: ['scutil --proxy','networksetup -setwebproxy ...']
    },
    network_change: {
      win: ['netsh interface ip set address ...'],
      linux: ['ip addr add ...','ifconfig eth0 ...','nmcli device set ...'],
      mac: ['networksetup -setmanual ...']
    },
    registry_change: {
      win: ['reg add HKCU\\...\\Run','New-ItemProperty ...'],
      linux: [],
      mac: []
    },
    startup_change: {
      win: ['shell:startup','bcdedit /set ...'],
      linux: ['systemd unit in ~/.config/systemd/user','crontab @reboot'],
      mac: ['launchctl load ~/Library/LaunchAgents/...']
    },
    scheduled_task: {
      win: ['schtasks /create ...'],
      linux: ['crontab -e'],
      mac: ['launchctl start ...']
    },
    service_change: {
      win: ['sc create ...','sc delete ...','Dism /online /Enable-Feature ...'],
      linux: ['systemctl enable ...','service ... start'],
      mac: ['launchctl bootstrap gui/...']
    },
    certificate_change: {
      win: ['certutil -addstore ...','Import-Certificate ...'],
      linux: ['openssl pkcs12 -in ...','update-ca-trust'],
      mac: ['security add-trusted-cert ...']
    },
    package_install: {
      win: ['msiexec /i ...','winget install ...','choco install ...'],
      linux: ['apt install ...','yum install ...','dnf install ...','rpm -i ...'],
      mac: ['brew install ...','installer -pkg ... -target /']
    },
    download_script: {
      win: ['Invoke-WebRequest ...','iwr ...','curl ...','wget ...'],
      linux: ['curl ... | sh','wget ... -O script.sh'],
      mac: ['curl ... | sh']
    },
    run_script: {
      win: ['.ps1/.bat/.cmd'],
      linux: ['sh script.sh','bash -c ...'],
      mac: ['sh script.sh']
    },
    delete: {
      win: ['del /s ...','robocopy /mir ... (danger)'],
      linux: ['rm -rf ...','mv ...'],
      mac: ['rm -rf ...']
    },
    screenshot: { win: [], linux: [], mac: [] },
    clipboard_read: { win: [], linux: [], mac: [] },
    gateway_control: { win: [], linux: [], mac: [] },
    config_change: { win: [], linux: [], mac: [] },
    state_write: { win: [], linux: [], mac: [] },
    channel_action: { win: [], linux: [], mac: [] },
    dm_approval: { win: [], linux: [], mac: [] },
  };

  function setLang(l) {
    lang = l; localStorage.setItem('ocp_lang', l);
    document.body.setAttribute('data-lang', l);
    const t = i18n[l];
    document.getElementById('title').textContent = t.title;
    document.getElementById('langLabel').textContent = t.lang;
    document.getElementById('presetLabel').textContent = t.preset;
    document.getElementById('presetMild').textContent = t.mild;
    document.getElementById('presetStandard').textContent = t.standard;
    document.getElementById('presetStrict').textContent = t.strict;
    document.getElementById('saveBtn').textContent = t.save;
    document.getElementById('rulesLabel').textContent = t.rules;
    document.getElementById('addRuleBtn').textContent = t.addRule;
    document.getElementById('actionTh').textContent = t.action;
    document.getElementById('sourceTh').textContent = t.source;
    document.getElementById('pathTh').textContent = t.pathContains;
    document.getElementById('decisionTh').textContent = t.decision;
    document.getElementById('examplesTh').textContent = t.examples;
    document.getElementById('opsTh').textContent = t.ops;
    document.getElementById('hint').textContent = t.hint;
    // notifications card i18n
    var nv = t.notify || {};
    if (document.getElementById('notifyTitleTag')) document.getElementById('notifyTitleTag').textContent = nv.title || 'Notifications';
    if (document.getElementById('lblWebhook')) document.getElementById('lblWebhook').textContent = nv.webhook || 'Webhook (Slack/Generic)';
    if (document.getElementById('lblFeishu')) document.getElementById('lblFeishu').textContent = nv.feishu || 'Lark/Feishu Webhook';
    if (document.getElementById('lblTgToken')) document.getElementById('lblTgToken').textContent = nv.tgToken || 'Telegram Bot Token';
    if (document.getElementById('lblTgChatId')) document.getElementById('lblTgChatId').textContent = nv.tgChatId || 'Telegram Chat ID';
    if (document.getElementById('lblWaToken')) document.getElementById('lblWaToken').textContent = nv.waToken || 'WhatsApp Token';
    if (document.getElementById('lblWaPhoneId')) document.getElementById('lblWaPhoneId').textContent = nv.waPhoneId || 'WhatsApp Phone ID';
    if (document.getElementById('lblWaTo')) document.getElementById('lblWaTo').textContent = nv.waTo || 'WhatsApp To';
    if (document.getElementById('notifySaveBtn')) document.getElementById('notifySaveBtn').textContent = nv.save || 'Save';
    if (document.getElementById('notifyTestBtn')) document.getElementById('notifyTestBtn').textContent = nv.test || 'Send Test';
    if (document.getElementById('notifyHint')) document.getElementById('notifyHint').textContent = nv.hint || 'After configuring, alert/wait approvals also send summary notifications to the configured channels (includes action, target, source).';
    document.getElementById('ocQuickLabel').textContent = t.ocQuick;
    document.getElementById('ocGatewayLabel').textContent = t.ocGateway;
    document.getElementById('ocConfigLabel').textContent = t.ocConfig;
    document.getElementById('ocConfigDecisionLabel').textContent = t.ocConfigDecision;
    document.getElementById('ocStateLabel').textContent = t.ocState;
    document.getElementById('ocStateDecisionLabel').textContent = t.ocStateDecision;
    document.getElementById('ocApplyConfigBtn').textContent = t.ocApply;
    document.getElementById('ocApplyStateBtn').textContent = t.ocApply;
    document.getElementById('ocDMLabel').textContent = t.ocDM;
    document.getElementById('ocChannelLabel').textContent = t.ocChannel;
    document.getElementById('ocHint').textContent = t.ocTip;
    render();
  }

  function actionOptions(selected) {
    const t = i18n[lang].actions;
    const opts = ['', 'run_script', 'delete', 'network_change', 'screenshot', 'clipboard_read', 'gateway_control', 'config_change', 'state_write', 'channel_action', 'dm_approval'];
    return opts.map(k => {
      const label = t[k] || '';
      const sel = selected===k ? 'selected' : '';
      return `<option value="${k}" ${sel}>${label||'-'}</option>`;
    }).join('');
  }
  function preset(name){
    if(name==='mild'){
      rules = [{"id":"modify-network","match":{"action":"network_change"},"decision":"alert"}];
    } else if(name==='standard'){
      rules = [
        {"id":"modify-network","match":{"action":"network_change"},"decision":"alert"},
        {"id":"bulk-delete","match":{"action":"delete"},"decision":"wait"},
        {"id":"run-remote-script","match":{"action":"run_script","source":"remote"},"decision":"alert"}
      ];
    } else {
      rules = [
        {"id":"modify-network","match":{"action":"network_change"},"decision":"wait"},
        {"id":"bulk-delete","match":{"action":"delete"},"decision":"wait"},
        {"id":"run-remote-script","match":{"action":"run_script"},"decision":"wait"},
        {"id":"sensitive-clipboard","match":{"action":"clipboard_read"},"decision":"block"}
      ];
    }
    render();
  }
  function addRule(){
    rules.push({id:'rule-'+Date.now(), match:{action:''}, decision:'alert'});
    render();
  }
  function removeRule(idx){
    rules.splice(idx,1); render();
  }
  function updateField(idx, field, value){
    if(field==='id' || field==='decision'){
      rules[idx][field]=value;
    } else {
      rules[idx].match = rules[idx].match||{};
      rules[idx].match[field]=value;
    }
    if (field === 'action') {
      render();
    }
  }
  function render(){
    const t = i18n[lang];
    const tbody = document.getElementById('rulesTbody'); tbody.innerHTML = '';
    var osEl = document.getElementById('osSelect');
    var os = 'win';
    if (osEl && osEl.value !== undefined) { os = osEl.value; }
    rules.forEach((r, i) => {
      const tr = document.createElement('tr');
      const ex = examples[r.match?.action||'']?.[os] || [];
      tr.innerHTML = `
        <td><input value="${r.id||''}" oninput="updateField(${i}, 'id', this.value)" /></td>
        <td>
          <select onchange="updateField(${i}, 'action', this.value)">
            ${actionOptions(r.match?.action||'')}
          </select>
        </td>
        <td>
          <select onchange="updateField(${i}, 'source', this.value)">
            ${Object.entries(t.sources).map(([k,v])=>`<option value="${k}" ${((r.match?.source||'')===k)?'selected':''}>${v}</option>`).join('')}
          </select>
        </td>
        <td><input placeholder="${t.pathContains}" value="${r.match?.path_pattern||''}" oninput="updateField(${i}, 'path_pattern', this.value)" /></td>
        <td>
          <select onchange="updateField(${i}, 'decision', this.value)">
            <option value="allow" ${r.decision==='allow'?'selected':''}>${t.allow}</option>
            <option value="alert" ${r.decision==='alert'?'selected':''}>${t.alert}</option>
            <option value="wait" ${r.decision==='wait'?'selected':''}>${t.wait}</option>
            <option value="block" ${r.decision==='block'?'selected':''}>${t.block}</option>
          </select>
        </td>
        <td class="muted">${ex.length? ex.join('<br/>') : '-'}</td>
        <td><button onclick="removeRule(${i})">${t.remove}</button></td>
      `;
      tbody.appendChild(tr);
    });
  }
  async function load(){
    const res = await fetch('/api/rules');
    const j = await res.json();
    rules = j.rules || [];
    document.getElementById('lang').value = lang;
    setLang(lang);
    // notification config
    try {
      const r = await fetch('/api/notify-config'); const c = await r.json();
      (document.getElementById('webhook')||{}).value = c.webhook||'';
      (document.getElementById('feishuWebhook')||{}).value = c.feishuWebhook||'';
      (document.getElementById('tgToken')||{}).value = c.tgToken||'';
      (document.getElementById('tgChatId')||{}).value = c.tgChatId||'';
      (document.getElementById('waToken')||{}).value = c.waToken||'';
      (document.getElementById('waPhoneId')||{}).value = c.waPhoneId||'';
      (document.getElementById('waTo')||{}).value = c.waTo||'';
      const en = Array.isArray(c.enabled) ? c.enabled : null;
      // default: auto-enable channels that have non-empty field values
      document.getElementById('chkWebhook').checked = en ? en.includes('webhook') : !!c.webhook;
      document.getElementById('chkFeishu').checked = en ? en.includes('feishu') : !!c.feishuWebhook;
      document.getElementById('chkTg').checked = en ? en.includes('telegram') : (!!c.tgToken && !!c.tgChatId);
      document.getElementById('chkWa').checked = en ? en.includes('whatsapp') : (!!c.waToken && !!c.waPhoneId && !!c.waTo);
      renderNotifyVisibility();
    } catch {}
  }
  async function save(){
    const res = await fetch('/api/rules',{method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({rules})});
    document.getElementById('status').textContent = res.ok ? i18n[lang].saved : i18n[lang].saveFailed;
    if(res.ok) setTimeout(()=>document.getElementById('status').textContent='',1500);
  }
  async function saveNotify(){
    const payload = {
      webhook: (document.getElementById('webhook')||{}).value || '',
      feishuWebhook: (document.getElementById('feishuWebhook')||{}).value || '',
      tgToken: (document.getElementById('tgToken')||{}).value || '',
      tgChatId: (document.getElementById('tgChatId')||{}).value || '',
      waToken: (document.getElementById('waToken')||{}).value || '',
      waPhoneId: (document.getElementById('waPhoneId')||{}).value || '',
      waTo: (document.getElementById('waTo')||{}).value || '',
      enabled: [
        document.getElementById('chkWebhook').checked ? 'webhook' : null,
        document.getElementById('chkFeishu').checked ? 'feishu' : null,
        document.getElementById('chkTg').checked ? 'telegram' : null,
        document.getElementById('chkWa').checked ? 'whatsapp' : null
      ].filter(Boolean)
    };
    const res = await fetch('/api/notify-config', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
    document.getElementById('status').textContent = res.ok ? i18n[lang].saved : i18n[lang].saveFailed;
    if(res.ok) setTimeout(()=>document.getElementById('status').textContent='',1500);
  }
  async function testNotify(){
    const res = await fetch('/api/notify-test', {method:'POST'});
    let msg = 'Notify failed';
    if (res.ok) {
      const j = await res.json();
      msg = j.ok ? 'Notified' : ('Notify failed: ' + (j.errors && j.errors.join('; ') || 'unknown'));
    }
    document.getElementById('status').textContent = msg;
    if(res.ok) setTimeout(()=>document.getElementById('status').textContent='',1500);
  }
  function toggleChannel(key, on){
    var rows = { webhook:'rowWebhook', feishu:'rowFeishu', telegram:'rowTg', whatsapp:'rowWa' };
    var id = rows[key]; if (!id) return;
    var el = document.getElementById(id); if (el) { el.style.display = on ? '' : 'none'; }
  }
  function renderNotifyVisibility(){
    toggleChannel('webhook', document.getElementById('chkWebhook').checked);
    toggleChannel('feishu', document.getElementById('chkFeishu').checked);
    toggleChannel('telegram', document.getElementById('chkTg').checked);
    toggleChannel('whatsapp', document.getElementById('chkWa').checked);
  }
  // Quick setup helpers
  function upsertRuleById(id, base) {
    const idx = rules.findIndex(r => r.id===id);
    if (idx>=0) { rules[idx] = Object.assign(rules[idx], base); }
    else { rules.push(Object.assign({id, match:{}}, base)); }
  }
  function quickSetGateway(decision){
    upsertRuleById('oc-gateway', {decision, match:{action:'gateway_control'}});
    render();
  }
  function quickApplyConfig(){
    const path = (document.getElementById('ocConfigPath').value||'').trim();
    const decision = document.getElementById('ocConfigDecision').value;
    upsertRuleById('oc-config-change', {decision, match:{action:'config_change', path_pattern:path}});
    render();
  }
  function quickApplyState(){
    const path = (document.getElementById('ocStatePath').value||'').trim();
    const decision = document.getElementById('ocStateDecision').value;
    upsertRuleById('oc-state-write', {decision, match:{action:'state_write', path_pattern:path}});
    render();
  }
  function quickSetDM(decision){
    upsertRuleById('oc-dm-approval', {decision, match:{action:'dm_approval'}});
    render();
  }
  function quickSetChannel(decision){
    upsertRuleById('oc-channel-action', {decision, match:{action:'channel_action'}});
    render();
  }
  document.addEventListener('DOMContentLoaded', load);
  </script>
</body>
</html>
'@
function Write-Json($ctx, $obj) {
 $json = ($obj | ConvertTo-Json -Depth 8 -Compress)
 $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
 $ctx.Response.ContentType = 'application/json; charset=utf-8'
 $ctx.Response.ContentLength64 = $bytes.Length
 $ctx.Response.OutputStream.Write($bytes,0,$bytes.Length)
 $ctx.Response.OutputStream.Close()
}
function Write-Text($ctx, $html) {
 $bytes = [System.Text.Encoding]::UTF8.GetBytes($html)
 $ctx.Response.ContentType = 'text/html; charset=utf-8'
 $ctx.Response.ContentLength64 = $bytes.Length
 $ctx.Response.OutputStream.Write($bytes,0,$bytes.Length)
 $ctx.Response.OutputStream.Close()
}
function Decide($req) {
 $rules = Get-Rules
 foreach ($r in $rules.rules) {
  $match = $true
  foreach ($k in $r.match.PSObject.Properties.Name) {
   $v = $r.match.$k
   if ($k -eq 'path_pattern') {
    if (-not ($req.context.target -like "*$v*")) { $match = $false; break }
   } elseif ($k -eq 'action') {
    if ($req.action -ne $v) { $match = $false; break }
   } else {
    if ($req.context.$k -ne $v) { $match = $false; break }
   }
  }
  if ($match) { return $r.decision }
 }
 return 'allow'
}
function Prompt-Consent($message) {
 $res = [System.Windows.Forms.MessageBox]::Show($message,'OpenClaw 保护确认','OKCancel','Warning')
 return ($res -eq [System.Windows.Forms.DialogResult]::OK)
}
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add($prefix)
$listener.Start()
Write-Host "protector agent listening on $prefix"
while ($true) {
 try {
  $ctx = $listener.GetContext()
  $path = $ctx.Request.Url.AbsolutePath
  if ($path -eq '/') { Write-Text $ctx $indexHtml; continue }
  if ($path -eq '/api/rules') {
   if ($ctx.Request.HttpMethod -eq 'GET') {
    $obj = Get-Rules
    Write-Json $ctx $obj
   } elseif ($ctx.Request.HttpMethod -eq 'POST') {
    $sr = New-Object System.IO.StreamReader($ctx.Request.InputStream, [System.Text.Encoding]::UTF8)
    $body = $sr.ReadToEnd()
    Save-Rules $body
    $ctx.Response.StatusCode = 204
    $ctx.Response.Close()
   } else {
    $ctx.Response.StatusCode = 405
    $ctx.Response.Close()
   }
   continue
  }
  if ($path -eq '/api/consent' -and $ctx.Request.HttpMethod -eq 'POST') {
   $sr = New-Object System.IO.StreamReader($ctx.Request.InputStream, [System.Text.Encoding]::UTF8)
   $body = $sr.ReadToEnd()
   $req = $body | ConvertFrom-Json
   $decision = Decide $req
   if ($decision -eq 'allow') { Write-Json $ctx @{allowed=$true; token=''; reason='policy allow'}; continue }
   if ($decision -eq 'block') { Write-Json $ctx @{allowed=$false; token=''; reason='policy block'}; continue }
   try {
     Send-Notify "高危操作审批" ("动作: " + $req.action + "`n目标: " + $req.context.target + "`n来源: " + $req.context.source)
   } catch {}
   $msg = "Action: $($req.action)`nTarget: $($req.context.target)`nSource: $($req.context.source)`nSummary: $($req.context.summary)`nAllow?"
   $ok = Prompt-Consent $msg
   if (-not $ok) { Write-Json $ctx @{allowed=$false; token=''; reason='user rejected'}; continue }
   Write-Json $ctx @{allowed=$true; token=''; reason='user approved'}
   continue
  }
  if ($path -eq '/api/notify-config') {
   if ($ctx.Request.HttpMethod -eq 'GET') {
    $obj = Get-Notify
    Write-Json $ctx $obj
   } elseif ($ctx.Request.HttpMethod -eq 'POST') {
    $sr = New-Object System.IO.StreamReader($ctx.Request.InputStream, [System.Text.Encoding]::UTF8)
    $body = $sr.ReadToEnd()
    Save-Notify $body
    $ctx.Response.StatusCode = 204
    $ctx.Response.Close()
   } else {
    $ctx.Response.StatusCode = 405
    $ctx.Response.Close()
   }
   continue
  }
  if ($path -eq '/api/notify-test' -and $ctx.Request.HttpMethod -eq 'POST') {
   $result = $null
   try { $result = Send-Notify "通知测试" "这是一条来自 OpenClaw 保护层的测试消息" } catch { $result = @{ ok = $false; errors = @("runtime: $($_.Exception.Message)") } }
   Write-Json $ctx $result
   continue
  }
  $ctx.Response.StatusCode = 404
  $ctx.Response.Close()
 } catch {
  Start-Sleep -Milliseconds 50
 }
}
