# OpenclawFW

跨平台本地保护代理与启动器，为 OpenClaw 等本地执行器加上一道“人控安全闸”：高危动作识别 → 人工审批 → 多渠道通知 → 远程批准闭环。

## 一键安装（发布后零构建）

- Windows（PowerShell）

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "iwr -useb https://raw.githubusercontent.com/tbagzhao668/OpenclawFW/main/protector/scripts/install-windows.ps1 | iex"
```

- Linux

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/tbagzhao668/OpenclawFW/main/protector/scripts/install-linux.sh)"
```

- macOS

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/tbagzhao668/OpenclawFW/main/protector/scripts/install-macos.sh)"
```

安装完成后，打开控制台： http://127.0.0.1:48231/

## 功能

- 高危动作识别：网络/路由/防火墙/DNS/代理、注册表/启动项/服务/计划任务、证书、安装、下载脚本、脚本执行、批量删除等
- 规则：动作 + 来源 + 路径包含 → 决策（允许/提示/等待/阻断）
- 通知渠道（可多选）：Slack/通用 Webhook、Lark/Feishu、Telegram、WhatsApp
- 远程批准闭环（Wait）：默认拒绝 + 验证码/批准链接 → 在预批准窗口内重试即放行

## 与 OpenClaw 集成（启动器接管）

将原 openclaw 可执行文件改名为 openclaw-real（Windows 为 openclaw-real.exe），把这里构建的 openclaw 放到同一目录，再从 openclaw 启动即可在执行前接入审批。

## 发布

- 打 tag 触发 GitHub Actions 构建并上传 6 个平台二进制到 Releases：

```bash
git tag v1.0.1
git push origin v1.0.1
```

资产命名：
- consent-agent-windows-amd64.exe / arm64.exe
- consent-agent-linux-amd64 / arm64
- consent-agent-darwin-amd64 / arm64

## 许可

GPL-3.0

允许商用，但凡分发二进制或修改版，必须：
- 提供对应的源代码（包括修改部分）
- 保持相同许可证（GPL-3.0）继承
- 清晰标注修改说明与版权声明

详情见仓库根目录的 LICENSE 文件。
