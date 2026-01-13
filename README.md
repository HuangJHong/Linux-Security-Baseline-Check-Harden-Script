# 🛡️ Linux Security Baseline Check & Harden Script

这是一个轻量级、无依赖的 Shell 脚本，旨在为 Linux 服务器提供一键式的**安全基线检测**、**自动加固**以及**安全回滚**功能。

该脚本严格遵循企业级安全标准，涵盖账号安全、文件权限、SSH 配置、内核参数及关键服务等 **25 项** 核心检查点。

## ✨ 核心特性

* **⚡️ 一键检测/加固/回滚**：三种模式满足运维全生命周期需求。
* **🐧 多系统支持**：自动识别并适配 **CentOS 7/8/9**, **RHEL**, **Ubuntu 18/20/22/24**, **Debian 10/11/12**。
* **🎨 完美视觉体验**：使用 `column` 命令实现表格自适应对齐，并采用 Bash 原生颜色渲染，彻底解决中文乱码和对齐错位问题。
* **🤖 智能交互**：
* 加固模式下支持**手动输入**（如自定义 SSH 端口），而非暴力覆盖。
* 自动检测并安装缺失组件（如 `auditd` 服务、`column` 工具）。


* **📦 安全回滚机制**：加固前自动生成 Manifest 清单备份，支持精确还原文件，不污染 `/etc` 目录。
* **🚀 零依赖**：基于原生 Shell (`bash`, `awk`, `sed`, `grep`) 编写，无需 Python 或 Ansible 环境。

## 📋 包含的检查项 (25项)

| ID | 类别 | 检查项内容 | 关键配置/文件 |
| --- | --- | --- | --- |
| 1-4 | 账号安全 | 密码最大/最小有效期、过期警告天数 | `/etc/login.defs` |
| 3 | 密码策略 | 密码复杂度 (长度≥12 + 包含大小写数字特殊字符) | `pwquality.conf` |
| 5-6 | 账号审计 | 检查是否存在空密码账户、UID为0的非Root账户 | `/etc/shadow`, `/etc/passwd` |
| 7-11 | SSH安全 | 禁止Root远程、禁止空密码、**SSH端口(交互修改)**、认证次数、空闲超时 | `sshd_config` |
| 12-15 | 文件权限 | `/etc/passwd`(644), `/etc/shadow`(400), `/etc/group`(644), `/etc/gshadow`(400) | `chmod` |
| 16-18 | 环境配置 | 默认 UMASK (027)、登录超时 (TMOUT)、历史命令时间戳 | `/etc/profile` |
| 19-22 | 内核参数 | 禁止ICMP重定向、禁止源路由、开启SYN Cookie、忽略ICMP广播 | `sysctl.conf` |
| 23-24 | 关键服务 | 确保 Rsyslog 和 Auditd 服务已启用并运行 | `systemctl` |

## 🚀 快速开始

### 1. 下载与安装

将脚本内容保存为 `linux_check.sh`，并赋予执行权限。

```bash
# 赋予执行权限
chmod +x linux_check.sh

```

> **⚠️ 注意**：如果您是在 Windows 上编辑或复制的脚本，上传到 Linux 后可能会出现 `/bin/bash^M: bad interpreter` 错误。请务必执行以下命令修复换行符：
> ```bash
> sed -i 's/\r$//' linux_check.sh
> 
> ```
> 
> 

### 2. 使用说明

此脚本必须以 **Root** 权限运行。

#### 🔍 模式一：基线检测 (Check)

仅扫描系统状态，不修改任何文件。输出当前值与标准值的对比结果。

```bash
./linux_check.sh check

```

**输出示例：**

```text
ID   检查项                   标准值        当前值          结果
1    密码最大有效期            90           99999          FAIL
...
24   服务状态: auditd         active       active         PASS

```

#### 🛡️ 模式二：一键加固 (Harden)

自动备份配置文件，并修改系统设置以符合安全基线。

```bash
./linux_check.sh harden

```

* **自动备份**：脚本会在 `/root/security_backup_YYYYMMDD_HHMMSS/` 下创建备份。
* **交互确认**：遇到敏感配置（如 SSH 端口），脚本会询问是否修改及输入新端口。
* **自动修复**：自动安装缺失的 `auditd`，修正权限，追加配置，并重启 `sshd`。

#### ↩️ 模式三：回滚恢复 (Rollback)

如果加固后业务出现异常，可快速恢复到最近一次备份的状态。

```bash
./linux_check.sh rollback

```

* 脚本会读取最近一次的备份清单 (`manifest.txt`)，精准恢复被修改的配置文件。

## ⚙️ 配置自定义

您可以直接编辑脚本头部的变量来调整标准值：

```bash
# 打开脚本编辑
vim linux_check.sh

# 修改以下变量
STD_PASS_MAX_DAYS=90   # 密码最大有效期
SSH_PORT=22            # 默认SSH端口判断
PW_MIN_LEN=12          # 密码最小长度要求
PW_MIN_CLASS=4         # 密码字符种类要求 (大写/小写/数字/特殊)

```

## ❓ 常见问题 (FAQ)

**Q: 运行输出全是乱码？**
A: 请确保使用支持 ANSI 颜色的终端（如 Xshell, Putty, VSCode Terminal）。脚本 v3.2+ 版本已修复 `column` 命令导致的颜色代码失效问题。

**Q: 加固后 SSH 连不上了？**
A:

1. 请检查是否在加固过程中修改了 SSH 端口（脚本通过交互询问修改）。
2. 如果修改了端口，请确保防火墙（Firewalld/UFW/云安全组）已放行新端口。
3. 使用控制台（VNC）登录，运行 `./linux_check.sh rollback` 恢复。

**Q: 为什么 Auditd 加固失败？**
A: 脚本会自动尝试使用 `yum` 或 `apt` 安装 auditd。如果安装失败（例如无网络源），则无法启动服务。请配置好软件源后重试。

---

## ⚠️ 免责声明

* 本脚本仅供安全合规参考，建议在**测试环境**验证无误后再在生产环境执行。
* 加固操作涉及 SSH 和内核参数修改，具有一定的风险，请务必保留好脚本生成的备份目录。