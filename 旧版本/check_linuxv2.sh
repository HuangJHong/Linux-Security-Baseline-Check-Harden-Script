#!/bin/bash
# ===========================================================================
# Linux 安全基线检查与加固脚本 (Support: CentOS/RHEL, Ubuntu/Debian)
# 功能：检测 (check) | 加固 (harden) | 回滚 (rollback)
# 注意：生产环境请谨慎操作，务必保持额外的 Root 会话窗口以防 SSH 中断 
# ===========================================================================

# --- 全局配置 ---
BACKUP_DIR="/root/security_backup_$(date +%Y%m%d_%H%M%S)"
RAW_OUTPUT="/tmp/sec_check_raw.txt" # 临时文件

# --- 辅助函数 ---
check_root() {
    if [ "$EUID" -ne 0 ]; then echo "错误: 请使用 Root 权限运行。"; exit 1; fi
}

log() { echo -e "$1"; }

# --- 核心审计逻辑 (只负责生成纯数据，不处理颜色) ---
# 输出格式: 标题^推荐值^当前值^状态(PASS/FAIL/SKIP)
audit_item() {
    local title="$1"
    local recommend="$2"
    local cmd="$3"
    local mode="$4"
    
    local current=$(eval "$cmd" 2>/dev/null)
    if [ -z "$current" ]; then current="未设置/默认"; fi
    
    # 截断过长字符，防止表格错位
    if [ ${#current} -gt 25 ]; then current="${current:0:22}..."; fi
    # 清理换行符
    current=$(echo "$current" | tr -d '\n' | tr -s ' ')

    local status="FAIL"
    
    case "$mode" in
        eq) [[ "$current" == "$recommend" ]] && status="PASS" ;;
        le) # 数值小于等于
            [[ "$current" != "未设置/默认" ]] && [ "$current" -le "$recommend" ] && status="PASS" ;;
        contain) [[ "$current" == *"$recommend"* ]] && status="PASS" ;;
        service_off)
            if [[ "$current" == *"not-found"* ]] || [[ "$current" == *"inactive"* ]] || [[ "$current" == *"dead"* ]]; then 
                status="PASS"; current="已关闭/未安装"
            else
                status="FAIL"; current="运行中"
            fi ;;
        service_on)
            if [[ "$current" == *"active"* ]]; then status="PASS"; else status="FAIL"; fi ;;
    esac

    echo "${title}^${recommend}^${current}^${status}" >> "$RAW_OUTPUT"
    
    if [[ "$status" == "PASS" ]]; then return 0; else return 1; fi
}

# --- 1. 账号与认证 ---
audit_account() {
    echo "@HEAD@^=== [1] 账号与认证安全 ===^^" >> "$RAW_OUTPUT"
    
    audit_item "禁止 Root 远程登录" "no" \
        "grep '^PermitRootLogin' /etc/ssh/sshd_config | tail -1 | awk '{print \$2}'" "eq"
    audit_item "密码复杂度策略(PAM)" \
    "password requisite pam_pwquality.so retry=3 minlen=12 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1" \
    "grep -h 'pam_pwquality.so' /etc/pam.d/system-auth /etc/pam.d/common-password 2>/dev/null | tail -1" \
    "eq"
    audit_item "禁止空密码账户" "无" \
        "awk -F: '(\$2 == \"\") {print \$1}' /etc/shadow" "eq"
    audit_item "密码最大有效期(天)" "90" \
        "grep '^PASS_MAX_DAYS' /etc/login.defs | awk '{print \$2}'" "le"
    audit_item "登录失败锁定(防爆破)" "存在配置" \
        "grep -E 'pam_tally2|pam_faillock' /etc/pam.d/password-auth /etc/pam.d/common-auth 2>/dev/null | head -1" "contain"
    audit_item "检查UID=0非Root账号" "root" \
        "awk -F: '(\$3 == 0) {print \$1}' /etc/passwd | tr '\n' ','" "eq"
    audit_item "清理无用系统账户" "已清理" \
        "egrep '^(lp|sync|shutdown|halt|games)' /etc/shadow >/dev/null && echo '存在' || echo '已清理'" "eq"
}

# --- 2. 文件系统权限 ---
audit_file() {
    echo "@HEAD@^=== [2] 文件权限安全 ===^^" >> "$RAW_OUTPUT"
    audit_item "默认UMASK设置(确保新建文件不具备全员可写权限)" "027" \
        "grep -i '^umask' /etc/profile /etc/bashrc 2>/dev/null | tail -1 | awk '{print \$2}'" "eq"
    audit_item "/etc/passwd 权限 (root 可写，其他人只读)" "644" "stat -c %a /etc/passwd" "eq"
    audit_item "/etc/shadow 权限（仅 root 可读哈希值）" "000" "stat -c %a /etc/shadow" "eq"
    audit_item "关键文件无全局可写" "0" \
        "find /etc -type f -perm -0002 2>/dev/null | wc -l" "eq"
    audit_item "/tmp 目录 Sticky Bit（防止用户删除属于其他用户的文件）" "1777" "stat -c %a /tmp" "eq"
}

# --- 3. 网络与服务 ---
audit_network() {
    echo "@HEAD@^=== [3] 网络与服务安全 ===^^" >> "$RAW_OUTPUT"
    audit_item "SSH 端口 (建议非22)" "22" \
        "grep '^Port' /etc/ssh/sshd_config | awk '{print \$2}'" "eq"
    audit_item "SSH 协议版本" "2" \
        "grep '^Protocol' /etc/ssh/sshd_config | awk '{print \$2}'" "eq"
    audit_item "SSH 空闲超时 (秒)" "300" \
        "grep '^ClientAliveInterval' /etc/ssh/sshd_config | awk '{print \$2}'" "eq"
    audit_item "禁止 IP 转发" "0" "sysctl -n net.ipv4.ip_forward" "eq"
    audit_item "禁止 ICMP 重定向" "0" "sysctl -n net.ipv4.conf.all.accept_redirects" "eq"
    audit_item "关闭 Postfix 邮件服务" "dead" "systemctl is-active postfix" "service_off"
}

# --- 4. 日志与系统 ---
audit_system() {
    echo "@HEAD@^=== [4] 日志与系统增强 ===^^" >> "$RAW_OUTPUT"
    audit_item "Rsyslog 服务状态（日志服务正在运行并开机自启）" "active" "systemctl is-active rsyslog" "service_on"
    audit_item "Auditd 审计服务" "active" "systemctl is-active auditd" "service_on"
    audit_item "历史命令加时间戳" "存在配置" \
        "grep 'HISTTIMEFORMAT' /etc/profile" "contain"
    audit_item "Grub 引导密码" "存在配置" \
        "grep -r '^password' /boot/grub* 2>/dev/null | head -1" "contain"
    audit_item "禁用 Ctrl+Alt+Del" "masked" \
        "systemctl is-enabled ctrl-alt-del.target 2>/dev/null || echo masked" "eq"
}

# --- 报表显示 (使用 AWK 解决乱码) ---
show_report() {
    echo "正在生成报表..."
    # 1. 写入表头
    echo "检查项目(Check Item)^推荐标准^当前状态^判定结果" > "$RAW_OUTPUT"
    echo "----------------------------------------^--------^--------^--------" >> "$RAW_OUTPUT"
    
    # 2. 执行所有检查
    audit_account
    audit_file
    audit_network
    audit_system
    
    echo ""
    
    # 3. 渲染输出
    # column: 先对齐
    # awk: 负责上色。awk 中的 \033 是跨平台兼容的。
    cat "$RAW_OUTPUT" | column -t -s '^' | awk '
    BEGIN {
        RESET = "\033[0m"
        RED = "\033[31m"
        GREEN = "\033[32m"
        YELLOW = "\033[33m"
        BLUE = "\033[34m"
    }
    {
        line = $0
        
        # 1. 处理标题行 (@HEAD@)
        if (line ~ /@HEAD@/) {
            gsub(/@HEAD@/, "", line)
            print YELLOW line RESET
        }
        # 2. 处理表头
        else if (line ~ /检查项目/) {
            print BLUE line RESET
        }
        # 3. 处理数据行
        else {
            # 替换状态词为彩色中文
            if (line ~ /PASS/) {
                sub(/PASS/, GREEN "合规" RESET, line)
                print line
            }
            else if (line ~ /FAIL/) {
                sub(/FAIL/, RED "不合规" RESET, line)
                print line
            } 
            else {
                print line
            }
        }
    }'
    
    rm -f "$RAW_OUTPUT"
}

# --- 加固与回滚 (逻辑保持不变) ---
run_harden() {
    echo -e "\033[33m[*] 正在备份配置到 $BACKUP_DIR ...\033[0m"
    mkdir -p "$BACKUP_DIR"
    for f in "/etc/ssh/sshd_config" "/etc/login.defs" "/etc/profile" "/etc/sysctl.conf" \
             "/etc/pam.d/system-auth" "/etc/pam.d/common-password" "/etc/pam.d/common-auth" \
             "/etc/default/grub" "/etc/passwd" "/etc/shadow"; do
        [ -f "$f" ] && cp --parents "$f" "$BACKUP_DIR"
    done

    echo -e "\033[33m[*] 开始执行加固...\033[0m"

    # 1. SSH
    sed -i '/^PermitRootLogin/d' /etc/ssh/sshd_config && echo "PermitRootLogin no" >> /etc/ssh/sshd_config
    # === 人工决策区：SSH 端口 ===
    read -p "输入新 SSH 端口(回车跳过): " NEW_PORT
    [ -n "$NEW_PORT" ] && { sed -i '/^Port/d' /etc/ssh/sshd_config; echo "Port $NEW_PORT" >> /etc/ssh/sshd_config; }
    sed -i '/^Protocol/d' /etc/ssh/sshd_config && echo "Protocol 2" >> /etc/ssh/sshd_config
    sed -i '/^ClientAliveInterval/d' /etc/ssh/sshd_config && echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
    sed -i '/^ClientAliveCountMax/d' /etc/ssh/sshd_config && echo "ClientAliveCountMax 3" >> /etc/ssh/sshd_config

    # 2. 账号策略
    sed -i '/^PASS_MAX_DAYS/c\PASS_MAX_DAYS   90' /etc/login.defs
    sed -i '/^PASS_MIN_DAYS/c\PASS_MIN_DAYS   7' /etc/login.defs
    sed -i '/^PASS_WARN_AGE/c\PASS_WARN_AGE   7' /etc/login.defs

    # 3. PAM 密码复杂度 & 失败锁定（CentOS/RHEL 路径）
    # 定义目标整行（与检测行 100% 相同）
    PWQ_LINE="password requisite pam_pwquality.so retry=3 minlen=12 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1"

    # CentOS/RHEL
    if [ -f /etc/pam.d/system-auth ]; then
        # 先清掉所有 pam_pwquality.so 行
        sed -i '/pam_pwquality\.so/d' /etc/pam.d/system-auth
        # 在第一条 password requisite 行**后面**插入（保持 PAM 顺序）
        sed -i '/^password.*requisite/a\'"$PWQ_LINE" /etc/pam.d/system-auth
    fi
    # Ubuntu/Debian
    if [ -f /etc/pam.d/common-password ]; then
        sed -i '/pam_pwquality\.so/d' /etc/pam.d/common-password
        # 插到文件最顶（Debian 习惯）
        sed -i '1i\'"$PWQ_LINE" /etc/pam.d/common-password
    fi
    #失败锁定
    FAIL_LINE_PRE="auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900"
    FAIL_LINE_FAIL="auth [default=die] pam_faillock.so authfail silent audit deny=5 unlock_time=900"

    for f in /etc/pam.d/system-auth /etc/pam.d/common-auth; do
        [ -f "$f" ] || continue
        sed -i '/pam_faillock\.so/d' "$f"
        # 插在 auth 区最前
        sed -i '1i\'"$FAIL_LINE_PRE" "$f"
        sed -i '/^auth.*sufficient.*pam_unix.so/a\'"$FAIL_LINE_FAIL" "$f"
    done

    # 5. UID=0 非 root 账号（仅列出，人工确认后删除）
    # === 人工决策区：确认后删除 ===
    echo "以下 UID=0 账号非 root，请确认后手动删除："
    awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd
    for u in $(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd); do
        userdel -r "$u"
    done

    # 6. 清理无用系统账户（示例，需要人工确认）
    # === 人工决策区：取消注释即删除 ===
    for acc in lp sync shutdown halt games; do
        userdel -r "$acc" 2>/dev/null
    done

    # 7. 文件权限
    grep -q "^umask 027" /etc/profile || echo "umask 027" >> /etc/profile
    chmod 644 /etc/passwd
    chmod 000 /etc/shadow
    chmod 600 /etc/gshadow 2>/dev/null
    # 去掉 /etc 下全局可写文件
    find /etc -type f -perm -0002 -exec chmod o-w {} \;

    # 8. 内核参数
    cat >> /etc/sysctl.conf <<EOF
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.icmp_ignore_bogus_error_responses = 1
EOF
    sysctl -p >/dev/null 2>&1

    # 9. 禁用 Ctrl+Alt+Del
    systemctl mask ctrl-alt-del.target >/dev/null 2>&1

    # 10. 历史命令时间戳
    grep -q HISTTIMEFORMAT /etc/profile || echo 'export HISTTIMEFORMAT="%F %T "' >> /etc/profile

    # 11. 审计服务 auditd（如未安装需人工装包）
    # === 人工决策区：如未安装先执行 yum install -y auditd 或 apt install -y auditd ===
    systemctl enable auditd --now >/dev/null 2>&1

    # 12. GRUB 密码（人工决策区：取消注释后设置密码）
    # grub2-setpassword  # CentOS7+
    # update-grub         # Ubuntu/Debian
    # 注意：设置后下次重启生效，务必保管好密码！

    echo -e "\033[33m[*] 重启 SSH 服务...\033[0m"
    systemctl restart sshd
    echo -e "\033[32m[SUCCESS] 加固完成！\033[0m"
}

# --- 主入口 ---
check_root
case "$1" in
    check) show_report ;;
    harden) 
        read -p "确定要进行加固吗？(y/n) " ans
        if [ "$ans" == "y" ]; then run_harden; fi ;;
    rollback) rollback "$2" ;;
    *) echo "用法: $0 {check|harden|rollback <path>}" ;;
esac
