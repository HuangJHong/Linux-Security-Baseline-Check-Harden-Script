#!/bin/bash

# =============================================================================
# 脚本名称: Linux Security Baseline Check & Harden v1
# 1. sed -i 's/\r$//' linux_check3.sh
# 2. chmod +x linux_baseline.sh
# 3. ./linux_baseline.sh check
# 4. ./linux_baseline.sh harden
# 4. ./linux_baseline.sh rollback
# =============================================================================

# --- 颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;36m'
NC='\033[0m'

# --- 临时文件 ---
TMP_DATA="/tmp/sec_check_data.txt"
TMP_ALIGNED="/tmp/sec_check_aligned.txt"

# --- 备份与配置 ---
BACKUP_DIR="/root/security_backup_$(date +%Y%m%d_%H%M%S)"
# 注意：数组顺序不影响，但回滚时需要知道原始路径，这里仅作为备份列表
CONFIG_FILES=("/etc/login.defs" "/etc/ssh/sshd_config" "/etc/profile" "/etc/sysctl.conf" "/etc/security/pwquality.conf")

# --- 标准值 (部分支持手动输入覆盖) ---
STD_PASS_MAX_DAYS=90
STD_PASS_MIN_DAYS=7
STD_PASS_WARN_AGE=7
STD_UMASK="027"
STD_TMOUT=300
PW_MIN_LEN=12
PW_MIN_CLASS=4

# --------------------------
# 基础工具函数
# --------------------------
if [ "$(id -u)" != "0" ]; then echo -e "${RED}错误: 必须使用 root 权限。${NC}"; exit 1; fi

# 检查 column 命令
if ! command -v column &> /dev/null; then
    if [ -f /etc/debian_version ]; then apt-get update && apt-get install -y bsdmainutils; fi
    if [ -f /etc/redhat-release ]; then yum install -y util-linux; fi
fi
# 识别包管理器
if [ -f /etc/redhat-release ]; then OS="CentOS"; PKG_MGR="yum"; elif [ -f /etc/debian_version ]; then OS="Debian"; PKG_MGR="apt-get"; else OS="Unknown"; fi

# 初始化输出
init_output() { echo "ID|检查项|标准值|当前值|结果" > "$TMP_DATA"; }

# 写入结果 (纯文本)
add_result() {
    local id=$1; local name=$2; local std=$3; local curr=$4; local code=$5
    curr=$(echo "$curr" | tr -d '\n\r|')
    if [ ${#curr} -gt 25 ]; then curr="${curr:0:22}..."; fi
    echo "${id}|${name}|${std}|${curr}|${code}" >> "$TMP_DATA"
}

# 打印表格 (Bash原生替换颜色，防乱码)
print_table() {
    echo -e "${BLUE}=== 系统基线检测报告 ($OS) ===${NC}"
    column -t -s '|' "$TMP_DATA" > "$TMP_ALIGNED"
    while IFS= read -r line; do
        line="${line//PASS/${GREEN}PASS${NC}}"
        line="${line//FAIL/${RED}FAIL${NC}}"
        line="${line//MANUAL/${YELLOW}MANUAL${NC}}"
        echo -e "$line"
    done < "$TMP_ALIGNED"
    echo "----------------------------------------------------------------------"
    rm -f "$TMP_DATA" "$TMP_ALIGNED"
}

backup_configs() {
    mkdir -p "$BACKUP_DIR"
    # 保存原始文件路径列表，方便回滚
    echo "# Backup manifest" > "$BACKUP_DIR/manifest.txt"
    for f in "${CONFIG_FILES[@]}"; do 
        if [ -f "$f" ]; then 
            cp -p "$f" "$BACKUP_DIR/"
            echo "$f" >> "$BACKUP_DIR/manifest.txt"
        fi
    done
    echo "$BACKUP_DIR" > /root/.last_sec_backup
    echo -e "${GREEN}备份已创建: $BACKUP_DIR${NC}"
}

# --------------------------
# 核心检测/加固逻辑
# --------------------------
handle_kv() {
    local id=$1; local desc=$2; local file=$3; local key=$4; local exp=$5; local mode=$6; local sep=$7
    if [ ! -f "$file" ]; then [ "$mode" == "check" ] && add_result "$id" "$desc" "$exp" "文件不存在" "FAIL"; return; fi
    local cur=$(grep "^$key" "$file" | grep -v "^#" | tail -1 | awk -F"${sep/space/ }" '{print $2}' | tr -d ' "='); [ -z "$cur" ] && cur="未设置"
    
    if [ "$mode" == "check" ]; then 
        add_result "$id" "$desc" "$exp" "$cur" "$([ "$cur" == "$exp" ] && echo PASS || echo FAIL)"
    elif [ "$mode" == "harden" ] && [ "$cur" != "$exp" ]; then
        if grep -q "^$key" "$file"; then sed -i "s|^$key.*|$key${sep/space/ }$exp|" "$file"; else echo "$key${sep/space/ }$exp" >> "$file"; fi
    fi
}

run_tasks() {
    local mode=$1; if [ "$mode" == "check" ]; then init_output; fi

    # 1. 密码策略
    handle_kv 1 "密码最大有效期" "/etc/login.defs" "PASS_MAX_DAYS" "$STD_PASS_MAX_DAYS" "$mode" "space"
    handle_kv 2 "密码最小天数" "/etc/login.defs" "PASS_MIN_DAYS" "$STD_PASS_MIN_DAYS" "$mode" "space"
    handle_kv 4 "密码过期警告" "/etc/login.defs" "PASS_WARN_AGE" "$STD_PASS_WARN_AGE" "$mode" "space"

    # 3. 密码复杂度
    local pf="/etc/security/pwquality.conf"; local pi="未配置"; local pr="FAIL"
    if [ "$mode" == "check" ]; then
        if [ -f "$pf" ]; then local l=$(grep "^minlen" $pf|awk -F= '{print $2}'|tr -d ' '); local c=$(grep "^minclass" $pf|awk -F= '{print $2}'|tr -d ' '); [ -z "$l" ]&&l=0; [ -z "$c" ]&&c=0; pi="L:$l,C:$c"; if [ "$l" -ge "$PW_MIN_LEN" ]&&[ "$c" -ge "$PW_MIN_CLASS" ]; then pr="PASS"; fi; fi
        add_result 3 "密码复杂度" "L:12,C:4" "$pi" "$pr"
    elif [ "$mode" == "harden" ]; then
        [ ! -f "$pf" ] && touch "$pf"
        for k in minlen minclass; do v=$([ "$k" == "minlen" ]&&echo $PW_MIN_LEN||echo $PW_MIN_CLASS); grep -q "^$k" "$pf" && sed -i "s/^$k.*/$k = $v/" "$pf" || echo "$k = $v" >> "$pf"; done
    fi

    # 5. 空密码
    local eu=$(awk -F: '($2 == "") {print $1}' /etc/shadow | tr '\n' ',' | sed 's/,$//'); [ -z "$eu" ] && eu="无"
    [ "$mode" == "check" ] && add_result 5 "空密码账户" "无" "$eu" "$([ "$eu" == "无" ] && echo PASS || echo FAIL)"
    [ "$mode" == "harden" ] && [ "$eu" != "无" ] && echo " -> [警告] 存在空密码用户: $eu，请手动处理！"

    # 6. UID 0
    local u0=$(awk -F: '($3 == 0) {print $1}' /etc/passwd | grep -v '^root$' | tr '\n' ',' | sed 's/,$//'); [ -z "$u0" ] && u0="无"
    [ "$mode" == "check" ] && add_result 6 "UID0非root" "无" "$u0" "$([ "$u0" == "无" ] && echo PASS || echo FAIL)"

    # 7-8. SSH 基础
    handle_kv 7 "禁止Root远程" "/etc/ssh/sshd_config" "PermitRootLogin" "no" "$mode" "space"
    handle_kv 8 "禁止空密码登录" "/etc/ssh/sshd_config" "PermitEmptyPasswords" "no" "$mode" "space"
    
    # 9. SSH 端口 (人工决策输入)
    local port=$(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}' | tail -1 | tr -d '\r'); [ -z "$port" ] && port="22(默认)"
    if [ "$mode" == "check" ]; then
        add_result 9 "SSH端口" "非22" "$port" "MANUAL"
    elif [ "$mode" == "harden" ]; then
        if [ "$port" == "22(默认)" ] || [ "$port" == "22" ]; then
            echo -e "${YELLOW} -> [交互] 检测到 SSH 端口为 22。${NC}"
            read -p "    是否修改 SSH 端口? (y/n): " ch_port
            if [ "$ch_port" == "y" ]; then
                read -p "    请输入新端口 (如 2222): " new_port
                if [[ "$new_port" =~ ^[0-9]+$ ]]; then
                    if grep -q "^Port" /etc/ssh/sshd_config; then sed -i "s/^Port.*/Port $new_port/" /etc/ssh/sshd_config; else echo "Port $new_port" >> /etc/ssh/sshd_config; fi
                    echo "    -> 端口已修改为 $new_port"
                else
                    echo "    -> 输入无效，跳过。"
                fi
            fi
        fi
    fi

    # 10-11. SSH 其他
    handle_kv 10 "SSH认证次数" "/etc/ssh/sshd_config" "MaxAuthTries" "4" "$mode" "space"
    handle_kv 11 "SSH空闲超时" "/etc/ssh/sshd_config" "ClientAliveInterval" "300" "$mode" "space"
    [ "$mode" == "harden" ] && ! grep -q "^ClientAliveCountMax" /etc/ssh/sshd_config && echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config

    # 12-15. 文件权限
    check_p(){ local i=$1;local f=$2;local e=$3;local c=$(stat -c "%a" "$f" 2>/dev/null);[ -z "$c" ]&&c="缺";if [ "$mode" == "check" ];then add_result "$i" "$f权限" "<=$e" "$c" "$([ "$c" != "缺" ]&&[ "$c" -le "$e" ]&&echo PASS||echo FAIL)";elif [ "$mode" == "harden" ]&&[ "$c" != "缺" ]&&[ "$c" -gt "$e" ];then chmod "$e" "$f";fi;}
    check_p 12 "/etc/passwd" 644; check_p 13 "/etc/shadow" 400; check_p 14 "/etc/group" 644; check_p 15 "/etc/gshadow" 400

    # 16-18. 环境配置
    local uv=$(grep -i "^umask" /etc/profile|tail -1|awk '{print $2}'|tr -d '\r');[ -z "$uv" ]&&uv="未设置"
    [ "$mode" == "check" ] && add_result 16 "默认UMASK" "$STD_UMASK" "$uv" "$([ "$uv" == "$STD_UMASK" ] && echo PASS || echo FAIL)"
    [ "$mode" == "harden" ] && ! grep -q "^umask $STD_UMASK" /etc/profile && echo "umask $STD_UMASK" >> /etc/profile

    local tv=$(grep "^export TMOUT" /etc/profile|awk -F= '{print $2}'|tr -d '\r');[ -z "$tv" ]&&tv="未设置"
    [ "$mode" == "check" ] && add_result 17 "登录超时TMOUT" "$STD_TMOUT" "$tv" "$([ "$tv" == "$STD_TMOUT" ] && echo PASS || echo FAIL)"
    [ "$mode" == "harden" ] && ! grep -q "TMOUT=$STD_TMOUT" /etc/profile && echo "export TMOUT=$STD_TMOUT" >> /etc/profile

    local ht=$(grep "HISTTIMEFORMAT" /etc/profile); [ "$mode" == "check" ] && add_result 18 "History时间戳" "存在" "$([ -n "$ht" ]&&echo 存在||echo 未设置)" "$([ -n "$ht" ]&&echo PASS||echo FAIL)"
    [ "$mode" == "harden" ] && [ -z "$ht" ] && echo 'export HISTTIMEFORMAT="%F %T `whoami` "' >> /etc/profile

    # 19-22. 内核参数
    handle_s(){ local i=$1;local n=$2;local k=$3;local e=$4;local c=$(grep "^$k" /etc/sysctl.conf|grep -v "^#"|tail -1|tr -d ' '|awk -F= '{print $2}');[ -z "$c" ]&&c="未设置"
    if [ "$mode" == "check" ];then add_result "$i" "$n" "$e" "$c" "$([ "$c" == "$e" ]&&echo PASS||echo FAIL)";elif [ "$mode" == "harden" ]&&[ "$c" != "$e" ];then grep -q "^$k" /etc/sysctl.conf && sed -i "s|^$k.*|$k = $e|" /etc/sysctl.conf || echo "$k = $e" >> /etc/sysctl.conf;fi;}
    handle_s 19 "禁止ICMP重定向" "net.ipv4.conf.all.accept_redirects" "0"; handle_s 20 "禁止IP源路由" "net.ipv4.conf.all.accept_source_route" "0"
    handle_s 21 "开启SYN Cookie" "net.ipv4.tcp_syncookies" "1"; handle_s 22 "忽略ICMP广播" "net.ipv4.icmp_echo_ignore_broadcasts" "1"
    [ "$mode" == "harden" ] && sysctl -p >/dev/null 2>&1

    # 23-24. 服务
    check_sv(){ local i=$1;local n=$2;local s=$(systemctl is-active "$n" 2>/dev/null);[ -z "$s" ]&&s="inactive"
    if [ "$mode" == "check" ];then add_result "$i" "服务:$n" "active" "$s" "$([ "$s" == "active" ]&&echo PASS||echo FAIL)";elif [ "$mode" == "harden" ]&&[ "$s" != "active" ];then
    if ! command -v "$n" &>/dev/null && [ "$n" == "auditd" ]; then 
        echo " -> 安装 auditd..."
        [ "$PKG_MGR" == "apt-get" ] && apt-get update && apt-get install -y auditd >/dev/null
        # CentOS 通常包名是 audit，但服务名是 auditd
        [ "$PKG_MGR" == "yum" ] && yum install -y audit >/dev/null
    fi
    systemctl enable --now "$n" >/dev/null 2>&1; sleep 1; s=$(systemctl is-active "$n" 2>/dev/null); [ "$s" == "active" ] && echo " -> $n 启动成功" || echo -e "${RED} -> $n 启动失败${NC}";fi;}
    check_sv 23 "rsyslog"; check_sv 24 "auditd"
}

case "$1" in
    check) run_tasks "check"; print_table ;;
    harden) 
        echo -e "${YELLOW}警告: 即将修改系统配置，已包含自动备份。${NC}"
        read -p "确认继续? (y/n): " c
        if [ "$c" == "y" ]; then 
            backup_configs; run_tasks "harden"; systemctl restart sshd
            echo -e "${GREEN}加固完成。SSH服务已重启。${NC}"
        else
            echo "已取消。"
        fi 
        ;;
    rollback) 
        if [ -f /root/.last_sec_backup ]; then 
            DIR=$(cat /root/.last_sec_backup)
            if [ -d "$DIR" ] && [ -f "$DIR/manifest.txt" ]; then 
                echo -e "${BLUE}正在从 $DIR 回滚...${NC}"
                # 按照 manifest 清单精准恢复，防止文件错位
                while read -r original_path; do
                    # 忽略注释
                    [[ "$original_path" =~ ^#.*$ ]] && continue
                    fname=$(basename "$original_path")
                    if [ -f "$DIR/$fname" ]; then
                        cp -f "$DIR/$fname" "$original_path"
                        echo "  -> 恢复: $original_path"
                    fi
                done < "$DIR/manifest.txt"
                
                sysctl -p >/dev/null 2>&1
                systemctl restart sshd
                echo -e "${GREEN}回滚完成。${NC}"
            else
                echo -e "${RED}备份目录或清单文件损坏。${NC}"
            fi
        else 
            echo "无备份记录。"
        fi 
        ;;
    *) echo "Usage: $0 {check|harden|rollback}" ;;
esac