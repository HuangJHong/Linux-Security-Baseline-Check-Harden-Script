#!/bin/bash

# =============================================================================
# 脚本名称: Linux Security Baseline Check & Harden v2.0
# 更新内容: 修复对齐、升级密码复杂度(12位+4种字符)、移除Banner项、修复空行Bug
# =============================================================================

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;36m'
NC='\033[0m'

# 备份目录
BACKUP_DIR="/root/security_backup_$(date +%Y%m%d_%H%M%S)"
# 增加 pwquality.conf 到备份列表
CONFIG_FILES=(
    "/etc/login.defs"
    "/etc/ssh/sshd_config"
    "/etc/profile"
    "/etc/sysctl.conf"
    "/etc/security/pwquality.conf" 
)

# --------------------------
# 标准值配置
# --------------------------
STD_PASS_MAX_DAYS=90
STD_PASS_MIN_DAYS=7
STD_PASS_WARN_AGE=7
STD_UMASK="027"
STD_TMOUT=300
# 密码复杂度标准
PW_MIN_LEN=12
PW_MIN_CLASS=4 # 包含大小写数字特殊字符四类

# --------------------------
# 基础工具函数
# --------------------------

if [ "$(id -u)" != "0" ]; then
    echo -e "${RED}错误: 请使用 root 权限运行此脚本。${NC}"
    exit 1
fi

if [ -f /etc/redhat-release ]; then OS="CentOS"; elif [ -f /etc/debian_version ]; then OS="Debian"; else OS="Unknown"; fi

print_header() {
    # 调整宽度以适应中文和长字符串
    printf "${BLUE}%-3s %-38s %-20s %-20s %-10s${NC}\n" "ID" "检查项" "标准值" "当前值" "结果"
    echo "----------------------------------------------------------------------------------------------------"
}

print_row() {
    local id=$1
    local name=$2
    local std=$3
    local curr=$4
    local res=$5
    
    local color=$GREEN
    if [ "$res" == "FAIL" ]; then color=$RED; fi
    if [ "$res" == "MANUAL" ]; then color=$YELLOW; fi
    
    # 截断过长的当前值以防破坏对齐
    if [ ${#curr} -gt 18 ]; then curr="${curr:0:15}..."; fi

    printf "%-3s %-38s %-20s %-20s ${color}%-10s${NC}\n" "$id" "$name" "$std" "$curr" "$res"
}

backup_configs() {
    echo -e "${BLUE}[*] 正在创建配置文件备份...${NC}"
    mkdir -p "$BACKUP_DIR"
    for file in "${CONFIG_FILES[@]}"; do
        # 仅备份存在的文件
        if [ -f "$file" ]; then
            cp -p "$file" "$BACKUP_DIR/"
        fi
    done
    echo "$BACKUP_DIR" > /root/.last_sec_backup
    echo -e "${GREEN}[+] 备份完成: $BACKUP_DIR${NC}"
}

# --------------------------
# 核心处理函数
# --------------------------

# 处理 Key Value 类型的配置
handle_config_kv() {
    local id=$1
    local desc=$2
    local file=$3
    local key=$4
    local expect=$5
    local mode=$6
    local sep_type=$7 # space 或 eq

    local current_val=""
    
    if [ ! -f "$file" ]; then
        [ "$mode" == "check" ] && print_row "$id" "$desc" "$expect" "文件不存在" "FAIL"
        return
    fi

    # 获取当前值：增加 tail -1 防止多行，增加 tr -d 删除换行符
    if [ "$sep_type" == "eq" ]; then
        current_val=$(grep "^$key" "$file" | grep -v "^#" | tail -1 | awk -F= '{print $2}' | tr -d ' "\n\r')
    else
        current_val=$(grep "^$key" "$file" | grep -v "^#" | tail -1 | awk '{print $2}' | tr -d ' "\n\r')
    fi

    [ -z "$current_val" ] && current_val="未设置"

    if [ "$mode" == "check" ]; then
        if [ "$current_val" == "$expect" ]; then
            print_row "$id" "$desc" "$expect" "$current_val" "PASS"
        else
            print_row "$id" "$desc" "$expect" "$current_val" "FAIL"
        fi
    elif [ "$mode" == "harden" ]; then
        if [ "$current_val" != "$expect" ]; then
            if grep -q "^$key" "$file"; then
                if [ "$sep_type" == "eq" ]; then
                     sed -i "s|^$key=.*|$key=$expect|" "$file"
                else
                     sed -i "s|^$key .*|$key $expect|" "$file"
                fi
            else
                if [ "$sep_type" == "eq" ]; then
                    echo "$key=$expect" >> "$file"
                else
                    echo "$key $expect" >> "$file"
                fi
            fi
            echo " -> ID $id 已修复: $desc"
        fi
    fi
}

# --------------------------
# 具体的24项任务
# --------------------------

run_tasks() {
    local mode=$1
    if [ "$mode" == "check" ]; then print_header; fi

    # --- 1-2, 4. 基础账号有效期 (/etc/login.defs) ---
    handle_config_kv 1 "密码最大有效期" "/etc/login.defs" "PASS_MAX_DAYS" "$STD_PASS_MAX_DAYS" "$mode" "space"
    handle_config_kv 2 "密码最小天数" "/etc/login.defs" "PASS_MIN_DAYS" "$STD_PASS_MIN_DAYS" "$mode" "space"
    # ID 3 单独处理复杂度，ID 4 继续
    handle_config_kv 4 "密码过期警告" "/etc/login.defs" "PASS_WARN_AGE" "$STD_PASS_WARN_AGE" "$mode" "space"

    # --- 3. 密码复杂度 (重写逻辑) ---
    # 目标文件: /etc/security/pwquality.conf
    # 要求: minlen=12, minclass=4 (大写+小写+数字+特殊)
    local pw_file="/etc/security/pwquality.conf"
    local pw_res="FAIL"
    local pw_curr="不达标"
    
    # 检测逻辑
    if [ "$mode" == "check" ]; then
        if [ -f "$pw_file" ]; then
            local cur_len=$(grep "^minlen" $pw_file | awk -F= '{print $2}' | tr -d ' ')
            local cur_class=$(grep "^minclass" $pw_file | awk -F= '{print $2}' | tr -d ' ')
            [ -z "$cur_len" ] && cur_len=0
            [ -z "$cur_class" ] && cur_class=0
            
            if [ "$cur_len" -ge "$PW_MIN_LEN" ] && [ "$cur_class" -ge "$PW_MIN_CLASS" ]; then
                pw_curr="Len:${cur_len},Class:${cur_class}"
                pw_res="PASS"
            else
                pw_curr="Len:${cur_len},Class:${cur_class}"
            fi
        else
            pw_curr="未配置"
        fi
        print_row 3 "密码复杂度(长度12+四类字符)" "Len:12,Class:4" "$pw_curr" "$pw_res"

    # 加固逻辑
    elif [ "$mode" == "harden" ]; then
        if [ ! -f "$pw_file" ]; then touch "$pw_file"; fi
        
        # 使用 sed 配置 minlen
        if grep -q "^minlen" "$pw_file"; then
            sed -i "s/^minlen.*/minlen = $PW_MIN_LEN/" "$pw_file"
        else
            echo "minlen = $PW_MIN_LEN" >> "$pw_file"
        fi
        
        # 使用 sed 配置 minclass
        if grep -q "^minclass" "$pw_file"; then
            sed -i "s/^minclass.*/minclass = $PW_MIN_CLASS/" "$pw_file"
        else
            echo "minclass = $PW_MIN_CLASS" >> "$pw_file"
        fi
        echo " -> ID 3 已设置密码复杂度: 长度12, 字符类别4"
    fi

    # --- 5. 空密码账户 ---
    local empty_users=$(awk -F: '($2 == "") {print $1}' /etc/shadow | tr '\n' ',' | sed 's/,$//')
    [ -z "$empty_users" ] && empty_users="无"
    if [ "$mode" == "check" ]; then
        if [ "$empty_users" == "无" ]; then
            print_row 5 "空密码账户检测" "无" "无" "PASS"
        else
            print_row 5 "空密码账户检测" "无" "$empty_users" "FAIL"
        fi
    elif [ "$mode" == "harden" ] && [ "$empty_users" != "无" ]; then
        echo " -> ID 5 警告: 发现空密码用户 [$empty_users]，请手动处理！"
    fi

    # --- 6. UID 0 ---
    local uid0_users=$(awk -F: '($3 == 0) {print $1}' /etc/passwd | grep -v '^root$' | tr '\n' ',' | sed 's/,$//')
    [ -z "$uid0_users" ] && uid0_users="无"
    if [ "$mode" == "check" ]; then
        if [ "$uid0_users" == "无" ]; then
             print_row 6 "UID为0的非root账户" "无" "无" "PASS"
        else
             print_row 6 "UID为0的非root账户" "无" "$uid0_users" "FAIL"
        fi
    fi

    # --- 7-11. SSH ---
    handle_config_kv 7 "禁止Root远程登录" "/etc/ssh/sshd_config" "PermitRootLogin" "no" "$mode" "space"
    handle_config_kv 8 "禁止空密码登录" "/etc/ssh/sshd_config" "PermitEmptyPasswords" "no" "$mode" "space"
    
    # ID 9 Port
    local cur_port=$(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}' | tail -1 | tr -d '\r')
    [ -z "$cur_port" ] && cur_port="22(默认)"
    if [ "$mode" == "check" ]; then
        print_row 9 "SSH端口非默认" "非22" "$cur_port" "MANUAL"
    elif [ "$mode" == "harden" ]; then
        # 仅当处于加固模式且用户未修改时询问
        if [ "$cur_port" == "22(默认)" ] || [ "$cur_port" == "22" ]; then
            read -p " -> ID 9 是否修改SSH端口为 2222? (y/n): " choice
            if [ "$choice" == "y" ]; then
                if grep -q "^Port" /etc/ssh/sshd_config; then
                    sed -i 's/^Port .*/Port 2222/' /etc/ssh/sshd_config
                else
                    echo "Port 2222" >> /etc/ssh/sshd_config
                fi
                echo " -> SSH端口已改为 2222"
            fi
        fi
    fi

    handle_config_kv 10 "SSH最大认证次数" "/etc/ssh/sshd_config" "MaxAuthTries" "4" "$mode" "space"
    handle_config_kv 11 "SSH空闲超时(Interval)" "/etc/ssh/sshd_config" "ClientAliveInterval" "300" "$mode" "space"
    if [ "$mode" == "harden" ]; then
        if grep -q "^ClientAliveCountMax" /etc/ssh/sshd_config; then
            sed -i 's/^ClientAliveCountMax.*/ClientAliveCountMax 0/' /etc/ssh/sshd_config
        else
            echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config
        fi
    fi

    # --- 12-15. 权限 ---
    check_perm() {
        local id=$1
        local file=$2
        local exp_perm=$3
        # 使用 stat 获取权限数字
        local cur_perm=$(stat -c "%a" "$file" 2>/dev/null)
        if [ "$mode" == "check" ]; then
            if [ -z "$cur_perm" ]; then
                print_row "$id" "$file" "<=$exp_perm" "不存在" "PASS"
            elif [ "$cur_perm" -le "$exp_perm" ]; then
                print_row "$id" "$file 权限" "<=$exp_perm" "$cur_perm" "PASS"
            else
                print_row "$id" "$file 权限" "<=$exp_perm" "$cur_perm" "FAIL"
            fi
        elif [ "$mode" == "harden" ]; then
            if [ -n "$cur_perm" ] && [ "$cur_perm" -gt "$exp_perm" ]; then
                chmod "$exp_perm" "$file"
                echo " -> ID $id 已修复: $file 权限 -> $exp_perm"
            fi
        fi
    }
    check_perm 12 "/etc/passwd" 644
    check_perm 13 "/etc/shadow" 400
    check_perm 14 "/etc/group" 644
    check_perm 15 "/etc/gshadow" 400

    # --- 16-18. Profile ---
    if [ "$mode" == "check" ]; then
        local cur_umask=$(grep -i "^umask" /etc/profile | tail -1 | awk '{print $2}' | tr -d '\r')
        [ -z "$cur_umask" ] && cur_umask="未设置"
        if [ "$cur_umask" == "$STD_UMASK" ]; then
            print_row 16 "默认UMASK设置" "$STD_UMASK" "$cur_umask" "PASS"
        else
            print_row 16 "默认UMASK设置" "$STD_UMASK" "$cur_umask" "FAIL"
        fi
    elif [ "$mode" == "harden" ]; then
        if ! grep -q "^umask $STD_UMASK" /etc/profile; then
            echo "umask $STD_UMASK" >> /etc/profile
            echo " -> ID 16 已设置 umask"
        fi
    fi

    if [ "$mode" == "check" ]; then
        local cur_tmout=$(grep "^export TMOUT" /etc/profile | tail -1 | awk -F= '{print $2}' | tr -d '\r')
        [ -z "$cur_tmout" ] && cur_tmout="未设置"
        if [ "$cur_tmout" == "$STD_TMOUT" ]; then
             print_row 17 "登录超时TMOUT" "$STD_TMOUT" "$cur_tmout" "PASS"
        else
             print_row 17 "登录超时TMOUT" "$STD_TMOUT" "$cur_tmout" "FAIL"
        fi
    elif [ "$mode" == "harden" ]; then
        if ! grep -q "TMOUT=$STD_TMOUT" /etc/profile; then
            echo "export TMOUT=$STD_TMOUT" >> /etc/profile
        fi
    fi

    if [ "$mode" == "check" ]; then
        if grep -q "HISTTIMEFORMAT" /etc/profile; then
             print_row 18 "History时间戳" "存在" "存在" "PASS"
        else
             print_row 18 "History时间戳" "存在" "未设置" "FAIL"
        fi
    elif [ "$mode" == "harden" ]; then
        if ! grep -q "HISTTIMEFORMAT" /etc/profile; then
            echo 'export HISTTIMEFORMAT="%F %T `whoami` "' >> /etc/profile
        fi
    fi

    # --- 19-22. Sysctl (注意：eq模式下需要严格处理空格) ---
    # sysctl.conf 中可能是 "key = value" 或 "key=value"，使用 tr 删除空格统一处理
    handle_sysctl() {
        local id=$1; local desc=$2; local key=$3; local exp=$4
        local file="/etc/sysctl.conf"
        
        # 获取当前值：grep行 -> 去除注释 -> tail取最后一行 -> 删空格 -> 删key -> 删等号 -> 结果
        # 比如 net.ipv4.conf.all.accept_redirects = 0 -> 0
        local cur=$(grep "^$key" $file | grep -v "^#" | tail -1 | tr -d ' ' | awk -F= '{print $2}' | tr -d '\n\r')
        [ -z "$cur" ] && cur="未设置"

        if [ "$mode" == "check" ]; then
            if [ "$cur" == "$exp" ]; then
                print_row "$id" "$desc" "$exp" "$cur" "PASS"
            else
                print_row "$id" "$desc" "$exp" "$cur" "FAIL"
            fi
        elif [ "$mode" == "harden" ]; then
            if [ "$cur" != "$exp" ]; then
                if grep -q "^$key" $file; then
                    sed -i "s|^$key.*|$key = $exp|" $file
                else
                    echo "$key = $exp" >> $file
                fi
                echo " -> ID $id 已修复: $desc"
            fi
        fi
    }

    handle_sysctl 19 "禁止ICMP重定向" "net.ipv4.conf.all.accept_redirects" "0"
    handle_sysctl 20 "禁止IP源路由" "net.ipv4.conf.all.accept_source_route" "0"
    handle_sysctl 21 "开启SYN Cookie" "net.ipv4.tcp_syncookies" "1"
    handle_sysctl 22 "忽略ICMP广播" "net.ipv4.icmp_echo_ignore_broadcasts" "1"

    if [ "$mode" == "harden" ]; then sysctl -p >/dev/null 2>&1; fi

    # --- 23-24. Services ---
    check_svc() {
        local id=$1; local name=$2
        local status=$(systemctl is-active "$name" 2>/dev/null)
        [ -z "$status" ] && status="inactive"
        
        if [ "$mode" == "check" ]; then
            if [ "$status" == "active" ]; then
                print_row "$id" "服务状态: $name" "active" "active" "PASS"
            else
                print_row "$id" "服务状态: $name" "active" "$status" "FAIL"
            fi
        elif [ "$mode" == "harden" ]; then
            if [ "$status" != "active" ]; then
                systemctl enable --now "$name" >/dev/null 2>&1
                echo " -> ID $id 尝试启动: $name"
            fi
        fi
    }
    check_svc 23 "rsyslog"
    check_svc 24 "auditd"
}

rollback() {
    echo -e "${YELLOW}[!] 正在回滚...${NC}"
    if [ ! -f /root/.last_sec_backup ]; then
        echo "无备份记录。"
        exit 1
    fi
    LAST_BACKUP=$(cat /root/.last_sec_backup)
    if [ ! -d "$LAST_BACKUP" ]; then echo "备份目录不存在"; exit 1; fi
    
    for file in "${CONFIG_FILES[@]}"; do
        base_name=$(basename "$file")
        if [ -f "$LAST_BACKUP/$base_name" ]; then
            cp -f "$LAST_BACKUP/$base_name" "$file"
            echo "已恢复: $file"
        fi
    done
    sysctl -p >/dev/null 2>&1
    systemctl restart sshd
    echo -e "${GREEN}回滚完成。${NC}"
}

case "$1" in
    check)
        echo -e "${BLUE}=== 系统基线检测 ($OS) ===${NC}"
        run_tasks "check"
        ;;
    harden)
        read -p "确认加固? (y/n): " c
        if [ "$c" == "y" ]; then
            backup_configs
            run_tasks "harden"
            systemctl restart sshd
            echo -e "${GREEN}加固完成。${NC}"
        fi
        ;;
    rollback)
        rollback
        ;;
    *)
        echo "Usage: $0 {check|harden|rollback}"
        ;;
esac