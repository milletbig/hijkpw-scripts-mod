#!/bin/bash
# Xray一键安装脚本 (VLESS Only + XHTTP 修改版)
# Original Author: hijk
# Modified by: Gemini (2025 Fix with XHTTP)
# 适配系统：CentOS 7/8/9, Debian 10+, Ubuntu 20+

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[36m"
PLAIN='\033[0m'

# 伪装网站列表
SITES=(
http://www.quanben.io/
http://www.55shuba.com/
https://www.23xsw.cc/
https://www.xindingdianxsw.com/
)

CONFIG_FILE="/usr/local/etc/xray/config.json"
NGINX_CONF_PATH="/etc/nginx/conf.d/"
NGINX_HTML_PATH="/usr/share/nginx/html"

# 核心变量初始化
VLESS="true" # 强制开启VLESS
TLS="false"
WS="false"
XTLS="false" # 对应 Vision 模式
XHTTP="false" # 对应 XHTTP 模式

checkSystem() {
    result=$(id | awk '{print $1}')
    if [[ $result != "uid=0(root)" ]]; then
        colorEcho $RED " 请以root身份执行该脚本"
        exit 1
    fi

    if [[ -f /etc/redhat-release ]]; then
        PMT="yum"
        CMD_INSTALL="yum install -y "
        CMD_REMOVE="yum remove -y "
    elif cat /etc/issue | grep -q -E -i "debian|ubuntu"; then
        PMT="apt"
        CMD_INSTALL="apt install -y "
        CMD_REMOVE="apt remove -y "
        $PMT update
    else
        colorEcho $RED " 不受支持的Linux系统"
        exit 1
    fi
}

colorEcho() {
    echo -e "${1}${@:2}${PLAIN}"
}

# 1: new Xray. 0: no. 1: yes. 2: not installed. 3: check failed.
getVersion() {
    VER=`/usr/local/bin/xray version 2>/dev/null | head -n1 | awk '{print $2}'`
    RETVAL=$?
    CUR_VER=${VER:-"未安装"}
    
    # 获取最新版本
    TAG_URL="https://api.github.com/repos/XTLS/Xray-core/releases/latest"
    NEW_VER=`curl -s "${TAG_URL}" --connect-timeout 10| grep 'tag_name' | cut -d\" -f4`
    
    if [[ $? -ne 0 ]] || [[ $NEW_VER == "" ]]; then
        colorEcho $RED " 检查Xray版本信息失败，请检查网络"
        return 3
    elif [[ $RETVAL -ne 0 ]];then
        return 2
    elif [[ $NEW_VER != $CUR_VER ]];then
        return 1
    fi
    return 0
}

archAffix(){
    case "$(uname -m)" in
        x86_64|amd64) echo '64' ;;
        armv8|aarch64) echo 'arm64-v8a' ;;
        *) colorEcho $RED " 不支持的CPU架构！"; exit 1 ;;
    esac
}

getData() {
    # 强制获取域名和证书逻辑
    echo ""
    echo " Xray VLESS 脚本，运行之前请确认如下条件已经具备："
    colorEcho ${YELLOW} "  1. 一个伪装域名"
    colorEcho ${YELLOW} "  2. 伪装域名DNS解析指向当前服务器ip"
    echo " "
    read -p " 确认满足按y，按其他退出脚本：" answer
    if [[ "${answer,,}" != "y" ]]; then
        exit 0
    fi

    echo ""
    while true
    do
        read -p " 请输入伪装域名：" DOMAIN
        if [[ -z "${DOMAIN}" ]]; then
            colorEcho ${RED} " 域名输入错误，请重新输入！"
        else
            break
        fi
    done
    DOMAIN=${DOMAIN,,}
    colorEcho ${BLUE}  " 伪装域名(host)：$DOMAIN"

    # 端口设置
    if [[ "$XTLS" = "true" ]]; then
        # Vision 模式下 Xray 必须监听 443
        PORT=443
    elif [[ "$WS" = "true" || "$XHTTP" = "true" ]]; then
        # WS/XHTTP 模式下 Nginx 前置监听 443/80，Xray 监听本地端口
        PORT=443 # 这是 Nginx 对外的端口
        XPORT=`shuf -i10000-65000 -n1` # 这是 Xray 本地端口
    else
        # VLESS TCP TLS 模式 (保留逻辑)
        read -p " 请输入xray监听端口[默认443]：" PORT
        [[ -z "${PORT}" ]] && PORT=443
    fi

    # 路径设置 (WS 和 XHTTP 都需要路径)
    if [[ "$WS" = "true" || "$XHTTP" = "true" ]]; then
        echo ""
        while true
        do
            read -p " 请输入分流路径，以/开头(默认 /api)：" WSPATH
            [[ -z "${WSPATH}" ]] && WSPATH="/api"
            if [[ "${WSPATH:0:1}" != "/" ]]; then
                colorEcho ${RED}  " 路径必须以/开头！"
            else
                break
            fi
        done
        colorEcho ${BLUE}  " 分流路径：$WSPATH"
    fi

    # 伪装站逻辑
    echo ""
    colorEcho $BLUE " 请选择伪装站类型:"
    echo "   1) 静态网站(位于 $NGINX_HTML_PATH)"
    echo "   2) 小说站(随机选择)"
    echo "   3) 高清壁纸站(https://wallroom.io/)"
    echo "   4) 自定义反代站点"
    read -p "  请选择伪装网站类型[默认:高清壁纸站]" answer
    if [[ -z "$answer" ]]; then
        PROXY_URL="https://wallroom.io/"
    else
        case $answer in
        1) PROXY_URL="" ;;
        2)
            len=${#SITES[@]}
            ((len--))
            index=`shuf -i0-${len} -n1`
            PROXY_URL=${SITES[$index]}
            ;;
        3) PROXY_URL="https://wallroom.io/" ;;
        4)
            read -p " 请输入反代站点(以http或者https开头)：" PROXY_URL
            ;;
        *) PROXY_URL="https://wallroom.io/" ;;
        esac
    fi
    REMOTE_HOST=`echo ${PROXY_URL} | cut -d/ -f3`
    colorEcho $BLUE " 伪装网站：$PROXY_URL"
}

installNginx() {
    echo ""
    colorEcho $BLUE " 安装nginx..."
    if [[ "$PMT" = "yum" ]]; then
        $CMD_INSTALL epel-release
        $CMD_INSTALL nginx
    else
        $CMD_INSTALL nginx
    fi
    
    if [[ ! -f /etc/nginx/nginx.conf ]]; then
        colorEcho $RED " Nginx安装看起来失败了，请检查系统源"
        exit 1
    fi
    systemctl enable nginx
}

stopNginx() {
    systemctl stop nginx
}

startNginx() {
    systemctl start nginx
}

getCert() {
    mkdir -p /usr/local/etc/xray
    
    # 检查端口占用
    if [[ "$XTLS" = "true" ]]; then
        stopNginx
        systemctl stop xray
        # 释放 80 端口给 acme.sh 独立模式使用
    fi

    $CMD_INSTALL socat openssl
    if [[ "$PMT" = "yum" ]]; then
        $CMD_INSTALL cronie
        systemctl start crond
        systemctl enable crond
    else
        $CMD_INSTALL cron
        systemctl start cron
        systemctl enable cron
    fi

    curl -sL https://get.acme.sh | sh
    source ~/.bashrc
    ~/.acme.sh/acme.sh --upgrade --auto-upgrade
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt

    # 申请证书 (使用 Standalone 模式，需要占用 80 端口)
    stopNginx
    ~/.acme.sh/acme.sh --issue -d $DOMAIN --keylength ec-256 --standalone --force
    
    if [[ $? -ne 0 ]]; then
        colorEcho $RED " 证书申请失败！请检查域名解析或防火墙设置（需开放80端口）"
        exit 1
    fi

    CERT_FILE="/usr/local/etc/xray/${DOMAIN}.pem"
    KEY_FILE="/usr/local/etc/xray/${DOMAIN}.key"
    
    # 安装证书
    ~/.acme.sh/acme.sh --install-cert -d $DOMAIN --ecc \
        --key-file       $KEY_FILE  \
        --fullchain-file $CERT_FILE \
        --reloadcmd     "systemctl restart xray; systemctl restart nginx"
        
    chmod 644 $CERT_FILE
    chmod 644 $KEY_FILE
}

configNginx() {
    mkdir -p $NGINX_HTML_PATH
    
    # 设置反代配置段
    if [[ "$PROXY_URL" = "" ]]; then
        action=""
    else
        action="proxy_ssl_server_name on;
        proxy_pass $PROXY_URL;
        proxy_set_header Accept-Encoding '';
        sub_filter \"$REMOTE_HOST\" \"$DOMAIN\";
        sub_filter_once off;"
    fi

    # 清理旧配置
    rm -f ${NGINX_CONF_PATH}${DOMAIN}.conf

    # 生成 Location 块内容
    if [[ "$WS" = "true" ]]; then
        # WS 需要 Upgrade 头
        LOCATION_BLOCK="location ${WSPATH} {
      proxy_redirect off;
      proxy_pass http://127.0.0.1:${XPORT};
      proxy_http_version 1.1;
      proxy_set_header Upgrade \$http_upgrade;
      proxy_set_header Connection \"upgrade\";
      proxy_set_header Host \$host;
      proxy_set_header X-Real-IP \$remote_addr;
      proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }"
    elif [[ "$XHTTP" = "true" ]]; then
        # XHTTP 不需要 Upgrade 头，作为纯 HTTP 代理
        LOCATION_BLOCK="location ${WSPATH} {
      proxy_redirect off;
      proxy_pass http://127.0.0.1:${XPORT};
      proxy_http_version 1.1;
      proxy_set_header Host \$host;
      proxy_set_header X-Real-IP \$remote_addr;
      proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }"
    else
        LOCATION_BLOCK=""
    fi

    # 生成完整配置
    # 场景1: WS/XHTTP + TLS (Nginx 前置)
    if [[ "$WS" = "true" || "$XHTTP" = "true" ]]; then
        cat > ${NGINX_CONF_PATH}${DOMAIN}.conf<<-EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    return 301 https://\$server_name:${PORT}\$request_uri;
}

server {
    listen       ${PORT} ssl http2;
    listen       [::]:${PORT} ssl http2;
    server_name ${DOMAIN};
    
    ssl_certificate $CERT_FILE;
    ssl_certificate_key $KEY_FILE;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;

    root $NGINX_HTML_PATH;
    location / {
        $action
    }

    $LOCATION_BLOCK
}
EOF
    # 场景2: XTLS-Vision (Xray 前置)
    elif [[ "$XTLS" = "true" ]]; then
        cat > ${NGINX_CONF_PATH}${DOMAIN}.conf<<-EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    root $NGINX_HTML_PATH;
    
    # 仅处理回落流量，不需要 SSL
    location / {
        $action
    }
}
EOF
    fi
}

installXray() {
    rm -rf /tmp/xray
    mkdir -p /tmp/xray
    DOWNLOAD_LINK="https://github.com/XTLS/Xray-core/releases/download/${NEW_VER}/Xray-linux-$(archAffix).zip"
    colorEcho $BLUE " 下载Xray: ${DOWNLOAD_LINK}"
    curl -L -H "Cache-Control: no-cache" -o /tmp/xray/xray.zip ${DOWNLOAD_LINK}
    if [ $? != 0 ];then
        colorEcho $RED " 下载Xray文件失败"
        exit 1
    fi
    systemctl stop xray
    mkdir -p /usr/local/etc/xray /usr/local/share/xray
    unzip -o /tmp/xray/xray.zip -d /tmp/xray
    cp /tmp/xray/xray /usr/local/bin
    cp /tmp/xray/geo* /usr/local/share/xray
    chmod +x /usr/local/bin/xray

    cat >/etc/systemd/system/xray.service<<-EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=root
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable xray.service
}

vlessWSConfig() {
    local uuid="$(cat '/proc/sys/kernel/random/uuid')"
    cat > $CONFIG_FILE<<-EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [{
    "port": $XPORT,
    "listen": "127.0.0.1",
    "protocol": "vless",
    "settings": {
        "clients": [
            {
                "id": "$uuid",
                "level": 0
            }
        ],
        "decryption": "none"
    },
    "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
            "path": "$WSPATH",
            "headers": {
                "Host": "$DOMAIN"
            }
        }
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {}
  },{
    "protocol": "blackhole",
    "settings": {},
    "tag": "blocked"
  }]
}
EOF
}

vlessXHTTPConfig() {
    local uuid="$(cat '/proc/sys/kernel/random/uuid')"
    # XHTTP 配置：相比 WS，Network 改为 xhttp，配置块改为 xhttpSettings
    cat > $CONFIG_FILE<<-EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [{
    "port": $XPORT,
    "listen": "127.0.0.1",
    "protocol": "vless",
    "settings": {
        "clients": [
            {
                "id": "$uuid",
                "level": 0
            }
        ],
        "decryption": "none"
    },
    "streamSettings": {
        "network": "xhttp",
        "security": "none",
        "xhttpSettings": {
            "path": "$WSPATH",
            "host": "$DOMAIN"
        }
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {}
  },{
    "protocol": "blackhole",
    "settings": {},
    "tag": "blocked"
  }]
}
EOF
}

vlessVisionConfig() {
    local uuid="$(cat '/proc/sys/kernel/random/uuid')"
    cat > $CONFIG_FILE<<-EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [{
    "port": 443,
    "protocol": "vless",
    "settings": {
      "clients": [
        {
          "id": "$uuid",
          "flow": "xtls-rprx-vision",
          "level": 0
        }
      ],
      "decryption": "none",
      "fallbacks": [
          {
              "dest": 80
          }
      ]
    },
    "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
            "certificates": [
                {
                    "certificateFile": "$CERT_FILE",
                    "keyFile": "$KEY_FILE"
                }
            ]
        }
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {}
  },{
    "protocol": "blackhole",
    "settings": {},
    "tag": "blocked"
  }]
}
EOF
}

configXray() {
    mkdir -p /usr/local/xray
    
    if [[ "$WS" = "true" ]]; then
        vlessWSConfig
    elif [[ "$XHTTP" = "true" ]]; then
        vlessXHTTPConfig
    elif [[ "$XTLS" = "true" ]]; then
        vlessVisionConfig
    fi
}

install() {
    getData
    $PMT clean all
    [[ "$PMT" = "apt" ]] && $PMT update
    $CMD_INSTALL wget vim unzip tar gcc openssl net-tools
    
    installNginx
    
    # 防火墙处理
    if command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-service=http
        firewall-cmd --permanent --add-service=https
        firewall-cmd --reload
    elif command -v ufw &> /dev/null; then
        ufw allow http
        ufw allow https
    fi

    getCert
    configNginx
    
    # 再次重载 Nginx 确保配置生效
    systemctl restart nginx

    colorEcho $BLUE " 安装Xray..."
    getVersion
    if [[ $RETVAL == 0 ]]; then
        colorEcho $BLUE " Xray ${CUR_VER} 已安装"
    else
        installXray
    fi

    configXray
    start
    showInfo
}

start() {
    systemctl restart nginx
    systemctl restart xray
    sleep 2
    statusText
}

status() {
    if [[ ! -f /usr/local/bin/xray ]]; then
        echo 0
        return
    fi
    if [[ ! -f $CONFIG_FILE ]]; then
        echo 1
        return
    fi
    if pgrep -x "xray" > /dev/null; then
        echo 2
    else
        echo 3
    fi
}

statusText() {
    res=`status`
    case $res in
        2) echo -e ${GREEN}Xray 正在运行${PLAIN} ;;
        3) echo -e ${RED}Xray 未运行${PLAIN} ;;
        *) echo -e ${RED}未安装${PLAIN} ;;
    esac
}

showInfo() {
    echo ""
    echo "================================"
    echo "   Xray 配置信息"
    echo "================================"
    
    uid=`grep id $CONFIG_FILE | head -n1| cut -d: -f2 | tr -d \",' '`
    
    if [[ "$WS" = "true" ]]; then
        path=`grep path $CONFIG_FILE | cut -d: -f2 | tr -d \",' '`
        echo -e " 协议: ${BLUE}VLESS + WS + TLS${PLAIN}"
        echo -e " 地址: ${RED}${DOMAIN}${PLAIN}"
        echo -e " 端口: ${RED}443${PLAIN}"
        echo -e " UUID: ${RED}${uid}${PLAIN}"
        echo -e " 路径: ${RED}${path}${PLAIN}"
        echo -e " 加密: ${RED}none${PLAIN}"
    elif [[ "$XHTTP" = "true" ]]; then
        path=`grep path $CONFIG_FILE | cut -d: -f2 | tr -d \",' '`
        echo -e " 协议: ${BLUE}VLESS + XHTTP + TLS${PLAIN}"
        echo -e " 地址: ${RED}${DOMAIN}${PLAIN}"
        echo -e " 端口: ${RED}443${PLAIN}"
        echo -e " UUID: ${RED}${uid}${PLAIN}"
        echo -e " 路径: ${RED}${path}${PLAIN}"
        echo -e " 加密: ${RED}none${PLAIN}"
        echo -e " 提示: ${YELLOW}请确保客户端 Xray 内核版本 >= 1.8.24${PLAIN}"
    elif [[ "$XTLS" = "true" ]]; then
        echo -e " 协议: ${BLUE}VLESS + TCP + XTLS-Vision${PLAIN}"
        echo -e " 地址: ${RED}${DOMAIN}${PLAIN}"
        echo -e " 端口: ${RED}443${PLAIN}"
        echo -e " UUID: ${RED}${uid}${PLAIN}"
        echo -e " 流控: ${RED}xtls-rprx-vision${PLAIN}"
        echo -e " 加密: ${RED}none${PLAIN}"
    fi
    echo "================================"
}

menu() {
    clear
    echo "#################################################################"
    echo -e "#                  ${RED}Xray VLESS 极简安装脚本${PLAIN}                  #"
    echo -e "# ${GREEN}已修正 Nginx 路径与 ACME 配置${PLAIN}                             #"
    echo -e "# ${GREEN}支持 WS / XHTTP / XTLS-Vision 三种模式${PLAIN}                    #"
    echo "#################################################################"
    echo -e "  ${GREEN}1.${PLAIN}   安装 Xray-${BLUE}VLESS+WS+TLS${PLAIN} (经典，兼容性好)"
    echo -e "  ${GREEN}2.${PLAIN}   安装 Xray-${BLUE}VLESS+XTLS-Vision${PLAIN} (直连速度最快)"
    echo -e "  ${GREEN}3.${PLAIN}   安装 Xray-${BLUE}VLESS+XHTTP+TLS${PLAIN} (最新协议，抗封锁强)"
    echo " -------------"
    echo -e "  ${GREEN}11.${PLAIN}  更新 Xray 核心"
    echo -e "  ${GREEN}12.${PLAIN}  查看配置信息"
    echo -e "  ${GREEN}0.${PLAIN}   退出"
    echo ""
    read -p " 请选择操作：" answer
    case $answer in
        0) exit 0 ;;
        1)
            WS="true"
            TLS="true"
            XTLS="false"
            XHTTP="false"
            install
            ;;
        2)
            WS="false"
            TLS="true"
            XTLS="true"
            XHTTP="false"
            install
            ;;
        3)
            WS="false"
            TLS="true"
            XTLS="false"
            XHTTP="true"
            install
            ;;
        11)
            installXray
            start
            ;;
        12)
            showInfo
            ;;
        *)
            colorEcho $RED " 请选择正确的操作！"
            exit 1
            ;;
    esac
}

checkSystem
menu