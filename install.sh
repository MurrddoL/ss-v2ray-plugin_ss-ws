#!/bin/bash

#====================================================
#	System Request:Debian 9+/Ubuntu 18.04+/Centos 7+
#	Author:	MurrddoL
#	Dscription: V2ray ws+tls onekey 
#	Version: 5.1
#	email:murrddo@hotmail.com
#	Official document: www.v2ray.com
#====================================================

#fonts color
Green="\033[32m" 
Red="\033[31m" 
Yellow="\033[33m"
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
Font="\033[0m"

#notification information
Info="${Green}[信息]${Font}"
OK="${Green}[OK]${Font}"
Error="${Red}[错误]${Font}"

v2ray_conf_dir="/etc/v2ray"
nginx_conf_dir="/etc/nginx/conf/conf.d"
v2ray_conf="${v2ray_conf_dir}/config.json"
nginx_conf="${nginx_conf_dir}/v2ray.conf"
nginx_dir="/etc/nginx"
nginx_openssl_src="/usr/local/src"
nginx_version="1.16.1"
openssl_version="1.1.1d"
#生成伪装路径
camouflage=`cat /dev/urandom | head -n 10 | md5sum | head -c 8`

source /etc/os-release

#从VERSION中提取发行版系统的英文名称，为了在debian/ubuntu下添加相对应的Nginx apt源
VERSION=`echo ${VERSION} | awk -F "[()]" '{print $2}'`

check_system(){
    if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]];then
        echo -e "${OK} ${GreenBG} 当前系统为 Centos ${VERSION_ID} ${VERSION} ${Font}"
        INS="yum"
    elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 8 ]];then
        echo -e "${OK} ${GreenBG} 当前系统为 Debian ${VERSION_ID} ${VERSION} ${Font}"
        INS="apt"
        $INS update
        ## 添加 Nginx apt源
    elif [[ "${ID}" == "ubuntu" && `echo "${VERSION_ID}" | cut -d '.' -f1` -ge 16 ]];then
        echo -e "${OK} ${GreenBG} 当前系统为 Ubuntu ${VERSION_ID} ${UBUNTU_CODENAME} ${Font}"
        INS="apt"
        $INS update
    else
        echo -e "${Error} ${RedBG} 当前系统为 ${ID} ${VERSION_ID} 不在支持的系统列表内，安装中断 ${Font}"
        exit 1
    fi

    systemctl stop firewalld && systemctl disable firewalld
    echo -e "${OK} ${GreenBG} firewalld 已关闭 ${Font}"
}

is_root(){
    if [ `id -u` == 0 ]
        then echo -e "${OK} ${GreenBG} 当前用户是root用户，进入安装流程 ${Font}"
        sleep 3
    else
        echo -e "${Error} ${RedBG} 当前用户不是root用户，请切换到root用户后重新执行脚本 ${Font}" 
        exit 1
    fi
}
judge(){
    if [[ $? -eq 0 ]];then
        echo -e "${OK} ${GreenBG} $1 完成 ${Font}"
        sleep 1
    else
        echo -e "${Error} ${RedBG} $1 失败${Font}"
        exit 1
    fi
}
chrony_install(){
    ${INS} -y install chrony
    judge "安装 chrony 时间同步服务 "

    timedatectl set-ntp true

    if [[ "${ID}" == "centos" ]];then
       systemctl enable chronyd && systemctl restart chronyd
    else
       systemctl enable chrony && systemctl restart chrony
    fi

    judge "chronyd 启动 "

    timedatectl set-timezone Asia/Shanghai

    echo -e "${OK} ${GreenBG} 等待时间同步 ${Font}"
    sleep 10

    chronyc sourcestats -v
    chronyc tracking -v
    date
    read -p "请确认时间是否准确,误差范围±3分钟(Y/N): " chrony_install
    [[ -z ${chrony_install} ]] && chrony_install="Y"
    case $chrony_install in
        [yY][eE][sS]|[yY])
            echo -e "${GreenBG} 继续安装 ${Font}"
            sleep 2
            ;;
        *)
            echo -e "${RedBG} 安装终止 ${Font}"
            exit 2
            ;;
        esac
}

dependency_install(){
    ${INS} install wget git lsof -y

    if [[ "${ID}" == "centos" ]];then
       ${INS} -y install crontabs
    else
       ${INS} -y install cron
    fi
    judge "安装 crontab"

    if [[ "${ID}" == "centos" ]];then
       touch /var/spool/cron/root && chmod 600 /var/spool/cron/root
       systemctl start crond && systemctl enable crond
    else
       touch /var/spool/cron/crontabs/root && chmod 600 /var/spool/cron/crontabs/root
       systemctl start cron && systemctl enable cron

    fi
    judge "crontab 自启动配置 "



    ${INS} -y install bc
    judge "安装 bc"

    ${INS} -y install unzip
    judge "安装 unzip"

    ${INS} -y install qrencode
    judge "安装 qrencode"

    if [[ "${ID}" == "centos" ]];then
       ${INS} -y groupinstall "Development tools"
    else
       ${INS} -y install build-essential
    fi
    judge "编译工具包 安装"

    if [[ "${ID}" == "centos" ]];then
       ${INS} -y install pcre pcre-devel zlib-devel
    else
       ${INS} -y install libpcre3 libpcre3-dev zlib1g-dev
    fi


    judge "nginx 编译依赖安装"

}
basic_optimization(){
    # 最大文件打开数
    sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    echo '* soft nofile 65536' >> /etc/security/limits.conf
    echo '* hard nofile 65536' >> /etc/security/limits.conf

    # 关闭 Selinux
    if [[ "${ID}" == "centos" ]];then
        sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
        setenforce 0
    fi

}

    read -p "请输入Quantumult x端口Port（default:10020，不可为10010、10011、80、443）:" SSx_port
    if [[ -z ${SSx_port} ]]; then
     SSx_port="10020"
    fi
    echo ${SSx_port}

    read -p "请输入Quantumult x路径path（default:/x）:" SSx_path
    if [[ -z ${SSx_path} ]]; then
     SSx_path="/x"
    fi
    echo ${SSx_path}

    read -p "请输入Quantumult x密码password（default:pwd123）:" SSx_pwd
    if [[ -z ${SSx_pwd} ]]; then
     SSx_pwd="pwd123"
    fi
    echo ${SSx_pwd}

    read -p "请输入Quantumult x加密方式method（default:chacha20-ietf）:" SSx_method
    if [[ -z ${SSx_method} ]]; then
     SSx_method="chacha20-ietf"
    fi
    echo ${SSx_method}

    read -p "v2ray plugin路径path（default:/s）:" SSs_path
    if [[ -z ${SSs_path} ]]; then
     SSs_path="/s"
    fi
    echo ${SSs_path}

    read -p "请输入v2ray plugin密码password（default:pwd123）:" SSs_pwd
    if [[ -z ${SSs_pwd} ]]; then
     SSs_pwd="pwd123"
    fi
    echo ${SSs_pwd}

    read -p "请输入v2ray plugin加密方式method（default:chacha20-ietf）:" SSs_method
    if [[ -z ${SSs_method} ]]; then 
     SSs_method="chacha20-ietf"
    fi
    echo ${SSs_method}


v2ray_install(){
    if [[ -d /root/v2ray ]];then
        rm -rf /root/v2ray
    fi
    if [[ -d /etc/v2ray ]];then
        rm -rf /etc/v2ray
    fi
    mkdir -p /root/v2ray && cd /root/v2ray
    wget  --no-check-certificate https://install.direct/go.sh

    ## wget http://install.direct/go.sh
    
    if [[ -f go.sh ]];then
        bash go.sh --force
        judge "安装 V2ray"
    else
        echo -e "${Error} ${RedBG} V2ray 安装文件下载失败，请检查下载地址是否可用 ${Font}"
        exit 4
    fi
    # 清除临时文件
    rm -rf /root/v2ray
}
nginx_install(){
    if [[ -d "/etc/nginx" ]];then
        rm -rf /etc/nginx
    fi

    wget -nc http://nginx.org/download/nginx-${nginx_version}.tar.gz -P ${nginx_openssl_src}
    judge "Nginx 下载"
    wget -nc https://www.openssl.org/source/openssl-${openssl_version}.tar.gz -P ${nginx_openssl_src}
    judge "openssl 下载"

    cd ${nginx_openssl_src}

    [[ -d nginx-"$nginx_version" ]] && rm -rf nginx-"$nginx_version"
    tar -zxvf nginx-"$nginx_version".tar.gz

    [[ -d openssl-"$openssl_version" ]] && rm -rf openssl-"$openssl_version"
    tar -zxvf openssl-"$openssl_version".tar.gz

    [[ -d "$nginx_dir" ]] && rm -rf ${nginx_dir}

    echo -e "${OK} ${GreenBG} 即将开始编译安装 Nginx, 过程稍久，请耐心等待 ${Font}"
    sleep 4

    cd nginx-${nginx_version}
    ./configure --prefix="${nginx_dir}"                         \
            --with-http_ssl_module                              \
            --with-http_gzip_static_module                      \
            --with-http_stub_status_module                      \
            --with-pcre                                         \
            --with-http_realip_module                           \
            --with-http_flv_module                              \
            --with-http_mp4_module                              \
            --with-http_secure_link_module                      \
            --with-http_v2_module                               \
            --with-openssl=../openssl-"$openssl_version"
    judge "编译检查"
    make && make install
    judge "Nginx 编译安装"

    # 修改基本配置
    sed -i 's/#user  nobody;/user  root;/' ${nginx_dir}/conf/nginx.conf
    sed -i 's/worker_processes  1;/worker_processes  3;/' ${nginx_dir}/conf/nginx.conf
    sed -i 's/    worker_connections  1024;/    worker_connections  4096;/' ${nginx_dir}/conf/nginx.conf
    sed -i '$i include conf.d/*.conf;' ${nginx_dir}/conf/nginx.conf



    # 删除临时文件
    rm -rf nginx-"${nginx_version}"
    rm -rf openssl-"${openssl_version}"
    rm -rf ../nginx-"${nginx_version}".tar.gz
    rm -rf ../openssl-"${openssl_version}".tar.gz

    # 添加配置文件夹，适配旧版脚本
    mkdir ${nginx_dir}/conf/conf.d
}
ssl_install(){
    if [[ "${ID}" == "centos" ]];then
        ${INS} install socat nc -y        
    else
        ${INS} install socat netcat -y
    fi
    judge "安装 SSL 证书生成脚本依赖"

    curl  https://get.acme.sh | sh
    judge "安装 SSL 证书生成脚本"
}
domain_check(){
    read -p "请输入你的域名信息(eg:www.bing.com):" domain
    domain_ip=`ping ${domain} -c 1 | sed '1{s/[^(]*(//;s/).*//;q}'`
    echo -e "${OK} ${GreenBG} 正在获取 公网ip 信息，请耐心等待 ${Font}"
    local_ip=`curl -4 ip.sb`
    echo -e "域名dns解析IP：${domain_ip}"
    echo -e "本机IP: ${local_ip}"
    sleep 2
    if [[ $(echo ${local_ip}|tr '.' '+'|bc) -eq $(echo ${domain_ip}|tr '.' '+'|bc) ]];then
        echo -e "${OK} ${GreenBG} 域名dns解析IP  与 本机IP 匹配 ${Font}"
        sleep 2
    else
        echo -e "${Error} ${RedBG} 请确保域名添加了正确的 A 记录，否则将无法正常使用 V2ray"
        echo -e "${Error} ${RedBG} 域名dns解析IP 与 本机IP 不匹配 是否继续安装？（y/n）${Font}" && read install
        case $install in
        [yY][eE][sS]|[yY])
            echo -e "${GreenBG} 继续安装 ${Font}" 
            sleep 2
            ;;
        *)
            echo -e "${RedBG} 安装终止 ${Font}" 
            exit 2
            ;;
        esac
    fi
}

port_exist_check(){
    if [[ 0 -eq `lsof -i:"$1" | grep -i "listen" | wc -l` ]];then
        echo -e "${OK} ${GreenBG} $1 端口未被占用 ${Font}"
        sleep 1
    else
        echo -e "${Error} ${RedBG} 检测到 $1 端口被占用，以下为 $1 端口占用信息 ${Font}"
        lsof -i:"$1"
        echo -e "${OK} ${GreenBG} 5s 后将尝试自动 kill 占用进程 ${Font}"
        sleep 5
        lsof -i:"$1" | awk '{print $2}'| grep -v "PID" | xargs kill -9
        echo -e "${OK} ${GreenBG} kill 完成 ${Font}"
        sleep 1
    fi
}
acme(){
    ~/.acme.sh/acme.sh --issue -d ${domain} --standalone -k ec-256 --force
    if [[ $? -eq 0 ]];then
        echo -e "${OK} ${GreenBG} SSL 证书生成成功 ${Font}"
        sleep 2
        mkdir /data
        ~/.acme.sh/acme.sh --installcert -d ${domain} --fullchainpath /data/v2ray.crt --keypath /data/v2ray.key --ecc
        if [[ $? -eq 0 ]];then
        echo -e "${OK} ${GreenBG} 证书配置成功 ${Font}"
        sleep 2
        fi
    else
        echo -e "${Error} ${RedBG} SSL 证书生成失败 ${Font}"
        exit 1
    fi
}
v2ray_conf_add(){
    touch ${v2ray_conf_dir}/config.json
    cat <<EOF > ${v2ray_conf_dir}/config.json
{
  "log": {
    "access": "/var/log/v2ray/access.log",
    "error": "/var/log/v2ray/error.log",
    "loglevel": "info"
  },
  "inbounds": [
    { 
      "port": 10010,
      "protocol": "dokodemo-door",
      "tag": "wsdoko",
      "settings": {
        "address": "v1.mux.cool",
        "followRedirect": false,
        "network": "tcp"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "${SSs_path}"
        }
      }
    },
    { 
      "port": 10011, 
      "protocol": "shadowsocks",
      "settings": {
        "method": "${SSs_method}",
        "ota": false,
        "password": "${SSs_pwd}",
        "network": "tcp,udp"
      },
      "streamSettings": {
        "network": "domainsocket"
      }
    },
    {  
      "port": ${SSx_port}, 
      "protocol": "shadowsocks",
      "settings": {
        "method": "${SSx_method}",
        "ota": false,
        "password": "${SSx_pwd}",
        "network": "tcp,udp"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "${SSx_path}"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {},
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    },
    { 
      "protocol": "freedom",
      "tag": "ssmux",
      "streamSettings": {
        "network": "domainsocket"
      }
    }
  ], 
  "transport": {
    "dsSettings": {
      "path": "/var/run/ss-loop.sock"
    }
  },
  "routing": {
    "rules": [
      { 
        "type": "field",
        "inboundTag": [
          "wsdoko"
        ],
        "outboundTag": "ssmux"
      },
      {
        "type": "field",
        "ip": [
          "geoip:private"
        ],
        "outboundTag": "blocked"
      }
    ]
  }
}
EOF

judge "V2ray 配置修改"
}

nginx_conf_add(){
    touch ${nginx_conf_dir}/v2ray.conf
    cat <<EOF > ${nginx_conf_dir}/v2ray.conf
    server {
        listen 443 ssl;
        ssl_certificate       /data/v2ray.crt;
        ssl_certificate_key   /data/v2ray.key;
        ssl_protocols         TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
        ssl_ciphers           TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:TLS13-AES-128-CCM-8-SHA256:TLS13-AES-128-CCM-SHA256:EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;
        server_name           ${domain};
        index index.html index.htm;
        root  /home/wwwroot/levis;
        error_page 400 = /400.html;
        location ${SSs_path}
        {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10010;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        }
        location ${SSx_path}
        {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:${SSx_port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        }
    }
    server {
        listen 80;
        server_name ${domain};
        return 301 https://use.shadowsocksr.win\$request_uri;
    }
EOF

judge "Nginx 配置修改"

}

start_process_systemd(){
    ### nginx服务在安装完成后会自动启动。需要通过restart或reload重新加载配置
    systemctl restart nginx
    judge "Nginx 启动"

    systemctl enable nginx
    judge "设置 Nginx 开机自启"

    systemctl restart v2ray
    judge "V2ray 启动"

    systemctl enable v2ray
    judge "设置 v2ray 开机自启"
}

#debian 系 9 10 适配
#rc_local_initialization(){
#    if [[ -f /etc/rc.local ]];then
#        chmod +x /etc/rc.local
#    else
#        touch /etc/rc.local && chmod +x /etc/rc.local
#        echo "#!/bin/bash" >> /etc/rc.local
#        systemctl start rc-local
#    fi
#
#    judge "rc.local 配置"
#}
acme_cron_update(){
    if [[ "${ID}" == "centos" ]];then
        sed -i "/acme.sh/c 0 0 * * 0 systemctl stop nginx && \"/root/.acme.sh\"/acme.sh --cron --home \"/root/.acme.sh\" \
        > /dev/null && systemctl start nginx" /var/spool/cron/root
    else
        sed -i "/acme.sh/c 0 0 * * 0 systemctl stop nginx && \"/root/.acme.sh\"/acme.sh --cron --home \"/root/.acme.sh\" \
        > /dev/null && systemctl start nginx" /var/spool/cron/crontabs/root
    fi
    judge "cron 计划任务更新"
}


show_information(){
    clear
    cd ~

    echo -e "${OK} ${Green} ss+v2ray-plugin/ ss+ws_tls 安装成功" >./v2ray_info.txt
    echo -e "${Red} ss+v2ray-plugin/ ss+ws_tls配置信息 ${Font}" >>./v2ray_info.txt
    echo -e "${Red} ss v2ray-plugin地址（address）:${Font} ${domain} " >>./v2ray_info.txt
    echo -e "${Red} ss v2ray-plugin端口（port）：${Font} 443 " >>./v2ray_info.txt
    echo -e "${Red} ss v2ray-plugin密码（password）：${Font} ${SSs_pwd} " >>./v2ray_info.txt
    echo -e "${Red} ss v2ray-plugin加密方式（method）：${Font} ${SSs_method} " >>./v2ray_info.txt
    echo -e "${Red} ss v2ray-plugin插件（plugin）：${Font} v2ray " >>./v2ray_info.txt
    echo -e "${Red} ss v2ray-plugin插件选项（plugin+）：${Font} tls;host=${domain};path=${SSs_path} " >>./v2ray_info.txt
    echo -e "${Red} ss v2ray-plugin插件参数（plugin++）：${Font} fast-open=false " >>./v2ray_info.txt
    echo -e "${Red} ss+ws_tls（quantumult x）配置：${Font} shadowsocks=${domain}:${SSx_port}, method=${SSx_method}, password=${SSx_pwd}, obfs=ws, obfs-uri=${SSx_path}, fast-open=false, udp-relay=false, tag=ssx"  >>./v2ray_info.txt
    cat ./v2ray_info.txt

}
ssl_judge_and_install(){
    if [[ -f "/data/v2ray.key" && -f "/data/v2ray.crt" ]];then
        echo "证书文件已存在"
    elif [[ -f "~/.acme.sh/${domain}_ecc/${domain}.key" && -f "~/.acme.sh/${domain}_ecc/${domain}.cer" ]];then
        echo "证书文件已存在"
        ~/.acme.sh/acme.sh --installcert -d ${domain} --fullchainpath /data/v2ray.crt --keypath /data/v2ray.key --ecc
        judge "证书应用"
    else
        ssl_install
        acme
    fi
}
nginx_systemd(){
    cat>/lib/systemd/system/nginx.service<<EOF
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=syslog.target network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
PIDFile=/etc/nginx/logs/nginx.pid
ExecStartPre=/etc/nginx/sbin/nginx -t
ExecStart=/etc/nginx/sbin/nginx -c ${nginx_dir}/conf/nginx.conf
ExecReload=/etc/nginx/sbin/nginx -s reload
ExecStop=/bin/kill -s QUIT \$MAINPID
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

judge "Nginx systemd ServerFile 添加"
}
main(){
    is_root
    check_system
    chrony_install
    dependency_install
    basic_optimization
    domain_check
    port_alterid_set
    v2ray_install
    port_exist_check 80
    port_exist_check ${port}
    nginx_install
    v2ray_conf_add
    nginx_conf_add
    web_camouflage

    #将证书生成放在最后，尽量避免多次尝试脚本从而造成的多次证书申请
    ssl_judge_and_install
    nginx_systemd
    show_information
    start_process_systemd
    acme_cron_update
}

main

