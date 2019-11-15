### 用v2ray原生安装，适用于普通ss v2ray-plugin以及ss ws [Quantumult X(IOS)/Kitsunebi(Andriod)]
安装v2ray, 同时适配普通 shadowsocks v2ray-plugin 和shadowsocks ws [Quantumult X/Kitsunebi（即 mux=0 ）]的方案

### 目前支持Debian 9+ / Ubuntu 18.04+ / Centos7+

## V2ray core 更新方式
执行：
`bash <(curl -L -s https://install.direct/go.sh)`

（ 来源参考 ：[V2ray官方说明](https://www.v2ray.com/chapter_00/install.html)）
* 如果为最新版本，会输出提示并停止安装。否则会自动更新
* 未来会将相关内容集成到本脚本中并进行交互式操作更新

## 注意事项
* 该程序依赖 Nginx 实现相关功能，请使用 [LNMP](https://lnmp.org) 或其他类似携带 Nginx 脚本安装过 Nginx 的用户特别留意，使用本脚本可能会导致无法预知的错误（未测试，若存在，后续版本可能会处理本问题）。
* V2Ray 的部分功能依赖于系统时间，请确保您使用V2RAY程序的系统 UTC 时间误差在三分钟之内，时区无关。
* 本 bash 依赖于 [V2ray 官方安装脚本](https://install.direct/go.sh) 及 [acme.sh](https://github.com/Neilpang/acme.sh) 工作。
* Centos 系统用户请预先在防火墙中放行程序相关端口（默认：80，443）
## 准备工作
* 准备一个域名，并将A记录添加好。
* 一些需要的软件
```
sudo apt update && sudo apt upgrade
sudo apt install vim curl wget
```
* Quantumult X端口不可为443、80、10010、10011
## 安装方式
ss_v2ray-plugin_ws-tls
```
bash <(curl -L -s https://raw.githubusercontent.com/MurrddoL/ss-v2ray-plugin_ss-ws/master/install.sh) | tee v2ray_ins.log
```
### 启动方式

启动 ss(V2ray)：`systemctl start v2ray`

停止 ss(V2ray)：`systemctl stop v2ray`

重启 ss(V2ray)：`sudo service v2ray restart`

状态查询 ss(V2ray)：`sudo service v2ray status`

启动 Nginx：`systemctl start nginx`

停止 Nginx：`systemctl stop nginx`

重启 Nginx：`sudo service Nginx restart`

状态查询 Nginx：`sudo service Nginx status`

### 如安装失败，可一键重装为纯净系统后再安装：下例为ubuntu16.04，重装大概需20分钟以上，切勿在vps页面重启/停止等操作，以免失联
```
bash <(wget --no-check-certificate -qO- 'https://moeclub.org/attachment/LinuxShell/InstallNET.sh') -u 16.04 -v 64 -a -firmware
```
默认root密码是：MoeClub.org
其他系统可见https://moeclub.org/2018/04/03/603/



### 相关目录

Web 目录：`/home/wwwroot/levis`

V2ray 服务端配置：`/etc/v2ray/config.json`

V2ray 客户端配置: `执行安装时所在目录下的 v2ray_info.txt`

Nginx 配置目录： `/etc/nginx/conf/conf.d/v2ray.conf`

证书目录: `/data/v2ray.key 和 /data/v2ray.crt`

### 查看客户端配置
`cat v2ray_info.txt` 

### 可选，安装BBR加速

```
wget --no-check-certificate https://github.com/teddysun/across/raw/master/bbr.sh
chmod +x bbr.sh
./bbr.sh 
```

### 更新说明

...

V1.0
* 1.测试可用

# 参考与借鉴 

https://github.com/wulabing/V2Ray_ws-tls_bash_onekey

http://www.xuxiaobo.com/?p=5950

https://github.com/v2ray/discussion/issues/173

https://github.com/crossutility/Quantumult-X/blob/master/v2ray-ss-ws-tls.json

https://moeclub.org/2018/04/03/603/

https://teddysun.com/489.html



