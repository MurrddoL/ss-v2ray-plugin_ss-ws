### 查看客户端配置
放在执行脚本所在目录下的 v2ray_info.txt

推荐使用 `cat v2ray_info.txt` 查看

### V2ray 简介

* V2Ray是一个优秀的开源网络代理工具，可以帮助你畅爽体验互联网，目前已经全平台支持Windows、Mac、Android、IOS、Linux等操作系统的使用。
* 已安装的用户，当出现无法连接的情况时，请用户根据该文档更新 V2ray core 
* 请注意：我们依然强烈建议你全方面的了解整个程序的工作流程及原理


### 目前支持Debian 9+ / Ubuntu 18.04+ / Centos7+

## V2ray core 更新方式
执行：
`bash <(curl -L -s https://install.direct/go.sh)`

（ 来源参考 ：[V2ray官方说明](https://www.v2ray.com/chapter_00/install.html)）
* 如果为最新版本，会输出提示并停止安装。否则会自动更新
* 未来会将相关内容集成到本脚本中并进行交互式操作更新

## 注意事项
* 推荐在纯净环境下使用本脚本，如果你是新手，请不要使用Centos系统。
* 在尝试本脚本确实可用之前，请不要将本程序应用于生产环境中。
* 该程序依赖 Nginx 实现相关功能，请使用 [LNMP](https://lnmp.org) 或其他类似携带 Nginx 脚本安装过 Nginx 的用户特别留意，使用本脚本可能会导致无法预知的错误（未测试，若存在，后续版本可能会处理本问题）。
* V2Ray 的部分功能依赖于系统时间，请确保您使用V2RAY程序的系统 UTC 时间误差在三分钟之内，时区无关。
* 本 bash 依赖于 [V2ray 官方安装脚本](https://install.direct/go.sh) 及 [acme.sh](https://github.com/Neilpang/acme.sh) 工作。
* Centos 系统用户请预先在防火墙中放行程序相关端口（默认：80，443）
## 准备工作
* 准备一个域名，并将A记录添加好。
* [V2ray官方说明](https://www.v2ray.com/)，了解 TLS WebSocket 及 V2ray 相关信息
* 安装好 curl
## 安装方式
ss_v2ray-plugin_ws-tls
```
bash <(curl -L -s https://raw.githubusercontent.com/MurrddoL/ss_v2ray-plugin_ws-tls/master/install.sh | tee v2ray_ins.log
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



### 相关目录

Web 目录：`/home/wwwroot/levis`

V2ray 服务端配置：`/etc/v2ray/config.json`

V2ray 客户端配置: `执行安装时所在目录下的 v2ray_info.txt`

Nginx 配置目录： `/etc/nginx/conf/conf.d/v2ray.conf`

证书目录: `/data/v2ray.key 和 /data/v2ray.crt`

### 更新说明

...

V1.0（beta）
* 1.测试用



