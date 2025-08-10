## Mosdns-x

Mosdns-x 是一个用 Go 编写的高性能 DNS 转发器，支持运行插件流水线，用户可以按需定制 DNS 处理逻辑。

**支持监听与请求以下类型的 DNS：**

* UDP
* TCP
* DNS over TLS - DoT
* DNS over QUIC - DoQ
* DNS over HTTP/2 - DoH
* DNS over HTTP/3 - DoH3

功能概述、配置方式、教程，详见：[wiki](https://github.com/pmkol/mosdns-x/wiki)

下载预编译文件、更新日志，详见：[release](https://github.com/pmkol/mosdns-x/releases)

#### 电报社区：

**[Mosdns-x Group](https://t.me/mosdns)**

#### 关联项目：

**[easymosdns](https://github.com/pmkol/easymosdns)**

适用于 Linux 的辅助脚本。借助 Mosdns-x，仅需几分钟即可搭建一台支持 ECS 的无污染 DNS 服务器。内置中国大陆地区的优化规则，满足DNS日常使用场景，开箱即用。

**[mosdns-v4](https://github.com/IrineSistiana/mosdns/tree/v4)**

一个插件化的 DNS 转发器。是 Mosdns-x 的上游项目。
