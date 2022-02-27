# dissector-manscdp

Wireshark dissector for GB/T 28181 MANSCDP protocol.

Wireshark GB/T 28181 协议解析插件.

## 使用说明

### 安装

1. 将 `manscdp-xxx.dtd` 拷贝到 `wireshark` `dtd` 文件所在目录, 如: `/usr/share/wireshark/dtds/`;
1. 将 `GBT28181.lua` 拷贝到 `wireshark` 插件所在目录, 如: `$HOME/.local/lib/wireshark/plugins`;

### 使用

TODO: 待后续根据使用场景补充示例.

基本引用方式:
1. `query.cmdtype == "Catelog"`: 过滤查询目录请求;
1. `reponse.cmdtype == "Catelog"`: 过滤查询目录回复请求;

## 关于 [XML](https://wiki.wireshark.org/XML) 部分解析

Wireshark 支持通过根据 DTD 格式定义解析 XML 内容.
但一个 DTD 只能有一个根节点, 而 `MANSCDP` 有四个, 分别为: `Control`, `Query`, `Notify` 和 `Response`.
只能分别定义到不同的 DTD 文件中.
