# 第三方组件与许可证

pocketbase-authbridge 自身以 [Apache-2.0](LICENSE) 发布。本仓库两个模块的构建（go.mod 依赖）
所涉及的第三方组件：

| 组件 | 许可证 | 用于 |
| --- | --- | --- |
| [PocketBase](https://github.com/pocketbase/pocketbase) v0.40.4 | MIT | 根模块（签发扩展）的宿主框架 |
| [golang-jwt/jwt](https://github.com/golang-jwt/jwt) v5 | MIT | `authtoken` 模块的 JWT 签名/验签 |

`authtoken` 模块刻意只依赖 golang-jwt（零 PocketBase 依赖），资源服务引入它不会
把身份平面拖进依赖图。完整传递依赖以各 `go.mod` / `go.sum` 为准。
