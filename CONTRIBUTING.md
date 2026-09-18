# 贡献指南

```bash
cd authtoken && go vet ./... && go test ./...   # 验签模块
cd .. && go vet ./... && go test ./...           # 扩展模块（依赖 authtoken）
go build ./example                               # 集成示例须保持可编译
```

## 红线

- **fail-closed**：`AUTHBRIDGE_SHARED_SECRET` 缺省/过短时扩展整体不挂载——
  任何改动不得让无密钥的部署泄漏签发路径。
- **superuser 永不签发**：服务 token 只代表应用用户。
- **声明集只含身份**（iss/sub/iat/exp/jti）：不加权限、不加 PII——token 会进日志。
- `authtoken` 保持零 PocketBase 依赖；扩展模块不得把 PB 类型泄进 authtoken 的 API。
- 验签语义变更（新增声明/算法）必须是**可兼容旧 token**的，或升主版本并写迁移说明。

## 路线图欢迎的形状

- 非对称模式（RS256 + JWKS 端点，验签方只持公钥）；
- `jti` 撤销名单（denylist）挂钩；
- `aud` 受众声明（多受众部署时的重放防护）。

## 提交

一个逻辑步骤一个提交，`feat:` / `fix:` / `docs:` / `chore:` / `security:`；
签名提交（`git commit -s`，DCO）。
