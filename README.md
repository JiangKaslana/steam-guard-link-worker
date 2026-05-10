# Steam Guard Link Worker

一个可以部署到 Cloudflare Workers 的 Steam Guard 分享链接生成器。

访问者在首页粘贴 Steam Guard 密钥、maFile JSON、Base32 密钥、Base64 `shared_secret`，或者 `otpauth://totp/Steam:...` 链接。页面会在浏览器本地生成一个分享链接：

```text
https://你的域名/id.密文#解密钥
```

其他人打开完整链接后，页面会把加密文本和解密钥提交给 Worker。Worker 临时解密并计算 Steam Guard 5 位验证码，只把验证码返回给浏览器。

## 重点

- 默认不需要数据库，也可以可选绑定 KV 或 D1 做更强的过期/撤销校验。
- 不需要 `LINK_SECRET`。
- 不需要把 Steam 密钥放到 Cloudflare 环境变量或机密里。
- Worker 不存储 Steam 密钥。
- 访问者浏览器不会拿到明文 Steam 密钥。
- Worker 作为临时解密和验证码生成工具，只返回当前验证码。
- 支持可选访问密码。
- 支持链接自动过期，默认 30 分钟。
- 支持通过环境变量设置背景图片。
- 默认是粉色背景
- 强烈建议使用Cloudflare Worker部署

## 安全模型

这个版本是“前端生成加密链接，Worker 临时解密生成验证码”的模型：

- `/id.密文` 里，`id` 是链接格式标记，`密文` 是加密后的 Steam 密钥数据。
- `#解密钥` 是解密钥。浏览器正常请求页面时不会把 `#` 后面的内容发给服务器。
- 为了生成验证码，页面会把 `/密文` 和 `#解密钥` 通过 `POST /api/token` 发给 Worker。
- Worker 在请求期间临时解密 Steam 密钥，生成 Steam Guard 5 位验证码，然后只返回验证码。
- Worker 不会把明文 Steam 密钥返回给浏览器，也不会持久化保存。
- 默认过期时间是 30 分钟。无数据库模式下，过期时间写在加密内容里，Worker 解密后检查 `expiresAt`。
- 可选 KV/D1 模式下，Worker 还会在后端状态里校验链接 ID、密文哈希和过期时间；后端状态不保存 Steam 密钥，也不保存 `#解密钥`。
- 拿到完整链接的人可以查看验证码。
- 只拿到 `/密文`、没有 `#解密钥` 的人无法生成验证码。

请不要把真实生成的完整链接发到 Issue、截图、日志或公开仓库里。完整链接本身就是访问凭证。

## 过期机制

本项目有两种过期模式。

默认无数据库模式：

- 不需要 KV、D1 或数据库。
- 生成链接时，浏览器把 `expiresAt` 写进加密内容。
- Worker 临时解密后检查 `expiresAt`，超过时间就拒绝返回验证码。
- 这种模式能让原始链接到期失效，但懂技术的人如果已经拿到完整链接，理论上可以用同一密钥重新构造一份新的加密内容。

可选 KV 模式：

- 需要绑定 Cloudflare Workers KV，绑定名为 `LINK_KV`。
- 生成链接时，Worker 在 KV 中保存 `id`、密文哈希和过期时间。
- 查看验证码时，Worker 必须先通过 KV 校验。
- 到期、记录不存在、密文哈希不匹配都会拒绝解析。
- KV 不保存 Steam 密钥，也不保存解密钥。
- 这种模式适合轻量部署。

可选 D1 数据库模式：

- 需要绑定 Cloudflare D1，绑定名为 `LINK_DB`。
- 生成链接时，Worker 在 D1 中保存 `id`、密文哈希、过期时间和创建时间。
- 查看验证码时，Worker 必须先通过 D1 校验。
- 到期、记录不存在、密文哈希不匹配都会拒绝解析。
- D1 不保存 Steam 密钥，也不保存解密钥。
- 这种模式更适合后续扩展管理、审计、撤销等功能。

如果同时绑定 KV 和 D1，Worker 会优先使用 D1。

## 适用场景

这个工具更适合在完全可信任的小范围内，临时共享 Steam Guard 验证码访问能力，而不是公开分发或面向陌生人使用。

例如：

- 你和朋友共同维护一个测试用 Steam 账号
- 需要让可信任的人临时帮忙登录、排查、配置或维护账号
- 不想直接把 Steam Guard 原始密钥发给对方
- 希望分享链接可以设置过期时间，到期自动失效

这个项目的目标不是鼓励随意共享账号，而是在自托管、熟人协作、小团队使用的场景里，提供一个比“直接发送原始密钥”更克制的方案。

## 为什么不用直接发密钥

直接发送 Steam Guard 原始密钥风险很高。一旦泄露，对方可能长期生成验证码。

这个工具的思路是：

- 部署者不必把 Steam Guard 原始密钥存到固定后端机密里
- 使用者生成一个带有效期的分享链接
- 访问者只能通过链接获取当前验证码
- Worker 只在请求期间临时解密并返回验证码
- 可以结合 KV 或 D1 做更强的服务端过期和校验

这样做不能消除所有风险，但通常比直接把原始密钥发给别人要更克制一些。

## 免责声明

本项目是一个自托管的 Steam Guard 验证码辅助工具，仅供个人学习、研究和自用场景使用。

使用者应自行确认自己有权使用相关 Steam Guard 密钥，并自行承担因部署、分享、泄露链接、配置错误、服务器被入侵、浏览器环境不安全、第三方访问完整分享链接等原因造成的账号风险、财产损失或其他后果。

项目作者和部署者不保存、索取或主动收集任何 Steam 账号密码，但完整分享链接可以用于获取验证码。任何人拿到完整分享链接，都可能在有效期内查看验证码。请不要把真实链接分享给不可信的人，也不要把真实链接提交到 GitHub、Issue、日志、截图、论坛或聊天记录中。

本项目与 Valve、Steam 无关联，也不是 Steam 官方产品。使用本项目即表示你理解并接受上述风险。

## 文件说明

- `worker.js`：完整的 Cloudflare Worker 单文件版本，可以直接复制到 Workers 控制台。
- `wrangler.toml`：Wrangler 部署配置。
- `.dev.vars.example`：本地开发环境变量示例。
- `test/worker.test.js`：基础测试。

## 环境变量

全部都是可选项。

设置访问密码后，打开创建页面或分享页面都需要先登录。不设置则没有密码：

```text
ACCESS_PASSWORD=你的访问密码
```

用于签名登录 Cookie。不设置时会使用 `ACCESS_PASSWORD` 作为回退：

```text
SESSION_SECRET=另一串很长的随机字符
```

设置页面背景图链接：

```text
BACKGROUND_IMAGE_URL=https://example.com/background.jpg
```

设置链接有效期，单位分钟。默认 30，设置为 0 表示永久：

```text
LINK_TTL_MINUTES=30
```

可选 D1 数据库绑定：

```text
LINK_DB
```

可选 KV 绑定：

```text
LINK_KV
```

## 本地部署

要求：

- Node.js 18 或更新版本。
- npm。
- 第一次 `npm install` 需要联网。

步骤：

```bash
cd steam-guard-link-worker
npm install
copy .dev.vars.example .dev.vars
npm run dev
```

Linux 或 macOS 用：

```bash
cp .dev.vars.example .dev.vars
```

如果不需要密码和背景图，`.dev.vars` 可以保持空值。

如果本地想生成永久链接，可以把 `.dev.vars` 里的有效期设为永久：

```text
LINK_TTL_MINUTES="0"
```

启动后 Wrangler 通常会输出：

```text
http://127.0.0.1:8787
```

打开这个地址，粘贴 Steam Guard 密钥或 `otpauth://` 链接，即可生成分享链接。

本地 KV 模式可以使用 Wrangler 的本地 KV。先创建 KV namespace 并把绑定写入 `wrangler.toml`，绑定名必须是 `LINK_KV`：

```bash
npx wrangler kv namespace create LINK_KV
```

`wrangler.toml` 示例：

```toml
[[kv_namespaces]]
binding = "LINK_KV"
id = "你的 kv namespace id"
```

本地 D1 模式可以使用 Wrangler 的本地 D1。先创建数据库并把绑定写入 `wrangler.toml`，绑定名必须是 `LINK_DB`：

```bash
npx wrangler d1 create steam-guard-link-worker
```

`wrangler.toml` 示例：

```toml
[[d1_databases]]
binding = "LINK_DB"
database_name = "steam-guard-link-worker"
database_id = "你的 database_id"
```

## Cloudflare Workers 部署

方式一：Wrangler 部署。

```bash
npm install
npx wrangler deploy
```

如果要启用 D1 数据库模式：

```bash
npx wrangler d1 create steam-guard-link-worker
```

然后把输出的 `database_id` 填进 `wrangler.toml`：

```toml
[[d1_databases]]
binding = "LINK_DB"
database_name = "steam-guard-link-worker"
database_id = "你的 database_id"
```

表结构会由 Worker 自动创建：

```sql
CREATE TABLE IF NOT EXISTS links (
  id TEXT PRIMARY KEY,
  payload_hash TEXT NOT NULL,
  expires_at INTEGER,
  created_at INTEGER NOT NULL
);
```

如果要启用 KV 模式：

```bash
npx wrangler kv namespace create LINK_KV
```

然后把输出的 `id` 填进 `wrangler.toml`：

```toml
[[kv_namespaces]]
binding = "LINK_KV"
id = "你的 kv namespace id"
```

如果要设置访问密码：

```bash
npx wrangler secret put ACCESS_PASSWORD
npx wrangler secret put SESSION_SECRET
```

如果要设置背景图片：

```bash
npx wrangler secret put BACKGROUND_IMAGE_URL
```

如果要永久链接：

```bash
npx wrangler secret put LINK_TTL_MINUTES
```

填入：

```text
0
```

方式二：Cloudflare 控制台。

1. 新建 Worker。
2. 把 `worker.js` 全文复制进去。
3. 不需要任何必填密钥。
4. 如需 KV 模式，在 Cloudflare 控制台创建 KV 并绑定到 Worker，绑定名为 `LINK_KV`。
5. 如需 D1 模式，在 Cloudflare 控制台创建 D1 并绑定到 Worker，绑定名为 `LINK_DB`。
6. 需要密码就添加 `ACCESS_PASSWORD` 和 `SESSION_SECRET`。
7. 需要背景图就添加 `BACKGROUND_IMAGE_URL`。
8. 需要永久链接就添加 `LINK_TTL_MINUTES=0`。
9. 部署。

## 使用方式

首页支持粘贴这些格式：

```text
otpauth://totp/Steam:account?secret=BASE32_SECRET&issuer=Steam
```

maFile JSON：

```json
{
  "account_name": "main",
  "shared_secret": "BASE64_SHARED_SECRET"
}
```

也可以直接粘贴原始 Base64 `shared_secret` 或 Base32 secret。

生成后会得到一个类似：

```text
https://你的域名/id.密文#解密钥
```

访问这个完整链接即可查看自动刷新的 Steam Guard 5 位验证码。浏览器端不会显示或保存明文 Steam 密钥。

## 测试

```bash
npm test
```
