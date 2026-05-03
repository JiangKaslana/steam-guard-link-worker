# Steam Guard Link Worker

一个可以部署到 Cloudflare Workers 的 Steam Guard 分享链接生成器。

访问者在首页粘贴 Steam Guard 密钥、maFile JSON、Base32 密钥、Base64 `shared_secret`，或者 `otpauth://totp/Steam:...` 链接。页面会在浏览器本地生成一个分享链接：

```text
https://你的域名/密文#解密钥
```

其他人打开完整链接后，页面会把加密文本和解密钥提交给 Worker。Worker 临时解密并计算 Steam Guard 5 位验证码，只把验证码返回给浏览器。

## 重点

- 不需要数据库。
- 不需要 `LINK_SECRET`。
- 不需要把 Steam 密钥放到 Cloudflare 环境变量或机密里。
- Worker 不存储 Steam 密钥。
- 访问者浏览器不会拿到明文 Steam 密钥。
- Worker 作为临时解密和验证码生成工具，只返回当前验证码。
- 支持可选访问密码。
- 支持通过环境变量设置背景图片。
- 默认是粉色背景。

## 安全模型

这个版本是“前端生成加密链接，Worker 临时解密生成验证码”的模型：

- `/密文` 是加密后的 Steam 密钥数据。
- `#解密钥` 是解密钥。浏览器正常请求页面时不会把 `#` 后面的内容发给服务器。
- 为了生成验证码，页面会把 `/密文` 和 `#解密钥` 通过 `POST /api/token` 发给 Worker。
- Worker 在请求期间临时解密 Steam 密钥，生成 Steam Guard 5 位验证码，然后只返回验证码。
- Worker 不会把明文 Steam 密钥返回给浏览器，也不会持久化保存。
- 拿到完整链接的人可以查看验证码。
- 只拿到 `/密文`、没有 `#解密钥` 的人无法生成验证码。

请不要把真实生成的完整链接发到 Issue、截图、日志或公开仓库里。完整链接本身就是访问凭证。

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

启动后 Wrangler 通常会输出：

```text
http://127.0.0.1:8787
```

打开这个地址，粘贴 Steam Guard 密钥或 `otpauth://` 链接，即可生成分享链接。

## Cloudflare Workers 部署

方式一：Wrangler 部署。

```bash
npm install
npx wrangler deploy
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

方式二：Cloudflare 控制台。

1. 新建 Worker。
2. 把 `worker.js` 全文复制进去。
3. 不需要任何必填环境变量。
4. 需要密码就添加 `ACCESS_PASSWORD` 和 `SESSION_SECRET`。
5. 需要背景图就添加 `BACKGROUND_IMAGE_URL`。
6. 部署。

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
https://你的域名/密文#解密钥
```

访问这个完整链接即可查看自动刷新的 Steam Guard 5 位验证码。浏览器端不会显示或保存明文 Steam 密钥。

## 测试

```bash
npm test
```
