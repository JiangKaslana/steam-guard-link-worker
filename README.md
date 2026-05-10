# Steam Guard Link Worker

一个可以部署到 Cloudflare Workers 的 Steam Guard 分享链接生成器。

访问者在首页粘贴 Steam Guard 密钥、maFile JSON、Base32 密钥、Base64 `shared_secret`，或者 `otpauth://totp/Steam:...` 链接。页面会在浏览器本地加密生成一个分享链接：

```text
https://你的域名/id.密文#解密钥
其他人打开完整链接后，页面会把加密文本和解密钥提交给 Worker。Worker 临时解密并计算 Steam Guard 5 位验证码，只把验证码返回给浏览器。

✨ 主要功能
端到端加密分享：前端使用随机 AES‑GCM 密钥加密 Steam 令牌数据；解密密钥只存在于 URL 的 # 片段中，浏览器不会将其发送至服务器。

可选链接密码：可为单个链接设置独立密码，访问者必须输入正确密码才能查看动态验证码。

自定义有效期：生成链接时可单独指定有效期（分钟），设为 0 永久有效，留空则使用全局默认值。

二维码展示：生成链接后自动显示二维码，方便移动端扫码访问。

服务端二次封装（可选）：配置 LINK_SECRET 后，服务端会在客户端加密之上再加一层 AES‑GCM 封装，进一步提高安全性。

访问密码保护：主页面可设置全局访问密码，所有页面（生成页、查看页）均需登录。

过期与撤销：支持无状态（仅客户端过期）、KV 和 D1 三种过期校验模式；KV/D1 模式下可服务端强制过期或撤销。

轻量部署：默认无需数据库，Worker 单文件即可运行。

🔐 安全模型
/id.密文 中的 密文 是加密后的 Steam 令牌数据。

#解密钥 是客户端随机生成的 AES‑GCM 密钥。浏览器请求页面时不会将 # 之后的内容发送给服务器。

查看验证码时，前端通过 POST /api/token 将 密文 和 解密钥 一起发送给 Worker。

Worker 在请求期间临时解密，生成当前 5 位 Steam Guard 验证码，并只返回验证码。Worker 不存储 Steam 密钥，也不返回明文密钥。

如果配置了 LINK_SECRET，服务端会在客户端密文外层再进行一次 AES‑GCM 加密，服务端解封后才能得到客户端密文，而客户端密钥仍在 # 片段中。

链接过期时间可设置在加密数据中（无状态模式）或由服务端存储（KV/D1）强制检查。

链接密码的哈希值存储在 KV 或 D1 中，不包含 Steam 密钥。

拿到完整链接（含 # 密钥）且知道链接密码的人才能看到验证码；仅获得 密文 部分无法生成验证码。

警告：完整链接本身就是访问凭证，请勿将其公开在 Issue、日志、截图或聊天记录中。

⏱ 过期机制
生成链接时可以指定有效期（分钟），覆盖全局默认设置。

无状态模式（无 KV/D1）：过期时间加密在 payload 内，Worker 解密后检查 expiresAt。

KV 模式：过期时间、密文哈希、密码哈希存储在 Cloudflare KV 中，到期自动删除。

D1 模式：结构与 KV 类似，适合需要查询、审计、批量撤销的场景。

若同时绑定 KV 和 D1，优先使用 D1。

📦 环境变量
所有变量为可选，无需设置即可运行基础功能。

变量名	说明	默认值
ACCESS_PASSWORD	访问主页面所需密码	无（无需密码）
SESSION_SECRET	会话 Cookie 签名密钥	回退至 ACCESS_PASSWORD
BACKGROUND_IMAGE_URL	页面背景图片链接	无
LINK_TTL_MINUTES	全局默认链接有效期（分钟），0 表示永久	30
LINK_SECRET / SERVER_SECRET	服务端二次加密密钥	无（不启用）
REQUIRE_LINK_SECRET	强制所有链接使用服务端加密（true/1/yes/on）	false
D1 绑定：LINK_DB	用于存储链接元数据的 D1 数据库	无
KV 绑定：LINK_KV 或 LINK_STORE	用于存储链接元数据的 KV 命名空间	无
注意：链接密码功能必须配置 KV 或 D1 存储；无存储时密码将被忽略。

🚀 部署
Cloudflare Workers（推荐）
登录 Cloudflare Dashboard。

进入 Workers & Pages → 创建应用程序 → 创建 Worker。

将 worker.js 的全部代码粘贴到编辑器中。

（可选）设置环境变量或绑定 KV/D1。

点击 部署。

通过 Wrangler 部署
bash
npm install
npx wrangler deploy
需要 KV 或 D1 时请按文档在 wrangler.toml 中绑定。

D1 数据库初始化
若使用 D1 且需要链接密码功能，请确保表包含 password_hash 字段。新版 Worker 会自动创建带该字段的表；若已有旧表，请手动执行：

sql
ALTER TABLE links ADD COLUMN password_hash TEXT DEFAULT NULL;
🧩 使用方式
生成分享链接
打开主页面（如果设置了 ACCESS_PASSWORD 需先登录）。

（可选）填写显示名称。

在文本区粘贴 Steam 令牌信息，支持：

otpauth://totp/Steam:account?secret=BASE32_SECRET&issuer=Steam

maFile JSON（含 shared_secret）

纯 Base64 shared_secret 或 Base32 密钥

（可选）设置有效期（留空使用全局默认）。

（可选）输入链接密码（需已配置 KV 或 D1）。

点击 生成链接。

复制生成的完整链接（或扫描二维码）分享给需要的人。

查看动态验证码
在浏览器中打开分享链接。

若链接设置了密码，页面会弹出输入框，输入正确密码后显示验证码。

验证码每 30 秒自动刷新，点击“复制”可将当前码复制到剪贴板。

🛠 本地开发
bash
npm install
cp .dev.vars.example .dev.vars
npm run dev
启动后访问 http://127.0.0.1:8787。

⚠️ 免责声明
本项目仅为个人学习、研究及自用设计，不鼓励账号共享。使用者应确保有权管理相关 Steam 令牌，并自行承担因部署、分享、泄露或配置错误导致的一切风险。项目作者不保存、不收集任何 Steam 账户信息。完整分享链接可被用于查看验证码，切勿泄露给不可信方。本项目与 Valve、Steam 无任何关联。
