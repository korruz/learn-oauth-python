# OAuth 2.1 授权码 + PKCE 数据流转解析

本文档基于本项目实际代码，解析 OAuth 2.1 授权码流程（Authorization Code Flow with PKCE）中**每一步传输了什么数据、为什么这样传、以及安全意义**。

## 一、三个角色

| 角色 | 端口 | 代码位置 | 职责 |
|---|---|---|---|
| **Client**（客户端应用） | 8080 | `src/client/main.py` | 发起授权、保管 PKCE verifier、换取并使用令牌 |
| **Authorization Server**（授权服务器） | 8081 | `src/auth_server/` | 认证用户、签发授权码与访问令牌 |
| **Resource Server**（资源服务器） | 8082 | `src/resource_server/` | 校验 Bearer 令牌、提供受保护资源 |

角色分离是 OAuth 的核心：**资源服务器永远不接触用户密码**，它只认令牌。

## 二、完整时序

```
用户浏览器          Client(8080)        AuthServer(8081)      ResourceServer(8082)
    │                    │                     │                      │
    │  1.点击开始         │                     │                      │
    ├───────────────────>│                     │                      │
    │                    │ 生成 verifier/challenge                    │
    │                    │ 生成 state          │                      │
    │  2.302 跳转 /authorize?challenge&state   │                      │
    │<───────────────────┤                     │                      │
    │  3.GET /authorize (携带 challenge, state)│                      │
    ├─────────────────────────────────────────>│                      │
    │  4.返回登录表单                           │                      │
    │<─────────────────────────────────────────┤                      │
    │  5.POST /login (用户名+密码)              │                      │
    ├─────────────────────────────────────────>│                      │
    │                    │      存储 code ─> challenge 绑定关系        │
    │  6.302 跳回 /callback?code=xxx&state=xxx │                      │
    │<─────────────────────────────────────────┤                      │
    │  7.GET /callback?code&state              │                      │
    ├───────────────────>│                     │                      │
    │                    │ 校验 state(防CSRF)  │                      │
    │                    │                     │                      │
    │                    │ 8.POST /token       │                      │
    │                    │  (code + verifier)  │                      │
    │                    ├────────────────────>│                      │
    │                    │      校验 SHA256(verifier)==challenge      │
    │                    │ 9.返回 access_token │                      │
    │                    │<────────────────────┤                      │
    │                    │                     │                      │
    │                    │ 10.GET /protected (Authorization: Bearer)  │
    │                    ├──────────────────────────────────────────> │
    │                    │ 11.返回受保护资源                           │
    │                    │<──────────────────────────────────────────┤
```

## 三、逐步数据解析

### 步骤 1-2：客户端生成 PKCE 与 state

代码：`src/client/main.py` → `start_oauth_flow()`，`src/shared/crypto_utils.py` → `PKCEGenerator`

```python
verifier = base64url(random_bytes(32))        # 43 字符，客户端私密保存
challenge = base64url(SHA256(verifier))       # 派生值，可公开传输
state = secrets.token_urlsafe(...)            # CSRF 防护随机数
```

存入服务端 session（**不放在 URL 里**）：

| 数据 | 存放位置 | 是否公开 |
|---|---|---|
| `code_verifier` | Client session | ❌ 绝不外传（直到步骤 8） |
| `code_challenge` | 随 URL 传输 | ✅ 公开 |
| `state` | Client session + URL | ✅ 公开但需比对 |

> **PKCE 的本质**：先寄出「锁」（challenge），最后才出示「钥匙」（verifier）。攻击者即使窃取 challenge，因 SHA256 不可逆，也推不出 verifier。

### 步骤 3-4：授权请求

`GET http://localhost:8081/authorize` 携带 7 个参数：

```
client_id=demo-client
redirect_uri=http://localhost:8080/callback
scope=read
state=<随机值>
code_challenge=<SHA256派生值>
code_challenge_method=S256
response_type=code
```

服务端校验后渲染登录页（`src/auth_server/routes.py:authorize_endpoint`）。注意此时**尚未产生任何凭据**，只是把参数透传到登录表单的隐藏字段中。

`code_challenge_method` 固定为 `S256`：OAuth 2.1 已废弃 `plain` 方法（明文传 verifier 等于没有保护）。

### 步骤 5-6：用户认证与授权码签发

`POST /login`（`application/x-www-form-urlencoded`）→ `src/auth_server/routes.py:login_endpoint`

密码校验走 bcrypt（`src/shared/security.py`）：

```python
bcrypt.checkpw(password.encode()[:72], stored_hash.encode())
```

认证成功后，`AuthCodeStore.store_code()` 生成授权码并**绑定关键上下文**：

```python
code -> {
    client_id, user_id, scope,
    code_challenge,      # ← 关键：把 challenge 绑到 code 上
    redirect_uri,
    expires_at           # 10 分钟
}
```

然后 302 跳转：`http://localhost:8080/callback?code=xxx&state=xxx`

> **为什么先给 code 而不直接给 token？**
> 授权码经由**浏览器地址栏**传递，会残留在历史记录、Referer、服务器日志中。所以它被设计成：短期有效（10 分钟）、一次性使用、且必须配合 verifier 才能兑换。令牌则走后端直连通道，不经过浏览器。

### 步骤 7：回调与 state 校验

`src/client/main.py:oauth_callback`

```python
if session_state != state:      # 不一致则拒绝
    return error("invalid_state", "Possible CSRF attack")
```

> **state 防的是 CSRF**：攻击者诱导你的浏览器带上*他的*授权码访问回调，从而把你的账号绑定到他的身份。state 与 session 绑定，攻击者无法伪造。
>
> 注意区分：**state 防 CSRF，PKCE 防授权码拦截**，二者不可互相替代。

### 步骤 8-9：令牌交换（关键一步）

`POST http://localhost:8081/token`，**Content-Type 必须是 `application/x-www-form-urlencoded`**（RFC 6749 §4.1.3）：

```
grant_type=authorization_code
code=<步骤6拿到的授权码>
redirect_uri=http://localhost:8080/callback
client_id=demo-client
code_verifier=<步骤1生成的原始verifier>   ← 此刻才首次出示
```

授权服务器执行 5 重校验（`src/auth_server/routes.py:token_endpoint`）：

1. `grant_type` 必须为 `authorization_code`
2. 授权码存在、未过期、**未被使用过**（一次性）
3. `client_id` 与签发时一致
4. `redirect_uri` 与签发时一致
5. **PKCE 校验**：`SHA256(code_verifier) == 存储的 code_challenge`

第 5 步使用常量时间比较，防时序攻击：

```python
secrets.compare_digest(expected_challenge, challenge)
```

全部通过后返回：

```json
{
  "access_token": "<43字符随机串>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read"
}
```

### 步骤 10-11：访问受保护资源

`GET http://localhost:8082/protected`，令牌放在**请求头**而非 URL：

```
Authorization: Bearer <access_token>
```

> 放 header 而非 query string，是为了避免令牌泄漏进日志、Referer 与浏览器历史。

资源服务器（`src/resource_server/middleware.py:validate_bearer_token`）解析并校验格式后放行。

## 四、安全机制总览

| 攻击手段 | 防护机制 | 代码位置 |
|---|---|---|
| 授权码被拦截后盗用 | **PKCE**：无 verifier 无法兑换 | `crypto_utils.py:verify_challenge` |
| CSRF / 会话嫁接 | **state** 参数比对 | `client/main.py:oauth_callback` |
| 授权码重放 | **一次性使用** + 10 分钟过期 | `storage.py:AuthCodeStore` |
| 令牌重定向劫持 | `redirect_uri` **精确匹配** | `routes.py:token_endpoint` |
| 密码泄漏 | **bcrypt** 加盐哈希（cost=12） | `shared/security.py` |
| 时序攻击 | `secrets.compare_digest` 常量时间比较 | `crypto_utils.py` |
| 密码触达第三方 | 用户只在授权服务器输入密码 | 架构层面 |

## 五、凭据生命周期对照

| 凭据 | 产生方 | 传输通道 | 有效期 | 可重用 |
|---|---|---|---|---|
| `code_verifier` | Client | 仅步骤 8（后端直连） | 单次流程 | ❌ |
| `code_challenge` | Client | URL（公开） | 单次流程 | ❌ |
| `state` | Client | URL（公开） | 单次流程 | ❌ |
| `authorization_code` | AuthServer | **浏览器重定向** | 10 分钟 | ❌ 一次性 |
| `access_token` | AuthServer | **后端直连 + 请求头** | 3600 秒 | ✅ 有效期内 |

## 六、本次修复的问题

| 问题 | 现象 | 根因 | 修复 |
|---|---|---|---|
| 令牌端点 415/422 | `token_exchange_failed` status 422 | `/token` 声明 Pydantic 模型 → 期望 JSON；但客户端按 RFC 发送 form-urlencoded | `auth_server/main.py` 改用 `Form(...)` 接收 |
| 资源服务器 500 | `/protected` 报 500 | 读取含非 ASCII 的资源文件未指定编码，中文 Windows 下按 GBK 解码失败 | 显式 `encoding="utf-8"`，并扩展异常捕获 |
| 登录永远失败 | 凭据正确仍提示无效 | passlib 1.7.4 探测 `bcrypt.__about__`，bcrypt 4.1+ 已移除该属性；异常被 `except Exception` 吞掉 | 改为直接调用 `bcrypt`，显式处理 72 字节截断 |
| 模板渲染崩溃 | `TypeError: unhashable type: 'dict'` | Starlette 1.4 移除 `TemplateResponse(name, context)` 旧签名 | 全部改为 `TemplateResponse(request, name, context)` |

## 七、遗留问题（未修改，供决策）

1. **访问令牌未持久化**：`token_endpoint` 用 `secrets.token_urlsafe(32)` 生成令牌后**未存储**；资源服务器的 `validate_bearer_token` 也只校验格式，**任何格式正确的字符串都能通过**（`middleware.py:216` 注释已说明这是 demo 简化）。生产环境必须引入令牌存储或改用 JWT 签名校验。
2. **`validate_scope` 不接受冒号**：`SCOPE_PATTERN` 未包含 `:`，导致 `user:email` 这类标准 scope 被判非法（`tests/test_security.py::test_validate_scope_valid` 因此失败）。
3. **无 refresh_token 流程**：模型已定义字段，但未实现签发与刷新端点。
4. **端口 8080 被占用**：当前被一个无关的 `python -m http.server` 进程占据，客户端应用无法启动。
