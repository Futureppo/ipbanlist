# IPBanList

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)](https://go.dev/)
[![Gin](https://img.shields.io/badge/Gin-1.10-00A86B)](https://gin-gonic.com/)
[![SQLite](https://img.shields.io/badge/SQLite-GORM-003B57?logo=sqlite)](https://www.sqlite.org/)

轻量级、高性能的云端 IP 黑名单系统，适用于低配置服务器。  
提供 Web 管理界面和高性能 IP 查询 API，支持 Docker 一键部署。

## 项目结构

```text
.
├─ main.go
├─ static/
│  └─ index.html
├─ Dockerfile
├─ docker-compose.yml
├─ go.mod
└─ go.sum
```

## 快速开始

### 拉取仓库

```bash
git clone https://github.com/Futureppo/ipbanlist.git
cd ipbanlist
```

### 方式一：Docker Compose（推荐）

```bash
docker compose up -d --build
```

服务启动后访问：

- Web 管理台：`http://localhost:8080`
- 健康检查：`http://localhost:8080/healthz`

默认管理员密码：

- `admin`

### 方式二：本地运行

```bash
go mod tidy
go run main.go
```

## 环境变量

| 变量名 | 默认值 | 说明 |
|---|---|---|
| `PORT` | `8080` | 服务监听端口 |
| `DB_PATH` | `data/ipban.db` | SQLite 数据库文件路径 |
| `ADMIN_PASS` | `admin` | 管理员登录密码 |
| `GIN_MODE` | `release`（容器中） | Gin 运行模式 |

## 数据模型

### `blacklists` 表

- `id` (uint, PK)
- `ip` (string, unique)
- `reason` (string)
- `created_at` (datetime)
- `updated_at` (datetime)

### `configs` 表

- `key` (string, PK)
- `value` (string)
- `created_at` (datetime)
- `updated_at` (datetime)

当前用于持久化 `api_key` 配置项。

## 认证说明

### 管理端认证

1. 调用 `POST /admin/login` 提交密码
2. 服务端返回 HttpOnly Cookie（`ipban_admin_session`）
3. 后续访问 `/admin/*`（除登录）自动带 Cookie

### 客户端 API 认证（X-API-KEY）

请求头必须包含：

```text
X-API-KEY: <your_api_key>
```

服务端会对比数据库中的 `api_key` 值。

## API 文档

### 公共接口

### `GET /healthz`

健康检查。

返回示例：

```json
{"status":"ok"}
```

### 客户端查询接口（需 `X-API-KEY`）

### `GET /api/v1/ips`

仅返回 IP 字符串数组，带宽最省。

```json
["1.1.1.1","2.2.2.2"]
```

> 性能优化：后端使用 `Pluck("ip")` 只查询 `ip` 列，避免读取整行字段，降低 SQLite I/O 与响应体积。

### `GET /api/v1/details`

返回完整明细（IP、原因、创建时间、更新时间）。

```json
[
  {
    "ip":"1.1.1.1",
    "reason":"ddos",
    "created_at":"2026-02-08T00:00:00Z",
    "updated_at":"2026-02-08T00:00:00Z"
  }
]
```

### 管理接口（需登录 Cookie）

### `POST /admin/login`

请求：

```json
{"password":"admin"}
```

### `POST /admin/logout`

退出登录并清除会话 Cookie。

### `GET /admin/stats`

返回黑名单总数：

```json
{"count":12}
```

### `GET /admin/list?page=1&page_size=20`

分页查询。

### `POST /admin/add`

新增黑名单 IP。

请求：

```json
{"ip":"1.1.1.1","reason":"scanner"}
```

重复 IP 会返回 `409 Conflict`。

### `PUT /admin/update`

按 `id` 或 `ip` 更新原因。

请求示例（按 id）：

```json
{"id":1,"reason":"updated reason"}
```

请求示例（按 ip）：

```json
{"ip":"1.1.1.1","reason":"updated reason"}
```

### `DELETE /admin/delete`

按 `id` 或 `ip` 删除。

请求示例：

```json
{"id":1}
```

### `GET /admin/config/key`

获取当前 API Key：

```json
{"api_key":"xxxxx"}
```

### `PUT /admin/config/key`

轮换或自定义 API Key。

- 空请求体或 `{"api_key":""}`：自动生成新随机 Key
- 自定义 Key：长度至少 16

请求示例：

```json
{"api_key":"your-custom-api-key-1234"}
```

## 前端说明

- 文件位置：`static/index.html`
- 技术：Vue 3 + Element Plus（CDN）
- 功能：
  - 登录页
  - 总数统计
  - API Key 查看/复制/轮换/自定义
  - 黑名单表格分页
  - 新增、编辑、删除
  - 亮色/暗色切换

## Docker 部署说明

### 构建

```bash
docker build -t ipbanlist:latest .
```

### 运行

```bash
docker run -d \
  --name ipbanlist \
  -p 8080:8080 \
  -e ADMIN_PASS=yourStrongPass \
  -e DB_PATH=/app/data/ipban.db \
  -v ipban_data:/app/data \
  ipbanlist:latest
```

`docker-compose.yml` 已内置相同能力，可直接使用。

## License

MIT
