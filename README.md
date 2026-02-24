# ✨cpp-phira-mp✨

✨基于 [phira-mp](https://github.com/TeamFlos/phira-mp) 重新开发的C++版phira-mp，新增 Web 后台管理、REST API、SSE 实时事件、封禁系统、管理密码、WebSocket Secure 实时数据流和连接欢迎信息。✨

## 特点

### 1. 后台 Web 管理面板（含密码保护）
- 浏览器访问 `http://服务器IP:12345/admin`
- **登录认证**：首次运行默认密码 `admin123`，请立即修改
- **密码管理**：面板内可直接修改管理密码，密码持久化存储于 `admin_password.txt`
- 查看所有房间列表、房间状态、玩家人数及列表
- 实时刷新（每5秒自动更新）
- 一键解散任意房间
- 一键踢出房间内任意玩家
- 封禁/解封玩家 ID（封禁后连接时显示「你已被封禁」提示）
- 封禁列表持久化存储在 `banned.txt`

### 2. API

| 接口 | 说明 |
|------|------|
| `GET /api/rooms/info` | 获取所有房间列表及完整数据 |
| `GET /api/rooms/info/<n>` | 获取指定名称房间信息 |
| `GET /api/rooms/user/<user_id>` | 获取指定用户所在房间信息 |
| `GET /api/rooms/listen` | SSE 实时事件流 |

#### SSE 事件类型
| 事件 | 说明 |
|------|------|
| `snapshot` | 连接时自动发送当前所有房间快照 |
| `create_room` | 新房间创建 |
| `update_room` | 房间数据更新（状态、铺面、锁定、轮换等变化） |
| `join_room` | 用户加入房间 |
| `leave_room` | 用户离开房间 |
| `player_score` | 玩家完成游戏（含完整成绩记录） |
| `start_round` | 房间开始新一轮游戏 |

SSE 连接内建 15 秒心跳保活机制，防止连接被中间件或防火墙断开。

### 3. WebSocket实时数据流（实验性功能）
- 为游玩中的房间提供 WSS 服务，实时推送玩家的 TouchFrame 和 JudgeEvent
- 连接格式：`wss://[服务器IP]:[WSS端口]/[房间ID]/[玩家ID]`
- 默认 WSS 端口：7785
- 需要 TLS 证书（通过命令行参数 `--tls-cert` 和 `--tls-key` 指定）

#### WSS 数据格式
连接成功后会收到确认消息：
```json
{"type":"connected","room":"room-id","player":12345}
```

TouchFrame 实时推送：
```json
{
  "type": "touch_frame",
  "room": "room-id",
  "player": 12345,
  "data": [
    {
      "time": 1.234,
      "points": [
        {"id": 0, "x": 0.5, "y": 0.3}
      ]
    }
  ]
}
```

JudgeEvent 实时推送：
```json
{
  "type": "judge_event",
  "room": "room-id",
  "player": 12345,
  "data": [
    {
      "time": 1.234,
      "line_id": 0,
      "note_id": 1,
      "judgement": "Perfect"
    }
  ]
}
```

Judgement 类型：`Perfect`, `Good`, `Bad`, `Miss`, `HoldPerfect`, `HoldGood`

### 4. 连接欢迎信息
- 用户认证成功后自动发送欢迎消息
- 显示 QQ 群号：1049578201
- 展示当前可加入的房间列表（仅显示选图中且未锁定的房间）

---

## 编译前准备

```bash
# 更新包列表
sudo apt update

# 安装编译工具和依赖
sudo apt install -y build-essential g++ uuid-dev curl libssl-dev
```

### 所需依赖清单
| 依赖 | Ubuntu 包名 | 用途 |
|------|------------|------|
| G++ (>=10) | `build-essential` / `g++` | C++20 编译器 |
| uuid-dev | `uuid-dev` | UUID 生成 |
| curl | `curl` | HTTP 请求（获取 Phira API 数据） |
| make | `build-essential` | 构建工具 |
| OpenSSL | `libssl-dev` | TLS/SSL 支持（WSS 服务） |

---

## 编译

```bash
cd cpp-phira-mp-main
make clean
make
```

编译成功后生成 `phira-mp-server` 可执行文件。

---

## 下载

你可以前往本项目的[Github Actions](../../../actions)，下载已编译好可直接运行的 `exe` 和二进制文件。


---

## 运行

```bash
# 默认端口运行（游戏端口 12346，Web 端口 12345，WSS 端口 7785）
./phira-mp-server

# 自定义端口
./phira-mp-server -p 12346 -w 8080 -s 7785

# 指定 TLS 证书
./phira-mp-server --tls-cert /path/to/cert.pem --tls-key /path/to/key.pem

# 后台运行
nohup ./phira-mp-server -p 12346 -w 12345 -s 7785 \
  --tls-cert /etc/ssl/certs/server.crt \
  --tls-key /etc/ssl/private/server.key \
  > server.log 2>&1 &
```

### 命令行参数
| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-p, --port` | 游戏服务器端口 | 12346 |
| `-w, --web-port` | Web 管理/API 端口 | 12345 |
| `-s, --wss-port` | WebSocket Secure 端口 | 7785 |
| `--tls-cert` | TLS 证书文件路径 | /etc/ssl/certs/server.crt |
| `--tls-key` | TLS 私钥文件路径 | /etc/ssl/private/server.key |
| `-h, --help` | 显示帮助 | - |

---

## 文件结构

```
cpp-phira-mp-main/
├── include/
│   ├── ban_manager.h      # 封禁管理
│   ├── binary_protocol.h  # 二进制协议
│   ├── commands.h          # 命令定义
│   ├── http_client.h       # HTTP 客户端
│   ├── l10n.h              # 本地化
│   ├── room.h              # 房间 + 轮次历史
│   ├── server.h            # 服务器 + get_state()
│   ├── session.h           # 会话
│   ├── web_server.h        # [修改] Web 服务器（含密码管理）
│   └── ws_server.h         # [新增] WebSocket Secure 服务器
├── src/
│   ├── http_client.cpp
│   ├── l10n.cpp
│   ├── main.cpp            # [修改] 主入口 + WSS 启动
│   ├── room.cpp            # 轮次记录 + SSE
│   ├── server.cpp
│   ├── session.cpp         # [修改] WSS 广播 + SSE 修复
│   ├── web_server.cpp      # [修改] 密码管理 + SSE 修复
│   └── ws_server.cpp       # [新增] WSS 服务器实现
├── locales/
│   ├── en-US.ftl
│   ├── zh-CN.ftl
│   └── zh-TW.ftl
├── Makefile                # [修改] 新增 OpenSSL 依赖
└── README.md
```

### 运行时文件
- `banned.txt` — 封禁玩家 ID 列表（自动创建/管理）
- `admin_password.txt` — 管理密码（自动创建，默认 admin123）
- `server_config.yml` — 服务器配置（可选）

---

## API 使用示例

```bash
# 获取所有房间
curl http://localhost:12345/api/rooms/info

# 获取指定房间
curl http://localhost:12345/api/rooms/info/my-room

# 获取用户所在房间
curl http://localhost:12345/api/rooms/user/12345

# 监听实时事件（SSE）
curl http://localhost:12345/api/rooms/listen

# 登录管理面板（获取 token）
curl -X POST http://localhost:12345/admin/login \
  -H 'Content-Type: application/json' -d '{"password": "admin123"}'

# 封禁玩家（需要 admin_token cookie）
curl -X POST http://localhost:12345/admin/ban \
  -H 'Content-Type: application/json' \
  -b 'admin_token=YOUR_TOKEN' \
  -d '{"user_id": 12345}'

# 解封玩家
curl -X POST http://localhost:12345/admin/unban \
  -H 'Content-Type: application/json' \
  -b 'admin_token=YOUR_TOKEN' \
  -d '{"user_id": 12345}'

# 解散房间
curl -X POST http://localhost:12345/admin/dissolve \
  -H 'Content-Type: application/json' \
  -b 'admin_token=YOUR_TOKEN' \
  -d '{"room": "room-name"}'

# 踢出玩家
curl -X POST http://localhost:12345/admin/kick \
  -H 'Content-Type: application/json' \
  -b 'admin_token=YOUR_TOKEN' \
  -d '{"room":"room-name","user_id":12345}'

# 修改管理密码
curl -X POST http://localhost:12345/admin/change_password \
  -H 'Content-Type: application/json' \
  -b 'admin_token=YOUR_TOKEN' \
  -d '{"old_password":"admin123","new_password":"newpass"}'
```

### WSS 连接示例（JavaScript）

```javascript
const ws = new WebSocket('wss://your-server:7785/room-id/12345');

ws.onopen = () => console.log('WSS connected');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if (data.type === 'touch_frame') {
    console.log('Touch frames:', data.data);
  } else if (data.type === 'judge_event') {
    console.log('Judge events:', data.data);
  }
};

ws.onclose = () => console.log('WSS disconnected');
```

---

## QQ 群

**1049578201**

## 协议

使用 **MIT** 协议。