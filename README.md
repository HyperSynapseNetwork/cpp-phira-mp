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

### 3. 本程序可搭配 [phira-web-monitor](https://github.com/HyperSynapseNetwork/phira-web/monitor)进行观战。

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
sudo apt install -y build-essential g++ pkg-config uuid-dev curl libssl-dev libboost-dev libspdlog-dev libargon2-dev nlohmann-json3-dev libcurl4-openssl-dev
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
cd cpp-phira-mp
make clean
make
```

编译成功后生成 `phira-mp-server` 可执行文件。

---

## 下载

你可以前往本项目的[Github Actions](../../actions)，下载已编译好可直接运行的 `exe` 和二进制文件。


---

## 运行

```bash
# 默认端口运行（默认为游戏端口 12346，Web/api 端口 12347，后台管理密码 admin）
./phira-mp-server

# 自定义端口
./phira-mp-server --port 12346 --http-port 12347 --admin-password PASSWORD

```

### 命令行参数
| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--port` | 游戏服务器端口 | 12346 |
| `--http-port` | Web 管理/API 端口 | 12347 |
| `--admin-password` | 后台管理密码 | admin |
| `-h, --help` | 显示帮助 | - |

---

## 文件结构

```
cpp-phira-mp-main/
├── include/
│   ├── binary.hpp          # 二进制协议
│   ├── command.hpp         # 命令定义
│   ├── http_server.hpp     # HTTP 客户端
│   ├── l10n.hpp            # 本地化
│   ├── room.hpp            # 房间 + 轮次历史
│   ├── server.hpp          # 服务器 + get_state()
│   ├── session.hpp         # 会话
│   ├── stream.hpp          # 触摸信息流
├── src/
│   ├── binary.cpp          # 二进制协议实现
│   ├── command.cpp         # 命令实现
│   ├── http_server.cpp     # web/api实现
│   ├── l10n.cpp            # 本地化实现
│   ├── main.cpp            # 主入口
│   ├── room.cpp            # 主逻辑实现
│   ├── server.cpp          # 服务器
│   ├── session.cpp         # 主逻辑实现
│   └── stream.cpp          # [新增] 观战协议
├── locales/
│   ├── en-US.ftl
│   ├── zh-CN.ftl
│   └── zh-TW.ftl
├── Makefile
├── CMakeLists.txt
└── README.md
```

### 运行时文件
- `banned_user.txt` — 封禁玩家 ID 列表（自动创建/管理）

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

```


---

## QQ 群

**1049578201**

## 协议

使用 **MIT** 协议。
