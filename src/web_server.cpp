#include "web_server.h"
#include "server.h"
#include "ban_manager.h"
#include <iostream>
#include <sstream>
#include <cstring>
#include <algorithm>
#include <fstream>
#include <random>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

WebServer* g_web_server = nullptr;

// ── Login Page HTML ──────────────────────────────────────────────────
static const char* LOGIN_HTML = R"LOGINHTML(
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Phira MP - 管理登录</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1923;color:#e0e0e0;min-height:100vh;display:flex;justify-content:center;align-items:center}
.login-box{background:#1a2a3a;border-radius:16px;padding:40px;width:380px;border:1px solid #ffffff10;box-shadow:0 8px 32px rgba(0,0,0,0.4)}
.login-box h1{text-align:center;color:#00d4ff;font-size:22px;margin-bottom:8px}
.login-box .subtitle{text-align:center;color:#7aa;font-size:13px;margin-bottom:30px}
.form-group{margin-bottom:20px}
.form-group label{display:block;color:#7aa;font-size:13px;margin-bottom:6px}
.form-group input{width:100%;background:#0a1520;border:1px solid #ffffff20;color:#e0e0e0;padding:12px 16px;border-radius:8px;font-size:14px;outline:none;transition:border-color .2s}
.form-group input:focus{border-color:#00d4ff}
.login-btn{width:100%;padding:12px;background:#00d4ff;color:#0d1b2a;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;transition:all .2s}
.login-btn:hover{background:#00b8e0;transform:translateY(-1px)}
.error-msg{color:#ff4444;text-align:center;margin-top:16px;font-size:13px;display:none}
.first-time{text-align:center;color:#7aa;font-size:12px;margin-top:16px}
</style>
</head>
<body>
<div class="login-box">
  <h1>Phira MP 后台管理</h1>
  <div class="subtitle">请输入管理密码以继续</div>
  <div class="form-group">
    <label>管理密码</label>
    <input type="password" id="password" placeholder="输入密码" onkeydown="if(event.key==='Enter')doLogin()">
  </div>
  <button class="login-btn" onclick="doLogin()">登 录</button>
  <div class="error-msg" id="error"></div>
  <div class="first-time" id="first-time-hint"></div>
</div>
<script>
async function doLogin(){
  const pw=document.getElementById('password').value;
  if(!pw){showErr('请输入密码');return}
  try{
    const r=await fetch('/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});
    const d=await r.json();
    if(d.ok){window.location.href='/admin'}
    else{showErr(d.error||'密码错误')}
  }catch(e){showErr('登录失败')}
}
function showErr(m){const e=document.getElementById('error');e.textContent=m;e.style.display='block';setTimeout(()=>e.style.display='none',3000)}
</script>
</body>
</html>
)LOGINHTML";

// ── Admin Panel HTML ────────────────────────────────────────────────
static const char* ADMIN_HTML = R"ADMINHTML(
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Phira MP - 后台管理</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:#0f1923;color:#e0e0e0;min-height:100vh}
.header{background:linear-gradient(135deg,#1a2a3a 0%,#0d1b2a 100%);padding:20px 30px;border-bottom:2px solid #00d4ff;display:flex;align-items:center;justify-content:space-between}
.header h1{font-size:24px;color:#00d4ff;font-weight:700}
.header .subtitle{color:#7aa;font-size:13px;margin-top:2px}
.header-right{display:flex;align-items:center;gap:12px}
.header .qq{background:#1a3a4a;padding:8px 16px;border-radius:8px;color:#00d4ff;font-size:13px;border:1px solid #00d4ff33}
.header .logout-btn{background:#ff444433;padding:8px 16px;border-radius:8px;color:#ff6666;font-size:13px;border:1px solid #ff444444;cursor:pointer;text-decoration:none;transition:all .2s}
.header .logout-btn:hover{background:#ff444455}
.container{max-width:1400px;margin:0 auto;padding:20px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:20px}
@media(max-width:900px){.grid{grid-template-columns:1fr}}
.card{background:#1a2a3a;border-radius:12px;border:1px solid #ffffff10;overflow:hidden}
.card-header{padding:16px 20px;background:#0d1b2a;border-bottom:1px solid #ffffff10;display:flex;justify-content:space-between;align-items:center}
.card-header h2{font-size:16px;color:#00d4ff}
.card-body{padding:20px}
.stats{display:flex;gap:20px;margin-bottom:20px}
.stat{background:#0d1b2a;padding:16px 24px;border-radius:10px;text-align:center;flex:1;border:1px solid #ffffff08}
.stat .num{font-size:32px;font-weight:700;color:#00d4ff}
.stat .label{font-size:12px;color:#7aa;margin-top:4px}
.room-item{background:#0d1b2a;border-radius:8px;padding:14px 18px;margin-bottom:10px;border:1px solid #ffffff08;transition:border-color .2s}
.room-item:hover{border-color:#00d4ff33}
.room-name{font-weight:600;color:#fff;font-size:15px}
.room-meta{display:flex;gap:16px;margin-top:6px;font-size:12px;color:#7aa;flex-wrap:wrap}
.room-meta span{display:inline-flex;align-items:center;gap:4px}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}
.badge-green{background:#00ff8822;color:#00ff88}
.badge-yellow{background:#ffaa0022;color:#ffaa00}
.badge-red{background:#ff444422;color:#ff4444}
.badge-blue{background:#00d4ff22;color:#00d4ff}
.players-list{margin-top:8px;padding-left:12px}
.player-tag{display:inline-block;background:#1a3a4a;padding:3px 10px;border-radius:12px;font-size:12px;margin:2px 4px 2px 0;color:#cde}
.btn{padding:6px 14px;border:none;border-radius:6px;cursor:pointer;font-size:12px;font-weight:600;transition:all .2s}
.btn:hover{transform:translateY(-1px);filter:brightness(1.2)}
.btn-danger{background:#ff4444;color:#fff}
.btn-warn{background:#ff8800;color:#fff}
.btn-primary{background:#00d4ff;color:#0d1b2a}
.btn-sm{padding:4px 10px;font-size:11px}
.input{background:#0a1520;border:1px solid #ffffff20;color:#e0e0e0;padding:8px 12px;border-radius:6px;font-size:13px;outline:none;transition:border-color .2s}
.input:focus{border-color:#00d4ff}
.input-group{display:flex;gap:8px;margin-bottom:12px}
.input-group .input{flex:1}
.ban-item{display:flex;justify-content:space-between;align-items:center;background:#0d1b2a;padding:10px 14px;border-radius:6px;margin-bottom:6px;border:1px solid #ffffff08}
.ban-id{font-family:monospace;color:#ff8888;font-size:14px}
.empty{text-align:center;color:#556;padding:30px;font-size:14px}
.toast{position:fixed;top:20px;right:20px;background:#1a3a4a;border:1px solid #00d4ff;padding:12px 20px;border-radius:8px;color:#00d4ff;font-size:13px;z-index:9999;opacity:0;transition:opacity .3s;pointer-events:none}
.toast.show{opacity:1}
.refresh-btn{background:none;border:1px solid #00d4ff44;color:#00d4ff;padding:4px 12px;border-radius:6px;cursor:pointer;font-size:12px}
.refresh-btn:hover{background:#00d4ff11}
.pw-section{margin-top:12px;padding-top:12px;border-top:1px solid #ffffff10}
.pw-section h3{font-size:14px;color:#7aa;margin-bottom:8px}
</style>
</head>
<body>
<div class="header">
  <div>
    <h1>Phira MP 后台管理</h1>
    <div class="subtitle">多人游戏服务器管理面板</div>
  </div>
  <div class="header-right">
    <div class="qq">QQ群: 1049578201</div>
    <a class="logout-btn" href="#" onclick="doLogout();return false">退出登录</a>
  </div>
</div>
<div class="container">
  <div class="stats">
    <div class="stat"><div class="num" id="s-rooms">0</div><div class="label">活跃房间</div></div>
    <div class="stat"><div class="num" id="s-players">0</div><div class="label">在线玩家</div></div>
    <div class="stat"><div class="num" id="s-bans">0</div><div class="label">已封禁</div></div>
  </div>
  <div class="grid">
    <div class="card">
      <div class="card-header">
        <h2>房间列表</h2>
        <button class="refresh-btn" onclick="loadRooms()">刷新</button>
      </div>
      <div class="card-body" id="rooms-list"><div class="empty">加载中...</div></div>
    </div>
    <div class="card">
      <div class="card-header">
        <h2>封禁管理</h2>
        <button class="refresh-btn" onclick="loadBans()">刷新</button>
      </div>
      <div class="card-body">
        <div class="input-group">
          <input class="input" id="ban-input" placeholder="输入玩家 Phira ID" type="number">
          <button class="btn btn-danger" onclick="banPlayer()">封禁</button>
        </div>
        <div id="bans-list"><div class="empty">加载中...</div></div>
        <div class="pw-section">
          <h3>修改管理密码</h3>
          <div class="input-group">
            <input class="input" id="old-pw" placeholder="当前密码" type="password">
          </div>
          <div class="input-group">
            <input class="input" id="new-pw" placeholder="新密码" type="password">
          </div>
          <div class="input-group">
            <input class="input" id="new-pw2" placeholder="确认新密码" type="password">
          </div>
          <button class="btn btn-warn" onclick="changePassword()">修改密码</button>
        </div>
      </div>
    </div>
  </div>
</div>
<div class="toast" id="toast"></div>
<script>
function toast(msg){const t=document.getElementById('toast');t.textContent=msg;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2500)}
function stateText(s){return{'SELECTING_CHART':'选图中','WAITING_FOR_READY':'准备中','PLAYING':'游玩中'}[s]||s}
function stateBadge(s){const m={'SELECTING_CHART':'badge-green','WAITING_FOR_READY':'badge-yellow','PLAYING':'badge-red'};return m[s]||'badge-blue'}
async function loadRooms(){
  try{
    const r=await fetch('/admin/api/rooms');
    if(r.status===401){window.location.href='/admin/login';return}
    const d=await r.json();
    document.getElementById('s-rooms').textContent=d.length;
    let total=0;d.forEach(rm=>total+=rm.data.users.length);
    document.getElementById('s-players').textContent=total;
    const c=document.getElementById('rooms-list');
    if(!d.length){c.innerHTML='<div class="empty">暂无活跃房间</div>';return}
    let h='';
    d.forEach(rm=>{
      const st=rm.data.state;
      h+=`<div class="room-item">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <span class="room-name">${esc(rm.name)}</span>
          <div>
            <span class="badge ${stateBadge(st)}">${stateText(st)}</span>
            <button class="btn btn-danger btn-sm" style="margin-left:8px" onclick="dissolveRoom('${esc(rm.name)}')">解散</button>
          </div>
        </div>
        <div class="room-meta">
          <span>房主: ${rm.data.host}</span>
          <span>人数: ${rm.data.users.length}/8</span>
          <span>锁定: ${rm.data.lock?'是':'否'}</span>
          <span>轮换: ${rm.data.cycle?'是':'否'}</span>
          ${rm.data.chart?`<span>铺面: ${rm.data.chart}</span>`:''}
        </div>
        <div class="players-list">
          ${rm.data.users.map(uid=>`<span class="player-tag">${uid} <a href="#" onclick="kickPlayer('${esc(rm.name)}',${uid});return false" style="color:#f66;text-decoration:none;margin-left:4px" title="踢出">✕</a></span>`).join('')}
        </div>
      </div>`;
    });
    c.innerHTML=h;
  }catch(e){console.error(e);toast('加载房间失败')}
}
async function loadBans(){
  try{
    const r=await fetch('/admin/api/bans');
    if(r.status===401){window.location.href='/admin/login';return}
    const d=await r.json();
    document.getElementById('s-bans').textContent=d.length;
    const c=document.getElementById('bans-list');
    if(!d.length){c.innerHTML='<div class="empty">暂无封禁玩家</div>';return}
    let h='';d.forEach(id=>{
      h+=`<div class="ban-item"><span class="ban-id">ID: ${id}</span><button class="btn btn-primary btn-sm" onclick="unbanPlayer(${id})">解封</button></div>`;
    });
    c.innerHTML=h;
  }catch(e){console.error(e);toast('加载封禁列表失败')}
}
async function dissolveRoom(name){
  if(!confirm('确认解散房间 "'+name+'" ?'))return;
  try{
    const r=await fetch('/admin/dissolve',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({room:name})});
    if(r.status===401){window.location.href='/admin/login';return}
    const d=await r.json();toast(d.message||'操作完成');loadRooms();
  }catch(e){toast('操作失败')}
}
async function kickPlayer(room,uid){
  if(!confirm('确认将玩家 '+uid+' 踢出房间?'))return;
  try{
    const r=await fetch('/admin/kick',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({room:room,user_id:uid})});
    if(r.status===401){window.location.href='/admin/login';return}
    const d=await r.json();toast(d.message||'操作完成');loadRooms();
  }catch(e){toast('操作失败')}
}
async function banPlayer(){
  const inp=document.getElementById('ban-input');const id=parseInt(inp.value);
  if(!id){toast('请输入有效的玩家ID');return}
  try{
    const r=await fetch('/admin/ban',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user_id:id})});
    if(r.status===401){window.location.href='/admin/login';return}
    const d=await r.json();toast(d.message||'操作完成');inp.value='';loadBans();
  }catch(e){toast('操作失败')}
}
async function unbanPlayer(id){
  if(!confirm('确认解封玩家 '+id+' ?'))return;
  try{
    const r=await fetch('/admin/unban',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user_id:id})});
    if(r.status===401){window.location.href='/admin/login';return}
    const d=await r.json();toast(d.message||'操作完成');loadBans();
  }catch(e){toast('操作失败')}
}
async function changePassword(){
  const oldPw=document.getElementById('old-pw').value;
  const newPw=document.getElementById('new-pw').value;
  const newPw2=document.getElementById('new-pw2').value;
  if(!oldPw||!newPw){toast('请填写所有密码字段');return}
  if(newPw!==newPw2){toast('两次输入的新密码不一致');return}
  if(newPw.length<4){toast('新密码至少4个字符');return}
  try{
    const r=await fetch('/admin/change_password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({old_password:oldPw,new_password:newPw})});
    const d=await r.json();
    if(d.ok){toast('密码修改成功');document.getElementById('old-pw').value='';document.getElementById('new-pw').value='';document.getElementById('new-pw2').value=''}
    else{toast(d.error||'修改失败')}
  }catch(e){toast('操作失败')}
}
async function doLogout(){
  try{await fetch('/admin/logout',{method:'POST'})}catch(e){}
  window.location.href='/admin/login';
}
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}
loadRooms();loadBans();
setInterval(loadRooms,5000);
setInterval(loadBans,15000);
</script>
</body>
</html>
)ADMINHTML";

// ── Helpers ─────────────────────────────────────────────────────────

static std::string url_decode(const std::string& s) {
    std::string r;
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == '%' && i + 2 < s.size()) {
            int val = 0;
            std::istringstream iss(s.substr(i + 1, 2));
            if (iss >> std::hex >> val) {
                r += (char)val;
                i += 2;
            } else {
                r += s[i];
            }
        } else if (s[i] == '+') {
            r += ' ';
        } else {
            r += s[i];
        }
    }
    return r;
}

static std::string json_escape(const std::string& s) {
    std::string r;
    for (char c : s) {
        switch (c) {
            case '"': r += "\\\""; break;
            case '\\': r += "\\\\"; break;
            case '\n': r += "\\n"; break;
            case '\r': r += "\\r"; break;
            case '\t': r += "\\t"; break;
            default: r += c; break;
        }
    }
    return r;
}

static std::string extract_json_field(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    auto pos = json.find(search);
    if (pos == std::string::npos) return "";
    pos += search.size();
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':')) pos++;
    if (pos >= json.size()) return "";
    if (json[pos] == '"') {
        pos++;
        std::string result;
        while (pos < json.size() && json[pos] != '"') {
            if (json[pos] == '\\' && pos + 1 < json.size()) { pos++; result += json[pos]; }
            else result += json[pos];
            pos++;
        }
        return result;
    } else {
        size_t end = pos;
        while (end < json.size() && json[end] != ',' && json[end] != '}' && json[end] != ' ') end++;
        return json.substr(pos, end - pos);
    }
}

static int extract_json_int(const std::string& json, const std::string& key) {
    std::string v = extract_json_field(json, key);
    try { return std::stoi(v); } catch (...) { return 0; }
}

// ── WebServer Implementation ────────────────────────────────────────

WebServer::WebServer(uint16_t port, std::shared_ptr<ServerState> state)
    : port_(port), state_(std::move(state)) {
    load_password();
}

WebServer::~WebServer() {
    stop();
}

// ── Password Management ─────────────────────────────────────────────

void WebServer::load_password() {
    std::unique_lock lock(password_mtx_);
    std::ifstream f(password_file_);
    if (f.is_open()) {
        std::getline(f, admin_password_);
        // Trim whitespace
        size_t start = admin_password_.find_first_not_of(" \t\r\n");
        if (start != std::string::npos) {
            admin_password_ = admin_password_.substr(start);
            size_t end = admin_password_.find_last_not_of(" \t\r\n");
            if (end != std::string::npos) admin_password_ = admin_password_.substr(0, end + 1);
        } else {
            admin_password_.clear();
        }
    }
    if (admin_password_.empty()) {
        // Default password on first run
        admin_password_ = "admin123";
        lock.unlock();
        save_password();
        std::cerr << "[web] no admin password found, default set to: admin123" << std::endl;
        std::cerr << "[web] PLEASE CHANGE THE DEFAULT PASSWORD IMMEDIATELY!" << std::endl;
    } else {
        std::cerr << "[web] admin password loaded from " << password_file_ << std::endl;
    }
}

void WebServer::save_password() {
    std::shared_lock lock(password_mtx_);
    std::ofstream f(password_file_);
    if (f.is_open()) {
        f << admin_password_ << std::endl;
    } else {
        std::cerr << "[web] failed to save admin password" << std::endl;
    }
}

bool WebServer::is_password_set() const {
    std::shared_lock lock(password_mtx_);
    return !admin_password_.empty();
}

bool WebServer::check_password(const std::string& password) const {
    std::shared_lock lock(password_mtx_);
    return password == admin_password_;
}

bool WebServer::set_password(const std::string& old_pass, const std::string& new_pass) {
    {
        std::unique_lock lock(password_mtx_);
        if (old_pass != admin_password_) return false;
        admin_password_ = new_pass;
    }
    save_password();
    // Invalidate all existing tokens
    {
        std::lock_guard lock(token_mtx_);
        valid_tokens_.clear();
    }
    std::cerr << "[web] admin password changed" << std::endl;
    return true;
}

std::string WebServer::generate_token() {
    static thread_local std::mt19937_64 rng(std::random_device{}());
    static const char chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::string token;
    token.reserve(48);
    for (int i = 0; i < 48; i++) {
        token += chars[rng() % (sizeof(chars) - 1)];
    }
    return token;
}

bool WebServer::validate_token(const std::string& token) const {
    if (token.empty()) return false;
    std::lock_guard lock(token_mtx_);
    return valid_tokens_.count(token) > 0;
}

void WebServer::add_token(const std::string& token) {
    std::lock_guard lock(token_mtx_);
    valid_tokens_.insert(token);
}

void WebServer::remove_token(const std::string& token) {
    std::lock_guard lock(token_mtx_);
    valid_tokens_.erase(token);
}

std::string WebServer::extract_cookie_token(const std::string& headers) const {
    std::string search = "Cookie:";
    auto pos = headers.find(search);
    if (pos == std::string::npos) {
        search = "cookie:";
        pos = headers.find(search);
    }
    if (pos == std::string::npos) return "";

    size_t start = pos + search.size();
    auto line_end = headers.find("\r\n", start);
    if (line_end == std::string::npos) line_end = headers.size();
    std::string cookie_line = headers.substr(start, line_end - start);

    // Find admin_token=xxx
    std::string key = "admin_token=";
    auto tpos = cookie_line.find(key);
    if (tpos == std::string::npos) return "";
    tpos += key.size();
    auto tend = cookie_line.find(';', tpos);
    if (tend == std::string::npos) tend = cookie_line.size();
    std::string token = cookie_line.substr(tpos, tend - tpos);
    // Trim
    while (!token.empty() && token[0] == ' ') token = token.substr(1);
    while (!token.empty() && token.back() == ' ') token.pop_back();
    return token;
}

// ── Server Start/Stop ───────────────────────────────────────────────

void WebServer::start() {
    listen_fd_ = socket(AF_INET6, SOCK_STREAM, 0);
    if (listen_fd_ < 0) {
        std::cerr << "[web] socket failed: " << strerror(errno) << std::endl;
        return;
    }
    int opt = 1;
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    int v6only = 0;
    setsockopt(listen_fd_, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));

    struct sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port_);
    addr.sin6_addr = in6addr_any;

    if (bind(listen_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "[web] bind failed: " << strerror(errno) << std::endl;
        close(listen_fd_);
        listen_fd_ = -1;
        return;
    }
    if (listen(listen_fd_, 32) < 0) {
        std::cerr << "[web] listen failed: " << strerror(errno) << std::endl;
        close(listen_fd_);
        listen_fd_ = -1;
        return;
    }

    running_.store(true);
    accept_thread_ = std::thread(&WebServer::accept_loop, this);
    sse_heartbeat_thread_ = std::thread(&WebServer::sse_heartbeat_loop, this);

    std::cerr << "[web] admin panel & API listening on [::]:" << port_ << std::endl;
}

void WebServer::stop() {
    running_.store(false);
    if (listen_fd_ >= 0) {
        shutdown(listen_fd_, SHUT_RDWR);
        close(listen_fd_);
        listen_fd_ = -1;
    }
    {
        std::lock_guard<std::mutex> lock(sse_mtx_);
        for (int fd : sse_clients_) {
            shutdown(fd, SHUT_RDWR);
            close(fd);
        }
        sse_clients_.clear();
    }
    if (accept_thread_.joinable()) accept_thread_.join();
    if (sse_heartbeat_thread_.joinable()) sse_heartbeat_thread_.join();
}

void WebServer::accept_loop() {
    while (running_.load()) {
        struct pollfd pfd;
        pfd.fd = listen_fd_;
        pfd.events = POLLIN;
        int ret = poll(&pfd, 1, 500);
        if (ret <= 0) continue;

        struct sockaddr_in6 client_addr{};
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(listen_fd_, (struct sockaddr*)&client_addr, &addr_len);
        if (client_fd < 0) continue;

        int flag = 1;
        setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

        std::thread([this, client_fd]() {
            handle_client(client_fd);
        }).detach();
    }
}

// ── SSE Heartbeat Thread ────────────────────────────────────────────

void WebServer::sse_heartbeat_loop() {
    while (running_.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(15));
        if (!running_.load()) break;

        // Send SSE comment as keepalive
        std::string keepalive = ": keepalive\n\n";

        std::lock_guard<std::mutex> lock(sse_mtx_);
        std::vector<int> dead;
        for (int fd : sse_clients_) {
            ssize_t n = ::send(fd, keepalive.c_str(), keepalive.size(), MSG_NOSIGNAL);
            if (n <= 0) {
                dead.push_back(fd);
            }
        }
        for (int fd : dead) {
            close(fd);
            sse_clients_.erase(
                std::remove(sse_clients_.begin(), sse_clients_.end(), fd),
                sse_clients_.end());
        }
    }
}

// ── HTTP Parsing ────────────────────────────────────────────────────

WebServer::HttpRequest WebServer::parse_request(int fd) {
    HttpRequest req;
    std::string raw;
    char buf[4096];

    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (raw.find("\r\n\r\n") == std::string::npos && raw.size() < 65536) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        raw.append(buf, n);
    }

    if (raw.empty()) return req;

    auto first_end = raw.find("\r\n");
    if (first_end == std::string::npos) return req;
    std::string first_line = raw.substr(0, first_end);

    std::istringstream iss(first_line);
    std::string version;
    iss >> req.method >> req.path >> version;

    auto q = req.path.find('?');
    if (q != std::string::npos) {
        req.query = req.path.substr(q + 1);
        req.path = req.path.substr(0, q);
    }

    // Store raw headers for cookie extraction
    auto header_end = raw.find("\r\n\r\n");
    if (header_end != std::string::npos) {
        req.headers_raw = raw.substr(0, header_end);

        std::string headers = raw.substr(0, header_end);
        std::string cl_search = "Content-Length:";
        auto cl_pos = headers.find(cl_search);
        if (cl_pos == std::string::npos) {
            cl_search = "content-length:";
            cl_pos = headers.find(cl_search);
        }
        if (cl_pos != std::string::npos) {
            size_t cl_start = cl_pos + cl_search.size();
            while (cl_start < headers.size() && headers[cl_start] == ' ') cl_start++;
            size_t cl_end = headers.find("\r\n", cl_start);
            if (cl_end == std::string::npos) cl_end = headers.size();
            int content_length = 0;
            try { content_length = std::stoi(headers.substr(cl_start, cl_end - cl_start)); } catch (...) {}

            size_t body_start = header_end + 4;
            req.body = raw.substr(body_start);
            while ((int)req.body.size() < content_length) {
                ssize_t n = recv(fd, buf, std::min(sizeof(buf), (size_t)(content_length - req.body.size())), 0);
                if (n <= 0) break;
                req.body.append(buf, n);
            }
        } else {
            req.body = raw.substr(header_end + 4);
        }
    }

    return req;
}

void WebServer::send_response(int fd, int status, const std::string& content_type,
                               const std::string& body,
                               const std::string& extra_headers) {
    std::string status_text;
    switch (status) {
        case 200: status_text = "OK"; break;
        case 301: status_text = "Moved Permanently"; break;
        case 302: status_text = "Found"; break;
        case 401: status_text = "Unauthorized"; break;
        case 404: status_text = "Not Found"; break;
        case 400: status_text = "Bad Request"; break;
        default: status_text = "OK"; break;
    }
    std::ostringstream oss;
    oss << "HTTP/1.1 " << status << " " << status_text << "\r\n"
        << "Content-Type: " << content_type << "\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Access-Control-Allow-Origin: *\r\n"
        << "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        << "Access-Control-Allow-Headers: Content-Type\r\n"
        << "Connection: close\r\n";
    if (!extra_headers.empty()) {
        oss << extra_headers;
    }
    oss << "\r\n"
        << body;
    std::string resp = oss.str();
    const char* p = resp.c_str();
    size_t remaining = resp.size();
    while (remaining > 0) {
        ssize_t n = ::send(fd, p, remaining, MSG_NOSIGNAL);
        if (n <= 0) break;
        p += n;
        remaining -= n;
    }
}

void WebServer::send_sse_headers(int fd) {
    std::string resp =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/event-stream\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: keep-alive\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "\r\n";
    ::send(fd, resp.c_str(), resp.size(), MSG_NOSIGNAL);
}

// ── Request Routing ─────────────────────────────────────────────────

void WebServer::handle_client(int client_fd) {
    auto req = parse_request(client_fd);

    if (req.method == "OPTIONS") {
        send_response(client_fd, 200, "text/plain", "");
        close(client_fd);
        return;
    }

    // Extract auth token from cookie
    std::string token = extract_cookie_token(req.headers_raw);
    bool authed = validate_token(token);

    // Public API routes (no auth required)
    if (req.method == "GET") {
        if (req.path == "/api/rooms/info") {
            handle_api_rooms_info(client_fd);
            close(client_fd);
            return;
        } else if (req.path.rfind("/api/rooms/info/", 0) == 0) {
            std::string name = url_decode(req.path.substr(16));
            handle_api_room_info(client_fd, name);
            close(client_fd);
            return;
        } else if (req.path.rfind("/api/rooms/user/", 0) == 0) {
            std::string id_str = req.path.substr(16);
            int uid = 0;
            try { uid = std::stoi(id_str); } catch (...) {}
            if (uid > 0) handle_api_room_user(client_fd, uid);
            else send_response(client_fd, 400, "application/json", "{\"error\":\"invalid user_id\"}");
            close(client_fd);
            return;
        } else if (req.path == "/api/rooms/listen") {
            handle_api_rooms_listen(client_fd);
            return; // Don't close fd - SSE keeps it open
        }
    }

    // Login page (no auth required)
    if (req.method == "GET" && (req.path == "/admin/login" || req.path == "/admin/login/")) {
        handle_admin_login_page(client_fd);
        close(client_fd);
        return;
    }
    if (req.method == "POST" && req.path == "/admin/login") {
        handle_admin_login(client_fd, req.body);
        close(client_fd);
        return;
    }

    // Root redirect to admin
    if (req.method == "GET" && req.path == "/") {
        if (authed) {
            send_response(client_fd, 302, "text/plain", "", "Location: /admin\r\n");
        } else {
            send_response(client_fd, 302, "text/plain", "", "Location: /admin/login\r\n");
        }
        close(client_fd);
        return;
    }

    // All admin routes below require authentication
    if (!authed) {
        if (req.method == "GET") {
            // Redirect to login page for browser requests
            send_response(client_fd, 302, "text/plain", "", "Location: /admin/login\r\n");
        } else {
            send_response(client_fd, 401, "application/json", "{\"error\":\"unauthorized\"}");
        }
        close(client_fd);
        return;
    }

    // Authenticated routes
    if (req.method == "GET") {
        if (req.path == "/admin" || req.path == "/admin/") {
            handle_admin_page(client_fd, token);
        } else if (req.path == "/admin/api/rooms") {
            handle_admin_api_rooms(client_fd);
        } else if (req.path == "/admin/api/bans") {
            handle_admin_api_bans(client_fd);
        } else {
            send_response(client_fd, 404, "application/json", "{\"error\":\"not found\"}");
        }
    } else if (req.method == "POST") {
        if (req.path == "/admin/dissolve") {
            handle_admin_dissolve(client_fd, req.body);
        } else if (req.path == "/admin/ban") {
            handle_admin_ban(client_fd, req.body);
        } else if (req.path == "/admin/unban") {
            handle_admin_unban(client_fd, req.body);
        } else if (req.path == "/admin/kick") {
            handle_admin_kick(client_fd, req.body);
        } else if (req.path == "/admin/logout") {
            handle_admin_logout(client_fd);
        } else if (req.path == "/admin/change_password") {
            handle_admin_change_password(client_fd, req.body);
        } else {
            send_response(client_fd, 404, "application/json", "{\"error\":\"not found\"}");
        }
    } else {
        send_response(client_fd, 400, "application/json", "{\"error\":\"unsupported method\"}");
    }

    close(client_fd);
}

// ── JSON Builders ───────────────────────────────────────────────────

std::string WebServer::record_to_json(const Record& rec) const {
    std::ostringstream oss;
    oss << "{\"id\":" << rec.id
        << ",\"player\":" << rec.player
        << ",\"score\":" << rec.score
        << ",\"perfect\":" << rec.perfect
        << ",\"good\":" << rec.good
        << ",\"bad\":" << rec.bad
        << ",\"miss\":" << rec.miss
        << ",\"max_combo\":" << rec.max_combo
        << ",\"accuracy\":" << rec.accuracy
        << ",\"full_combo\":" << (rec.full_combo ? "true" : "false")
        << ",\"std\":" << rec.std_dev
        << ",\"std_score\":" << rec.std_score
        << "}";
    return oss.str();
}

std::string WebServer::room_to_json(const std::string& room_name) const {
    std::shared_ptr<Room> rm;
    {
        std::shared_lock lock(state_->rooms_mtx);
        auto it = state_->rooms.find(room_name);
        if (it == state_->rooms.end()) return "";
        rm = it->second;
    }

    int32_t host_id = 0;
    {
        std::shared_lock lock(rm->host_mtx);
        auto h = rm->host.lock();
        if (h) host_id = h->id;
    }

    auto user_list = rm->users();
    auto monitor_list = rm->monitors();

    std::string state_str;
    std::vector<int32_t> playing_users;
    {
        std::shared_lock lock(rm->state_mtx);
        switch (rm->state.type) {
            case InternalRoomStateType::SelectChart: state_str = "SELECTING_CHART"; break;
            case InternalRoomStateType::WaitForReady: state_str = "WAITING_FOR_READY"; break;
            case InternalRoomStateType::Playing: state_str = "PLAYING"; break;
        }
        if (rm->state.type == InternalRoomStateType::Playing) {
            for (auto& u : user_list) {
                if (rm->state.results.count(u->id) == 0 && rm->state.aborted.count(u->id) == 0) {
                    playing_users.push_back(u->id);
                }
            }
        }
    }

    std::optional<int32_t> chart_id;
    {
        std::shared_lock lock(rm->chart_mtx);
        if (rm->chart) chart_id = rm->chart->id;
    }

    std::string rounds_json;
    {
        std::shared_lock lock(rm->rounds_mtx);
        rounds_json = "[";
        bool first_round = true;
        for (auto& round : rm->rounds_history) {
            if (!first_round) rounds_json += ",";
            first_round = false;
            rounds_json += "{\"chart\":" + std::to_string(round.chart_id) + ",\"records\":[";
            bool first_rec = true;
            for (auto& rec : round.records) {
                if (!first_rec) rounds_json += ",";
                first_rec = false;
                rounds_json += record_to_json(rec);
            }
            rounds_json += "]}";
        }
        rounds_json += "]";
    }

    std::ostringstream oss;
    oss << "{\"name\":\"" << json_escape(room_name) << "\",\"data\":{";
    oss << "\"host\":" << host_id;

    oss << ",\"users\":[";
    bool first = true;
    for (auto& u : user_list) {
        if (!first) oss << ",";
        first = false;
        oss << u->id;
    }
    oss << "]";

    oss << ",\"lock\":" << (rm->is_locked() ? "true" : "false");
    oss << ",\"cycle\":" << (rm->is_cycle() ? "true" : "false");
    oss << ",\"chart\":" << (chart_id ? std::to_string(*chart_id) : "null");
    oss << ",\"state\":\"" << state_str << "\"";

    oss << ",\"playing_users\":[";
    first = true;
    for (auto pid : playing_users) {
        if (!first) oss << ",";
        first = false;
        oss << pid;
    }
    oss << "]";

    oss << ",\"rounds\":" << rounds_json;
    oss << "}}";

    return oss.str();
}

std::string WebServer::all_rooms_json() const {
    std::vector<std::string> room_names;
    {
        std::shared_lock lock(state_->rooms_mtx);
        for (auto& [name, _] : state_->rooms) {
            room_names.push_back(name);
        }
    }

    std::ostringstream oss;
    oss << "[";
    bool first = true;
    for (auto& name : room_names) {
        std::string j = room_to_json(name);
        if (j.empty()) continue;
        if (!first) oss << ",";
        first = false;
        oss << j;
    }
    oss << "]";
    return oss.str();
}

// ── API Handlers ────────────────────────────────────────────────────

void WebServer::handle_api_rooms_info(int fd) {
    send_response(fd, 200, "application/json", all_rooms_json());
}

void WebServer::handle_api_room_info(int fd, const std::string& name) {
    std::string j = room_to_json(name);
    if (j.empty()) {
        send_response(fd, 404, "application/json", "{\"error\":\"room not found\"}");
    } else {
        send_response(fd, 200, "application/json", j);
    }
}

void WebServer::handle_api_room_user(int fd, int32_t user_id) {
    std::vector<std::string> room_names;
    {
        std::shared_lock lock(state_->rooms_mtx);
        for (auto& [name, _] : state_->rooms) room_names.push_back(name);
    }

    for (auto& name : room_names) {
        std::shared_ptr<Room> rm;
        {
            std::shared_lock lock(state_->rooms_mtx);
            auto it = state_->rooms.find(name);
            if (it == state_->rooms.end()) continue;
            rm = it->second;
        }
        auto user_list = rm->users();
        auto mon_list = rm->monitors();
        for (auto& u : user_list) {
            if (u->id == user_id) {
                send_response(fd, 200, "application/json", room_to_json(name));
                return;
            }
        }
        for (auto& u : mon_list) {
            if (u->id == user_id) {
                send_response(fd, 200, "application/json", room_to_json(name));
                return;
            }
        }
    }
    send_response(fd, 404, "application/json", "{\"error\":\"user not in any room\"}");
}

void WebServer::handle_api_rooms_listen(int fd) {
    send_sse_headers(fd);

    // FIX: Send initial snapshot of all rooms so client gets immediate data
    std::string initial = "event: snapshot\ndata: " + all_rooms_json() + "\n\n";
    ::send(fd, initial.c_str(), initial.size(), MSG_NOSIGNAL);

    // Add to SSE clients list
    {
        std::lock_guard<std::mutex> lock(sse_mtx_);
        sse_clients_.push_back(fd);
    }
    // Keep connection open - heartbeat thread will keep it alive
}

// ── SSE Broadcast ───────────────────────────────────────────────────

void WebServer::broadcast_sse(const std::string& event_type, const std::string& json_data) {
    std::string msg = "event: " + event_type + "\ndata: " + json_data + "\n\n";

    std::lock_guard<std::mutex> lock(sse_mtx_);
    std::vector<int> dead;
    for (int fd : sse_clients_) {
        ssize_t total = 0;
        size_t remaining = msg.size();
        const char* p = msg.c_str();
        while (remaining > 0) {
            ssize_t n = ::send(fd, p, remaining, MSG_NOSIGNAL);
            if (n <= 0) {
                dead.push_back(fd);
                break;
            }
            p += n;
            remaining -= n;
            total += n;
        }
    }
    for (int fd : dead) {
        close(fd);
        sse_clients_.erase(
            std::remove(sse_clients_.begin(), sse_clients_.end(), fd),
            sse_clients_.end());
    }
}

// ── Auth Handlers ───────────────────────────────────────────────────

void WebServer::handle_admin_login_page(int fd) {
    send_response(fd, 200, "text/html; charset=utf-8", std::string(LOGIN_HTML));
}

void WebServer::handle_admin_login(int fd, const std::string& body) {
    std::string password = extract_json_field(body, "password");
    if (check_password(password)) {
        std::string token = generate_token();
        add_token(token);
        std::string cookie_header = "Set-Cookie: admin_token=" + token +
                                     "; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400\r\n";
        send_response(fd, 200, "application/json", "{\"ok\":true}", cookie_header);
        std::cerr << "[web] admin login successful" << std::endl;
    } else {
        send_response(fd, 200, "application/json", "{\"ok\":false,\"error\":\"密码错误\"}");
        std::cerr << "[web] admin login failed (wrong password)" << std::endl;
    }
}

void WebServer::handle_admin_logout(int fd) {
    // Clear cookie
    std::string cookie_header = "Set-Cookie: admin_token=; Path=/; HttpOnly; Max-Age=0\r\n";
    send_response(fd, 200, "application/json", "{\"ok\":true}", cookie_header);
}

void WebServer::handle_admin_change_password(int fd, const std::string& body) {
    std::string old_pass = extract_json_field(body, "old_password");
    std::string new_pass = extract_json_field(body, "new_password");

    if (new_pass.size() < 4) {
        send_response(fd, 200, "application/json", "{\"ok\":false,\"error\":\"新密码至少4个字符\"}");
        return;
    }

    if (set_password(old_pass, new_pass)) {
        send_response(fd, 200, "application/json", "{\"ok\":true}");
    } else {
        send_response(fd, 200, "application/json", "{\"ok\":false,\"error\":\"当前密码错误\"}");
    }
}

// ── Admin Page ──────────────────────────────────────────────────────

void WebServer::handle_admin_page(int fd, const std::string& /*token*/) {
    send_response(fd, 200, "text/html; charset=utf-8", std::string(ADMIN_HTML));
}

void WebServer::handle_admin_api_rooms(int fd) {
    send_response(fd, 200, "application/json", all_rooms_json());
}

void WebServer::handle_admin_api_bans(int fd) {
    auto banned = BanManager::instance().get_banned();
    std::ostringstream oss;
    oss << "[";
    bool first = true;
    for (auto id : banned) {
        if (!first) oss << ",";
        first = false;
        oss << id;
    }
    oss << "]";
    send_response(fd, 200, "application/json", oss.str());
}

void WebServer::handle_admin_dissolve(int fd, const std::string& body) {
    std::string room_name = extract_json_field(body, "room");
    if (room_name.empty()) {
        send_response(fd, 400, "application/json", "{\"error\":\"missing room name\"}");
        return;
    }

    std::shared_ptr<Room> rm;
    {
        std::shared_lock lock(state_->rooms_mtx);
        auto it = state_->rooms.find(room_name);
        if (it == state_->rooms.end()) {
            send_response(fd, 404, "application/json", "{\"error\":\"room not found\"}");
            return;
        }
        rm = it->second;
    }

    auto user_list = rm->users();
    auto mon_list = rm->monitors();
    for (auto& u : user_list) {
        u->clear_room();
        u->try_send(ServerCommand::simple_ok(ServerCommandType::LeaveRoom));
        u->try_send(ServerCommand::msg(Message::chat(0, "[系统] 房间已被管理员解散")));
    }
    for (auto& u : mon_list) {
        u->clear_room();
        u->try_send(ServerCommand::simple_ok(ServerCommandType::LeaveRoom));
    }

    {
        std::unique_lock lock(state_->rooms_mtx);
        state_->rooms.erase(room_name);
    }

    if (g_web_server) {
        for (auto& u : user_list) {
            g_web_server->broadcast_sse("leave_room",
                "{\"room\":\"" + json_escape(room_name) + "\",\"user\":" + std::to_string(u->id) + "}");
        }
    }

    std::cerr << "[admin] dissolved room: " << room_name << std::endl;
    send_response(fd, 200, "application/json", "{\"message\":\"房间已解散\"}");
}

void WebServer::handle_admin_ban(int fd, const std::string& body) {
    int uid = extract_json_int(body, "user_id");
    if (uid <= 0) {
        send_response(fd, 400, "application/json", "{\"error\":\"invalid user_id\"}");
        return;
    }

    if (BanManager::instance().ban(uid)) {
        std::cerr << "[admin] banned user: " << uid << std::endl;

        std::shared_ptr<User> user_ptr;
        {
            std::shared_lock lock(state_->users_mtx);
            auto it = state_->users.find(uid);
            if (it != state_->users.end()) user_ptr = it->second;
        }
        if (user_ptr) {
            user_ptr->try_send(ServerCommand::msg(Message::chat(0, "[系统] 你已被管理员封禁")));
            auto rm = user_ptr->get_room();
            if (rm) {
                user_ptr->clear_room();
                if (rm->on_user_leave(*user_ptr)) {
                    std::unique_lock lock(state_->rooms_mtx);
                    state_->rooms.erase(rm->id.to_string());
                }
            }
        }

        send_response(fd, 200, "application/json", "{\"message\":\"玩家已封禁\"}");
    } else {
        send_response(fd, 200, "application/json", "{\"message\":\"玩家已在封禁列表中\"}");
    }
}

void WebServer::handle_admin_unban(int fd, const std::string& body) {
    int uid = extract_json_int(body, "user_id");
    if (uid <= 0) {
        send_response(fd, 400, "application/json", "{\"error\":\"invalid user_id\"}");
        return;
    }
    if (BanManager::instance().unban(uid)) {
        std::cerr << "[admin] unbanned user: " << uid << std::endl;
        send_response(fd, 200, "application/json", "{\"message\":\"玩家已解封\"}");
    } else {
        send_response(fd, 200, "application/json", "{\"message\":\"玩家不在封禁列表中\"}");
    }
}

void WebServer::handle_admin_kick(int fd, const std::string& body) {
    std::string room_name = extract_json_field(body, "room");
    int uid = extract_json_int(body, "user_id");
    if (room_name.empty() || uid <= 0) {
        send_response(fd, 400, "application/json", "{\"error\":\"missing room or user_id\"}");
        return;
    }

    std::shared_ptr<Room> rm;
    {
        std::shared_lock lock(state_->rooms_mtx);
        auto it = state_->rooms.find(room_name);
        if (it == state_->rooms.end()) {
            send_response(fd, 404, "application/json", "{\"error\":\"room not found\"}");
            return;
        }
        rm = it->second;
    }

    std::shared_ptr<User> user_ptr;
    {
        std::shared_lock lock(state_->users_mtx);
        auto it = state_->users.find(uid);
        if (it != state_->users.end()) user_ptr = it->second;
    }

    if (!user_ptr) {
        send_response(fd, 404, "application/json", "{\"error\":\"user not found\"}");
        return;
    }

    user_ptr->clear_room();
    user_ptr->try_send(ServerCommand::simple_ok(ServerCommandType::LeaveRoom));
    user_ptr->try_send(ServerCommand::msg(Message::chat(0, "[系统] 你已被管理员踢出房间")));
    bool should_drop = rm->on_user_leave(*user_ptr);
    if (should_drop) {
        std::unique_lock lock(state_->rooms_mtx);
        state_->rooms.erase(rm->id.to_string());
    }

    if (g_web_server) {
        g_web_server->broadcast_sse("leave_room",
            "{\"room\":\"" + json_escape(room_name) + "\",\"user\":" + std::to_string(uid) + "}");
    }

    std::cerr << "[admin] kicked user " << uid << " from room " << room_name << std::endl;
    send_response(fd, 200, "application/json", "{\"message\":\"玩家已被踢出\"}");
}
