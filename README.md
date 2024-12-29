
# Zoffline-CN-Tool

Zoffline-CN-Tool is a GUI tool for switching between Zwift's official servers and community servers.

Zoffline-CN-Tool 是一个用于管理和切换 Zwift 官方服务器与社区服务器的图形化工具。它提供了一个简单的界面来帮助用户完成 Zoffline 在大陆地区特殊网络环境的相关的配置任务。对于Zoffline-CN 的更多信息，请访问分支 https://github.com/kanhao100/zwift-offline

For English-speaking users, this project may not be relevant as it's specifically designed for users in mainland China. If you need English support, please open an issue.

## 功能特点

### 主要功能
- 一键启动社区服 Zwift
- 一键启动官服 Zwift
- 自动检查社区服版本和本地版本

### 高级选项
- 自动 Host 设置
- 自动系统证书导入
- 自动客户端证书导入
- Caddy 反向代理后台单独启动
- 版本查询和管理
- 系统代理检查
- 端口占用检查
- 连通性测试

## 系统要求

- Windows 操作系统
- 管理员权限
- 已安装 Zwift 客户端
- Python 3.6+ (如果从源码运行)

## 使用说明 | Usage Instructions

### 使用预编译程序 | Using Pre-compiled Release

1. 从 Release 页面下载最新版本的 Zoffline-CN-Tool
2. 解压到任意目录
3. 以管理员身份运行程序

### 从源码构建 | Building from Source

1. 确保已安装 Python 3.6+ 和所需依赖:
   ```bash
   pip install freesimplegui requests
   ```

2. 克隆仓库:
   ```bash
   git clone https://github.com/kanhao100/zoffline-cn-tool.git
   cd zoffline-cn-tool
   ```

3. 下载 Caddy (https://caddyserver.com/download) 并重命名为 Caddy.exe，放置在项目根目录

4. 运行程序:
   ```bash
   python Zoffline-CN-Tool.py
   ```

5. 编译打包分发
   ```bash
   python -m PyInstaller --clean --onefile --uac-admin --icon=logo.ico --add-data "*.pem;." --add-data "*.p12;." --add-data "caddy.exe;." --add-data "Caddyfile;." Zoffline-CN-Tool.py
   ```

注意：无论使用哪种方式，都需要管理员权限来运行程序。【为什么？因为我们需要修改系统hosts文件，需要管理员权限】

## 使用指南

### 初始配置

1. 首次运行时，程序会自动请求管理员权限
2. 程序会自动查找 Zwift 安装位置，如果找不到会提示手动选择
3. 设置社区服务器 IP 地址

### 切换服务器

#### 切换到社区服务器
1. 点击"一键启动社区服 Zwift"
2. 等待程序完成所有必要的配置
3. 程序会自动启动 Zwift

#### 切换到官方服务器
1. 点击"一键启动官服 Zwift"
2. 程序会自动清理社区服务器的配置
3. 启动官方版本的 Zwift

### 故障排查

程序提供了多个诊断工具：
- 检查系统代理
- 检查端口占用
- 测试连通性
- 版本检查

## 注意事项

- 使用社区服务器功能需要先获取有效的Zoffline社区服务器 IP 地址
- 使用社区服务器功能需要先获取由Zoffline社区服务器提供的证书和密钥文件

## TODO list
- 添加DNS解析的功能，实现服务端动态IP绑定的域名也能成功连接
- 添加服务端证书配置教程或者脚本
- 添加英文支持

## 工作原理
• 官服 Zwift 连接:
```
   [Your PC]  ===============> [Zwift Official Servers]
   Zwift Client               - us-or-rly101.zwift.com
   - Default hosts file       - secure.zwift.com
   - Zwift SSL certificates   - cdn.zwift.com
                              - launcher.zwift.com
   Ports: 80(HTTP), 443(HTTPS), 3025(TCP)(Game),3024(UDP)(Game)
```
• 社区服连接:
```
                     (Local Reverse Proxy)
   [Your PC] <========> [Caddy Server] ==========> [Remote Zwift-Offline]
   Zwift Client      localhost:80/443/3025/3024         Custom Server

   Technical Setup:
   1. Modified hosts file:
      127.0.0.1  secure.zwift.com
      127.0.0.1  us-or-rly101.zwift.com
      127.0.0.1  cdn.zwift.com
      127.0.0.1  launcher.zwift.com
   2. SSL Certificate:
      - Custom SSL Certificate installed in Windows sys, Zwift Client, Caddy server and Remote server
   3. Caddy Configuration:
      - Reverse proxy for all Zwift domains
      - Remove Host header to avoid Chinese government hijacking [HTTP]
      - Repalce SNI to avoid Chinese government hijacking [HTTPS]
   4. Network Flow:
      Client --> Local Caddy --> Remote Server
      [80/443/3025/3024] --> [Proxy] --> [Remote Port]
```

## 致谢项

- Python 3 (https://www.python.org/downloads/)
- FreeSimpleGUI (https://github.com/spyoungtech/FreeSimpleGui)
- Caddy (https://github.com/caddyserver/caddy)

- Zwift Offline (https://github.com/zoffline/zwift-offline)
- Zoffline-helper (https://github.com/oldnapalm/zoffline-helper)

## 免责声明

本工具仅用于学习和研究目的。用户需要遵守相关服务条款和法律法规。使用本工具所产生的任何后果由用户自行承担。

Zwift 是 Zwift, Inc. 的商标,该公司与本项目的制作者没有关联,也不认可本项目。

所有产品和公司名称都是其各自持有者的商标。使用它们并不意味着与它们有任何关联或得到它们的认可。