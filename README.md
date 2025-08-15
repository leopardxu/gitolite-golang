# Gitolite-Golang - Git 仓库管理服务

## 项目简介

本项目是基于 Go 语言重写的 [Gitolite](https://github.com/sitaramc/gitolite) 实现，旨在保持与原版功能一致的同时，充分发挥 Golang 语言的优势。项目采用现代化的架构设计，提供高性能、高可靠性的 Git 仓库管理服务。

## 核心功能

### 1. **SSH 密钥管理**
   - 从 Gerrit 系统同步用户 SSH 公钥
   - 自动更新和维护 authorized_keys 文件
   - 支持多种密钥格式和转换
   - 定时同步和手动同步模式

### 2. **智能权限控制**
   - 深度集成 Gerrit 权限系统
   - 支持用户级和项目级权限检查
   - 管理员权限自动识别
   - 多种 Git 操作权限控制（读、写、创建、删除、强制推送等）
   - 基于配置文件的灵活权限管理

### 3. **仓库管理**
   - 自动创建和初始化新仓库
   - 支持 Gerrit 仓库同步
   - 智能处理 Git 初始化请求
   - 仓库路径规范化处理

### 4. **Git 协议处理**
   - 完整支持 Git 协议标准
   - 处理 `git-upload-pack`（克隆/拉取）操作
   - 处理 `git-receive-pack`（推送）操作
   - 协议错误处理和用户友好的错误信息

### 5. **审计系统**
   - 完整的用户访问审计记录
   - 结构化日志输出（JSON 格式）
   - 记录访问时间、用户、仓库、操作类型等详细信息
   - 支持控制台输出和文件记录
   - 审计信息与 Git 协议分离，避免干扰

### 6. 钩子系统
   - 支持 pre-receive、post-receive、update 等多种钩子
   - 自动为新仓库安装钩子
   - 可自定义钩子行为和脚本

### 7. **镜像复制功能**
   - 支持将仓库镜像到多个远程服务器
   - 按需或定时自动推送更新
   - 支持同步或异步推送模式
   - 灵活的仓库过滤和匹配配置
   - 支持通配符模式

### 8. **日志系统**
   - 多级别日志支持（INFO、WARN、ERROR）
   - 日志轮转功能（按日或按周）
   - 旧日志压缩和自动清理
   - 分离的审计日志和系统日志

## 快速开始

### 1. 安装

```bash
go build -o gitolite-shell ./cmd/gitolite-shell
sudo mv gitolite-shell /usr/bin/
```

### 2. 配置

配置文件路径: /home/git/.gitolite/config.yaml
···bash
export GITOLITE_CONFIG_PATH=/home/git/.gitolite/config.yaml
#支持
-config /home/git/.gitolite/config.yaml
#默认配置文件路径
default: $HOME/.gitolite/config.yaml
···

```yaml
# 基础配置
repo_base: /home/git/repositories
gerrit_url: https://gerrit.example.com
gerrit_user: gitadmin
gerrit_api_token: your_api_token
gerrit_remote_url: ssh://git@gerrit.example.com:29418
authorized_keys: /home/git/.ssh/authorized_keys

# 权限和钩子配置
access_config: /home/git/.gitolite/conf/gitolite.conf
hooks_dir: /home/git/.gitolite/hooks
# 日志配置
log:
  path: /home/git/gitolite/logs/gitolite.log
  level: INFO                  # 可选值: INFO, WARN, ERROR
  compress: true               # 是否压缩旧日志
  max_age: 30                  # 日志保留天数

# 审计配置
audit:
  enabled: true                # 是否启用审计功能
  log_path: /home/git/gitolite/audit.log  # 审计日志文件路径
  console_out: true            # 是否在控制台输出结构化访问信息
```

### 3. 运行

```bash
# 同步模式 - 一次性同步密钥
./gitolite-shell -sync

# ~/.ssh/authorized_keys 示例
command="gitolite-shell gitadmin",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty "gerrit publickey"

# 守护模式 - 后台运行定期同步密钥
./gitolite-shell -daemon

# 指定配置文件路径
./gitolite-shell -config /path/to/custom/config.yaml
```

### 4. 权限配置

在 `access_config` 指定的配置文件中定义仓库访问权限：

```
# 格式: repo [权限] = 用户
repo project1
    RW+ = user1 user2
    R   = user3

# 使用通配符匹配多个仓库
repo project.*
    RW  = admin
    R   = @developers
```

权限类型说明：
- R: 读取权限
- W: 写入权限
- +: 强制推送权限
- C: 创建权限
- D: 删除权限

## 高级功能

### 审计系统

系统提供完整的用户访问审计功能，记录所有 Git 操作的详细信息：

#### 审计信息包含：
- 访问时间戳
- 用户身份
- 目标仓库
- 操作类型（clone、push、pull 等）
- 原始 Git 命令
- 客户端 IP 地址
- SSH 客户端信息
- 连接 ID
- 操作结果（成功/失败）
- 错误信息（如果有）

#### 审计输出格式：
```json
{
  "timestamp": "2025-01-08T15:21:43Z",
  "user": "john.doe",
  "repository": "project1",
  "operation": "git-upload-pack",
  "command": "git-upload-pack 'project1.git'",
  "client_ip": "192.168.1.100",
  "ssh_client": "OpenSSH_8.0",
  "connection_id": "12345",
  "success": false,
  "error_message": "User john.doe has no permission"
}
```

#### 配置审计：
```yaml
audit:
  enabled: true                # 启用审计功能
  log_path: /path/to/audit.log # 审计日志文件路径
  console_out: true            # 是否在控制台输出审计信息
```

### 权限检查机制

系统实现了多层次的权限检查：

1. **管理员权限自动识别**：系统自动识别具有管理员权限的用户
2. **Gerrit 集成**：通过 Gerrit API 检查用户权限
3. **本地配置**：支持基于 gitolite.conf 的本地权限配置
4. **特殊用户处理**：对 `gerrit-replication`、`git`、`gitadmin` 等特殊用户提供直接访问

### 自定义钩子

将自定义钩子脚本放置在 `hooks_dir` 目录下，系统会自动为新仓库安装这些钩子：

```bash
# 钩子目录结构
/home/git/.gitolite/hooks/
├── pre-receive
├── post-receive
└── update
```

### 日志管理

系统提供分离的日志管理：

- **系统日志**：记录系统运行状态和错误信息
- **审计日志**：记录用户访问和操作详情
- **日志轮转**：支持日志压缩和自动清理
- **多级别支持**：INFO、WARN、ERROR 级别

### 镜像复制


### Git 协议兼容性

系统完全兼容标准 Git 协议，支持：

- 标准 Git 命令：git clone、git push、git pull 等
- 协议错误处理：提供用户友好的错误信息
- 输出分离：审计信息输出到 stderr，避免干扰 Git 协议通信
- 权限拒绝处理：标准的 Git 协议错误响应

## 项目结构

```
gitolite-golang/
├── cmd/
│   ├── gitolite-shell/     # 主程序入口
├── internal/
│   ├── access/            # 权限控制模块
│   ├── audit/             # 审计系统
│   ├── config/            # 配置管理
│   ├── gerrit/            # Gerrit 集成
│   ├── git/               # Git 操作封装
│   ├── hooks/             # 钩子系统
│   ├── log/               # 日志系统
│   ├── mirror/            # 镜像复制
│   ├── protocol/          # Git 协议处理
│   ├── sync/              # 同步功能
│   └── validator/         # 数据验证
├── docs/                  # 文档目录
├── hooks/                 # 默认钩子脚本
├── config.yaml           # 配置文件示例
├── gitolite.conf         # 权限配置示例
└── README.md             # 项目文档
```

## 故障排除

### 常见问题

#### 1. 权限拒绝错误
```bash
fatal: access denied or repository not found
```

**解决方案：**
- 检查用户是否在 Gerrit 系统中存在
- 验证用户对目标仓库的权限
- 检查 `gerrit_url`、`gerrit_user`、`gerrit_api_token` 配置是否正确
- 查看审计日志了解详细的权限检查过程

#### 2. SSH 密钥同步失败
```bash
Failed to sync SSH keys from Gerrit
```

**解决方案：**
- 检查 Gerrit API 连接是否正常
- 验证 API Token 是否有效
- 确认 `authorized_keys` 文件路径和权限正确

#### 3. 仓库创建失败
```bash
Failed to create repository
```

**解决方案：**
- 检查 `repo_base` 目录权限
- 确认磁盘空间充足
- 验证仓库名称格式是否正确

### 调试模式

启用详细日志输出：

```yaml
log:
  level: DEBUG  # 启用调试级别日志
```

查看实时日志：

```bash
# 查看系统日志
tail -f /path/to/gitolite.log

# 查看审计日志
tail -f /path/to/audit.log
```

## 开发指南

### 环境要求

- Go 1.23.6 或更高版本
- Git 2.0 或更高版本
- Linux/Unix 系统

### 构建项目

```bash
# 克隆项目
git clone <repository-url>
cd gitolite-golang

# 安装依赖
go mod tidy

# 构建主程序
go build -o gitolite-shell ./cmd/gitolite-shell

# 运行测试
go test ./...

# 代码格式化
gofmt -w .
```

### 代码规范

项目遵循 Go 语言最佳实践：

- 使用 `gofmt` 进行代码格式化
- 使用 `goimports` 管理导入
- 遵循 Go 命名规范
- 提供完整的错误处理
- 使用结构化日志
- 合理使用并发和 goroutine

### 贡献指南

1. Fork 项目
2. 创建功能分支
3. 提交代码变更
4. 编写测试用例
5. 确保代码通过所有测试
6. 提交 Pull Request

## 性能优化

### 并发处理

- 使用 goroutine 处理并发请求
- 实现连接池管理
- 避免 goroutine 泄露

### 内存管理

- 合理使用缓存
- 及时释放资源
- 避免内存泄露

### 网络优化

- 设置合理的超时时间
- 使用连接复用
- 实现重试机制

## 安全考虑

- **密钥管理**：安全存储 API Token 和私钥
- **权限控制**：严格的用户权限验证
- **审计日志**：完整记录所有操作
- **网络安全**：使用 HTTPS 和 SSH 协议
- **输入验证**：严格验证用户输入

## 许可证

本项目基于原版 Gitolite 的许可证条款发布。

## 支持

如有问题或建议，请通过以下方式联系：

- 提交 Issue
- 发送 Pull Request
- 查看项目文档

---

**注意**：本项目是 Gitolite 的 Go 语言重写版本，旨在提供更好的性能和可维护性，同时保持与原版的功能兼容性。

##BUG
Gerrit replication 删除事件无法执行