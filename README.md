# Gitolite-Golang - Git 仓库管理服务

## 功能概述

本项目是基于 Go 语言实现的 Git 仓库管理服务，主要提供以下核心功能：

1. **SSH 密钥管理**
   - 从 Gerrit 同步用户 SSH 公钥
   - 自动更新 authorized_keys 文件
   - 支持密钥格式转换

2. **仓库访问控制**
   - 集成 Gerrit 权限系统
   - 支持多种 Git 操作权限检查（读、写、创建、删除等）
   - 基于配置文件的灵活权限管理

3. **仓库管理**
   - 自动创建新仓库
   - 支持 Gerrit 仓库同步
   - 处理 Git 初始化请求

4. **钩子系统**
   - 支持 pre-receive、post-receive、update 等多种钩子
   - 自动为新仓库安装钩子
   - 可自定义钩子行为

5. **日志系统**
   - 支持日志级别配置
   - 日志轮转功能（按日或按周）
   - 旧日志压缩和自动清理

## 快速开始

### 1. 安装

```bash
go build -o gitolite-shell ./cmd/gitolite-shell
sudo mv gitolite-shell /usr/bin/
```

### 2. 配置

配置文件路径: /home/git/.gitolite/config.yaml

```yaml
# 基础配置
repo_base: /home/git/repositories
gerrit_url: https://gerrit.url.com
gerrit_user: gitadmin
gerrit_api_token: your_api_token
gerrit_remote_url: ssh://git@gerrit.url.com:29418
authorized_keys: /home/git/.ssh/authorized_keys

# 权限和钩子配置
access_config: /home/git/.gitolite/conf/gitolite.conf
hooks_dir: /home/git/.gitolite/hooks

# 日志配置
log:
  path: /home/git/gitolite/logs/gitolite.log
  level: INFO  # 可选值: INFO, WARN, ERROR
  rotation: daily  # 日志轮转周期: daily 或 weekly
  compress: true   # 是否压缩旧日志
  max_age: 30      # 日志保留天数
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

### 自定义钩子

将自定义钩子脚本放置在 `hooks_dir` 目录下，系统会自动为新仓库安装这些钩子。

### 日志管理

系统支持日志轮转和压缩功能，可通过配置文件调整日志级别、轮转周期和保留时间。