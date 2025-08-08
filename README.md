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

5. **镜像复制功能**
   - 支持将仓库镜像到多个远程服务器
   - 按需或定时自动推送更新
   - 支持同步或异步推送模式
   - 灵活的仓库过滤配置

6. **日志系统**
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
gerrit_url: https://gerrit.url.com
gerrit_user: gitadmin
gerrit_api_token: your_api_token
gerrit_remote_url: ssh://git@gerrit.url.com:29418
authorized_keys: /home/git/.ssh/authorized_keys

# 权限和钩子配置
access_config: /home/git/.gitolite/conf/gitolite.conf
hooks_dir: /home/git/.gitolite/hooks

# 镜像复制配置
mirror:
  enabled: true                # 是否启用镜像功能
  schedule: "@hourly"          # 定时推送频率 (cron 表达式)
  targets:                     # 镜像目标列表
    - name: "backup-server"    # 目标名称
      url: "git@backup-server:repos/" # 目标 URL
      enabled: true            # 是否启用此目标
      async: false             # 是否异步推送
      timeout: 300             # 推送超时时间(秒)
      all_repos: false         # 是否镜像所有仓库
      repos:                   # 需要镜像的仓库列表
        - "project1"           # 精确匹配
        - "project2/*"         # 通配符匹配

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

### 镜像复制

系统支持将仓库镜像到多个远程服务器，可以按需或定时自动推送更新。

#### 配置镜像

在配置文件中添加 `mirror` 部分，设置镜像目标和推送策略。

#### 手动触发镜像

使用 `mirror-push` 工具手动触发镜像推送：

```bash
# 镜像单个仓库
./mirror-push -repo project1

# 镜像所有仓库
./mirror-push -all

# 指定镜像目标
./mirror-push -repo project1 -target backup-server

# 异步推送
./mirror-push -repo project1 -async
```

#### 定时镜像

在配置文件中设置 `mirror.schedule` 字段，使用 cron 表达式定义推送频率。系统在守护模式下会按照设定的时间自动执行镜像推送。