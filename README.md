# Gitolite-Golang - Git 仓库管理服务
# 简单版本gitolite 实现

## 功能概述

本项目是基于 Go 语言实现的 Git 仓库管理服务，主要提供以下核心功能：

1. **SSH 密钥管理**
   - 从 Gerrit 同步用户 SSH 公钥
   - 自动更新 authorized_keys 文件
   - 支持密钥格式转换

2. **仓库访问控制**
   - 集成 Gerrit 权限系统
   - 支持多种 Git 操作权限检查

3. **仓库管理**
   - 自动创建新仓库
   - 支持 Gerrit 仓库同步
   - 处理 Git 初始化请求

## 快速开始

### 1. 安装

```bash
go build -o gitolite-shell ./cmd/gitolite-shell
sudo mv gitolite-shell /usr/bin/
```
### 2. 配置

配置文件路径: /home/git/.gitolite/config.yaml
```yaml
repo_base: /home/git/repositories
gerrit_url: https://gerrit.url.com
gerrit_user: gitadmin
gerrit_api_token: your_api_token
gerrit_remote_url: ssh://git@gerrit.url.com:29418
authorized_keys: /home/git/.ssh/authorized_keys
log:
  path: /home/git/gitolite/logs/gitolite.log
  level: INFO
  rotation: daily
  compress: true
```

### 3. 运行
```bash
# 默认模式 - 处理 Git SSH 请求
./gitolite-shell

# 同步模式 - 一次性同步密钥
./gitolite-shell -sync

# 守护模式 - 后台运行定期同步密钥
./gitolite-shell -daemon
```