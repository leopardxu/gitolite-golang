# Gitolite-Golang 镜像复制功能

## 功能概述

Gitolite-Golang 的镜像复制功能允许将 Git 仓库自动镜像到一个或多个远程服务器。这个功能类似于传统 Gitolite 的镜像功能，但与 Gerrit 集成更加紧密。

## 配置说明

镜像复制功能通过 `config.yaml` 文件进行配置。以下是配置示例：

```yaml
# 镜像配置
mirror:
  enabled: true  # 是否启用镜像功能
  schedule: "@hourly"  # 定时镜像调度（Cron表达式，@hourly表示每小时执行一次）
  targets:
    - name: backup-server  # 镜像目标名称
      url: ssh://git@backup-server.example.com/git-mirror/  # 镜像服务器URL
      enabled: true  # 是否启用此镜像目标
      async: true    # 是否异步推送（不阻塞主操作）
      timeout: 300   # 推送超时时间（秒）
      all_repos: false  # 是否镜像所有仓库
      repos:  # 需要镜像的仓库列表（如果all_repos为false）
        - project1
        - project2
        - group1/*  # 支持通配符
    
    - name: disaster-recovery
      url: ssh://git@dr-server.example.com/repositories/
      enabled: true
      async: false  # 同步推送（等待推送完成）
      timeout: 600
      all_repos: true  # 镜像所有仓库
```

### 配置项说明

- `enabled`: 是否启用镜像功能
- `schedule`: 定时镜像调度的 Cron 表达式，例如：
  - `@hourly`: 每小时执行一次
  - `@daily`: 每天执行一次
  - `@weekly`: 每周执行一次
  - `0 0 * * *`: 每天午夜执行
  - `0 */4 * * *`: 每4小时执行一次

每个镜像目标的配置项：

- `name`: 镜像目标的名称（用于日志和识别）
- `url`: 镜像服务器的 URL，格式为 `ssh://user@host/path/to/repos/`
- `enabled`: 是否启用此镜像目标
- `async`: 是否异步推送（不阻塞主操作）
- `timeout`: 推送超时时间（秒）
- `all_repos`: 是否镜像所有仓库
- `repos`: 需要镜像的仓库列表（如果 `all_repos` 为 false）
  - 支持精确匹配仓库名
  - 支持通配符匹配，例如 `group/*` 表示镜像 group 下的所有仓库

## 工作原理

镜像复制功能通过以下两种方式触发：

1. **按需触发**：当用户向仓库推送更新时，`post-receive` 钩子会自动触发镜像推送操作。

2. **定时触发**：根据配置的 `schedule` 表达式，系统会定期执行镜像推送操作，确保所有仓库都与镜像保持同步。

镜像推送使用 `git push --mirror` 命令，确保所有引用（包括分支、标签等）都被完整复制到镜像服务器。

## 注意事项

1. **SSH 密钥配置**：确保 Gitolite-Golang 服务器能够通过 SSH 密钥无密码访问镜像服务器。

2. **网络连接**：确保 Gitolite-Golang 服务器能够通过网络访问镜像服务器。

3. **权限设置**：确保镜像服务器上的用户具有创建和更新仓库的权限。

4. **异步推送**：启用异步推送可以提高主服务器的响应速度，但可能导致镜像服务器上的数据有短暂的延迟。

5. **超时设置**：对于大型仓库，可能需要增加超时时间以确保推送能够完成。

## 故障排除

如果镜像推送失败，请检查以下几点：

1. 检查日志文件中的错误信息。

2. 确认 SSH 密钥配置正确，可以通过手动执行 `ssh git@mirror-server` 测试连接。

3. 检查镜像服务器上的磁盘空间和权限设置。

4. 如果使用异步推送，检查是否有后台任务失败的日志。

5. 对于大型仓库，尝试增加超时时间。