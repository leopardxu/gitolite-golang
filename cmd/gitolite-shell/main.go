package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gitolite-golang/internal/config"
	"gitolite-golang/internal/gerrit"
	"gitolite-golang/internal/git"
	"gitolite-golang/internal/log"
	"gitolite-golang/internal/sync"
)

func main() {
	// 解析命令行参数
	syncMode := flag.Bool("sync", false, "仅运行同步任务")
	daemonMode := flag.Bool("daemon", false, "以守护进程模式运行同步任务")
	configPath := flag.String("config", "/home/git/.gitolite/config.yaml", "配置文件路径")
	flag.Parse()

	// 初始化配置和日志
	cfg, err := initConfigAndLogging(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "初始化失败: %v\n", err)
		os.Exit(1)
	}

	// 根据运行模式分发处理
	switch {
	case *syncMode:
		if err := runSyncMode(cfg); err != nil {
			log.Log(log.ERROR, err.Error())
			os.Exit(1)
		}
	case *daemonMode:
		runDaemonMode(cfg)
	default:
		if err := runNormalMode(cfg); err != nil {
			log.Log(log.ERROR, err.Error())
			os.Exit(1)
		}
	}
}

// 初始化配置和日志
func initConfigAndLogging(configPath string) (*config.Config, error) {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("加载配置失败: %w", err)
	}

	// 设置日志级别
	logLevel := getLogLevel(cfg.Log.Level)

	// 确保日志目录存在
	if err := os.MkdirAll(filepath.Dir(cfg.Log.Path), 0755); err != nil {
		return nil, fmt.Errorf("创建日志目录失败: %w", err)
	}

	if err := log.Init(cfg.Log.Path, logLevel); err != nil {
		return nil, fmt.Errorf("初始化日志失败: %w", err)
	}

	log.Log(log.INFO, "Gitolite-Golang 启动成功")
	return cfg, nil
}

// 获取日志级别
func getLogLevel(level string) log.LogLevel {
	switch level {
	case "WARN":
		return log.WARN
	case "ERROR":
		return log.ERROR
	default:
		return log.INFO
	}
}

// 同步模式处理
func runSyncMode(cfg *config.Config) error {
	keys, err := sync.FetchGerritSSHKeys(cfg.GerritURL, cfg.GerritUser, cfg.GerritAPIToken)
	if err != nil {
		return fmt.Errorf("获取Gerrit SSH密钥失败: %w (URL: %s, User: %s)",
			err, cfg.GerritURL, cfg.GerritUser)
	}

	gitoliteKeys := sync.ConvertToGitoliteFormat(keys)
	if err := sync.WriteAuthorizedKeys(gitoliteKeys, cfg.AuthorizedKeys); err != nil {
		return fmt.Errorf("写入authorized_keys失败: %w (Path: %s)",
			err, cfg.AuthorizedKeys)
	}

	log.Log(log.INFO, "成功从Gerrit同步SSH密钥")
	return nil
}

// 守护模式处理
func runDaemonMode(cfg *config.Config) {
	done := make(chan bool)
	sync.StartSyncTask(cfg.GerritURL, cfg.GerritUser, cfg.GerritAPIToken, cfg.AuthorizedKeys)
	<-done
}

// 正常模式处理
func runNormalMode(cfg *config.Config) error {
	// 1. 解析SSH原始命令
	sshCommand := os.Getenv("SSH_ORIGINAL_COMMAND")
	if sshCommand == "" {
		return fmt.Errorf("未设置SSH_ORIGINAL_COMMAND环境变量")
	}

	log.Log(log.INFO, fmt.Sprintf("处理SSH命令: %s", sshCommand))

	// 直接解析命令，不使用protocol包的函数
	parts := strings.Fields(sshCommand)
	if len(parts) < 2 {
		return fmt.Errorf("无效的SSH命令格式")
	}

	verb := parts[0]
	repo := strings.Trim(strings.Join(parts[1:], " "), "'\"")

	// 处理可能的绝对路径问题
	repo = strings.TrimPrefix(repo, "/")

	// 获取用户信息，优先使用GL_USER，如果未设置则尝试使用SSH_USER或USER
	user := os.Getenv("GL_USER")
	if user == "" {
		user = os.Getenv("SSH_USER")
		if user == "" {
			user = os.Getenv("USER")
			if user == "" {
				return fmt.Errorf("未能确定用户身份，GL_USER、SSH_USER和USER环境变量均未设置")
			}
		}
		log.Log(log.WARN, fmt.Sprintf("GL_USER未设置，使用备用用户: %s", user))
	}

	// 2. 处理特殊命令
	switch verb {
	case "init":
		return handleRepoInit(cfg, user, repo)
	case "git-upload-pack", "git-receive-pack":
		// git-receive-pack 命令同时处理普通提交和标签操作
		return handleGitOperation(cfg, user, repo, verb)
	case "git-upload-archive":
		return handleGitArchive(cfg, user, repo)
	case "gerrit-replication":
		return handleGerritReplication(cfg, user, repo)
	default:
		return fmt.Errorf("不支持的Git命令: %s", verb)
	}
}

// 处理Gerrit replication同步任务
func handleGerritReplication(cfg *config.Config, user, repo string) error {
	// 记录SSH连接信息
	remoteAddr := os.Getenv("SSH_CLIENT")
	pid := os.Getpid()
	log.Log(log.INFO, fmt.Sprintf("%d ssh ARGV=server-%s SOC=git-receive-pack '%s' FROM=%s",
		pid, user, repo, remoteAddr))

	// 记录mirror pre_git信息
	log.Log(log.INFO, fmt.Sprintf("%d mirror,pre_git,%s,user=,sender=%s,mode=copy",
		pid, repo, user))

	// 检查是否是replication专用账户
	if user != "gerrit-replication" && user != "git" {
		log.Log(log.WARN, fmt.Sprintf("非授权用户尝试执行replication操作: %s", user))
		return fmt.Errorf("只有gerrit-replication用户可执行此操作")
	}

	// 获取仓库路径
	repoPath := filepath.Join(cfg.RepoBase, repo+".git")

	// 记录执行的git命令
	log.Log(log.INFO, fmt.Sprintf("%d system,git,shell,-c,git-receive-pack '%s'",
		pid, repoPath))

	// 检查仓库是否存在
	if _, err := os.Stat(repoPath); os.IsNotExist(err) {
		log.Log(log.INFO, fmt.Sprintf("仓库不存在，自动创建: %s", repo))
		if err := handleRepoInit(cfg, user, repo); err != nil {
			return err
		}
	}

	// 执行同步操作，传入配置中的 Gerrit 远程 URL：
	if err := git.SyncRepository(repoPath, cfg.GerritRemoteURL, cfg.RepoBase); err != nil {
		log.Log(log.ERROR, fmt.Sprintf("同步仓库失败: %s, 错误: %v", repo, err))
		return fmt.Errorf("同步仓库失败: %w", err)
	}

	// 记录引用更新信息
	refs, err := git.GetUpdatedRefs(repoPath)
	if err == nil && len(refs) > 0 {
		for _, ref := range refs {
			log.Log(log.INFO, fmt.Sprintf("%d update %s (git) bypass %s %s %s",
				pid, repoPath, ref.RefName, ref.OldHash, ref.NewHash))
		}
	}

	// 记录post_git信息
	hostname, _ := os.Hostname()
	log.Log(log.INFO, fmt.Sprintf("%d post_git() on %s", pid, hostname))
	log.Log(log.INFO, fmt.Sprintf("%d mirror,post_git,%s,user=,sender=%s,mode=copy",
		pid, repo, user))

	// 记录结束标记
	log.Log(log.INFO, fmt.Sprintf("%d END", pid))

	return nil
}

// 处理仓库初始化
func handleRepoInit(cfg *config.Config, user, repo string) error {
	repoPath := filepath.Join(cfg.RepoBase, repo+".git")

	// 检查仓库是否已存在
	if _, err := os.Stat(repoPath); err == nil {
		log.Log(log.INFO, fmt.Sprintf("仓库已存在，跳过初始化: %s", repo))
		return nil
	}

	// 创建仓库目录
	if err := os.MkdirAll(repoPath, 0755); err != nil {
		return fmt.Errorf("创建仓库目录失败: %w", err)
	}

	// 修正：在仓库目录内执行git init --bare
	cmd := exec.Command("git", "init", "--bare")
	cmd.Dir = repoPath // 设置工作目录为仓库路径
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("初始化裸仓库失败: %w", err)
	}

	log.Log(log.INFO, fmt.Sprintf("用户 %s 成功创建仓库 %s", user, repo))

	// 创建仓库后进行全量同步
	log.Log(log.INFO, fmt.Sprintf("开始对新仓库 %s 进行全量同步", repo))
	if err := git.SyncRepository(repoPath, cfg.GerritRemoteURL, cfg.RepoBase); err != nil {
		log.Log(log.WARN, fmt.Sprintf("新仓库 %s 同步失败: %v", repo, err))
		// 这里我们只记录警告，不返回错误，因为仓库已经创建成功
	} else {
		log.Log(log.INFO, fmt.Sprintf("新仓库 %s 同步成功", repo))
	}

	return nil
}

// 处理Git操作
func handleGitOperation(cfg *config.Config, user, repo, verb string) error {
	// 确保仓库名称不重复添加.git后缀
	repoBase := strings.TrimSuffix(repo, ".git")

	// 只对非同步用户进行权限检查
	if user != "gerrit-replication" && user != "git" {
		allowed, err := gerrit.CheckAccess(cfg.GerritURL, user, repoBase,
			cfg.GerritUser, cfg.GerritAPIToken)
		if err != nil {
			return fmt.Errorf("检查访问权限失败: %w", err)
		}
		if !allowed {
			return fmt.Errorf("用户 %s 无权限访问仓库 %s", user, repoBase)
		}
	} else {
		log.Log(log.INFO, fmt.Sprintf("同步用户 %s 操作仓库 %s，跳过权限检查", user, repoBase))
	}

	// 检查仓库是否存在
	repoPath := filepath.Join(cfg.RepoBase, repoBase+".git")
	if _, err := os.Stat(repoPath); os.IsNotExist(err) {
		// 如果是推送操作且仓库不存在，则创建仓库
		if verb == "git-receive-pack" {
			log.Log(log.INFO, fmt.Sprintf("仓库不存在，自动创建: %s", repoBase))
			if err := handleRepoInit(cfg, user, repoBase); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("仓库不存在: %s", repoPath)
		}
	}

	// 执行Git命令，传递不带.git后缀的仓库名
	err := git.ExecuteGitCommand(verb, repoBase, cfg.RepoBase)

	// 如果是推送操作，检查是否有标签更新
	if verb == "git-receive-pack" && err == nil {
		// 记录引用更新信息，特别关注标签
		refs, refErr := git.GetUpdatedRefs(repoPath)
		if refErr == nil && len(refs) > 0 {
			pid := os.Getpid()
			for _, ref := range refs {
				// 记录所有引用更新，特别标记标签操作
				if strings.HasPrefix(ref.RefName, "refs/tags/") {
					log.Log(log.INFO, fmt.Sprintf("检测到标签操作: %s", ref.RefName))
				}
				log.Log(log.INFO, fmt.Sprintf("%d update %s (git) bypass %s %s %s",
					pid, repoPath, ref.RefName, ref.OldHash, ref.NewHash))
			}
		}
	}

	return err
}

// 处理Git归档操作
func handleGitArchive(cfg *config.Config, user, repo string) error {
	// 确保仓库名称不重复添加.git后缀
	repoBase := strings.TrimSuffix(repo, ".git")

	// 只对非同步用户进行权限检查
	if user != "gerrit-replication" && user != "git" {
		allowed, err := gerrit.CheckAccess(cfg.GerritURL, user, repoBase,
			cfg.GerritUser, cfg.GerritAPIToken)
		if err != nil {
			return fmt.Errorf("检查归档权限失败: %w", err)
		}
		if !allowed {
			return fmt.Errorf("用户 %s 无权限归档仓库 %s", user, repoBase)
		}
	} else {
		log.Log(log.INFO, fmt.Sprintf("同步用户 %s 归档仓库 %s，跳过权限检查", user, repoBase))
	}

	// 检查仓库是否存在
	repoPath := filepath.Join(cfg.RepoBase, repoBase+".git")
	if _, err := os.Stat(repoPath); os.IsNotExist(err) {
		return fmt.Errorf("仓库不存在: %s", repoBase)
	}

	return git.ExecuteGitCommand("git-upload-archive", repoBase, cfg.RepoBase)
}
