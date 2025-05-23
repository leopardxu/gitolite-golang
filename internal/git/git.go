package git

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gitolite-golang/internal/log"
)

// RefUpdate 表示Git引用更新信息
type RefUpdate struct {
	RefName string // 引用名称
	OldHash string // 旧的哈希值
	NewHash string // 新的哈希值
}

// ExecuteGitCommand 执行 Git 命令，增加安全验证
func ExecuteGitCommand(verb, repo, repoBase string) error {
	// 处理仓库路径
	// 确保repo不包含.git后缀，因为我们会在后面添加
	repo = strings.TrimSuffix(repo, ".git")
	// 如果是相对路径，添加repoBase前缀
	repoPath := filepath.Join(repoBase, repo+".git")

	// 处理初始化仓库的命令
	if verb == "init" {
		// 创建仓库目录
		if err := os.MkdirAll(repoPath, 0755); err != nil {
			return fmt.Errorf("创建仓库目录失败: %v", err)
		}

		// 初始化裸仓库
		cmd := exec.Command("git", "init", "--bare")
		cmd.Dir = repoPath
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("初始化仓库失败: %v, 输出: %s", err, output)
		}

		// 设置默认分支为 stable
		cmd = exec.Command("git", "symbolic-ref", "HEAD", "refs/heads/stable")
		cmd.Dir = repoPath
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("设置默认分支失败: %v, 输出: %s", err, output)
		}

		return nil
	}
	// 验证仓库名称 - 允许包含子目录的仓库路径
	// 注意：这里我们允许仓库名称包含斜杠，以支持子目录结构
	// 例如：ffmpeg_repo/ffmpeg
	if strings.Contains(repo, "../") || strings.Contains(repo, "./") {
		return fmt.Errorf("无效的仓库名称: 包含不允许的路径导航符号")
	}

	// 记录仓库路径信息
	log.Log(log.INFO, fmt.Sprintf("处理仓库: %s, 完整路径: %s", repo, repoPath))

	// 检查仓库是否存在，如果不存在且是推送操作，则初始化仓库
	if verb == "git-receive-pack" {
		if err := ensureRepoExists(repoPath); err != nil {
			return fmt.Errorf("确保仓库存在失败: %v", err)
		}
	} else if _, err := os.Stat(repoPath); os.IsNotExist(err) {
		return fmt.Errorf("仓库不存在: %s", repo)
	}

	// 构建 Git 命令
	// 使用仓库路径而不是仓库名称，确保支持子目录结构
	log.Log(log.INFO, fmt.Sprintf("执行Git命令: %s 于仓库: %s", verb, repoPath))
	gitCommand := fmt.Sprintf("%s '%s'", verb, repoPath)

	// 执行命令
	cmd := exec.Command("sh", "-c", gitCommand)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	return cmd.Run()
}

// ensureRepoExists 确保仓库存在，如不存在则初始化
func ensureRepoExists(repoPath string) error {
	// 检查仓库是否已存在
	if _, err := os.Stat(repoPath); err == nil {
		return nil // 仓库已存在
	}

	// 创建仓库目录
	if err := os.MkdirAll(filepath.Dir(repoPath), 0755); err != nil {
		return fmt.Errorf("创建仓库目录失败: %v", err)
	}

	// 初始化裸仓库
	cmd := exec.Command("git", "init", "--bare", repoPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("初始化仓库失败: %v", err)
	}

	log.Log(log.INFO, fmt.Sprintf("成功初始化新仓库: %s", repoPath))
	return nil
}

func InitBareRepository(repoPath string) error {
	// 修正：直接在仓库路径下执行命令
	cmd := exec.Command("git", "init", "--bare")
	cmd.Dir = repoPath // 而不是 filepath.Dir(repoPath)
	return cmd.Run()
}

// SyncRepository 执行仓库同步操作
func SyncRepository(repoPath string, gerritRemoteURL string, repoBase string) error {
	// 获取仓库名称
	log.Log(log.INFO, fmt.Sprintf("开始对仓库 %s 进行全量同步", repoPath))
	// repoName := filepath.Base(repoPath)
	// repoName := strings.TrimSuffix(repoPath, ".git")

	// 检查是否已经有 gerrit 远程仓库
	checkCmd := exec.Command("git", "remote")
	checkCmd.Dir = repoPath
	var out bytes.Buffer
	checkCmd.Stdout = &out
	if err := checkCmd.Run(); err != nil {
		log.Log(log.WARN, fmt.Sprintf("检查远程仓库失败: %v", err))
	} else {
		// 检查输出中是否包含 gerrit
		hasGerrit := false
		scanner := bufio.NewScanner(&out)
		for scanner.Scan() {
			if strings.TrimSpace(scanner.Text()) == "gerrit" {
				hasGerrit = true
				break
			}
		}

		// 如果没有 gerrit 远程仓库，则添加
		if !hasGerrit {
			log.Log(log.INFO, fmt.Sprintf("为仓库 %s 添加 gerrit 远程仓库", repoPath))
			remoteURL := fmt.Sprintf("%s%s", gerritRemoteURL, strings.TrimPrefix(repoPath, repoBase))
			addCmd := exec.Command("git", "remote", "add", "gerrit", remoteURL)
			addCmd.Dir = repoPath
			if err := addCmd.Run(); err != nil {
				log.Log(log.ERROR, fmt.Sprintf("添加 gerrit 远程仓库失败: %v", err))
				// 继续执行，不返回错误
			} else {
				log.Log(log.INFO, fmt.Sprintf("成功添加远程仓库: %s", remoteURL))
			}
		}
	}

	// 执行远程更新
	cmd := exec.Command("git", "fetch", "gerrit", "--tags", "+refs/heads/*:refs/heads/*")
	cmd.Dir = repoPath
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("执行git fetch失败: %w", err)
	}

	cmd = exec.Command("git", "gc")
	cmd.Dir = repoPath
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("执行git gc失败: %w", err)
	}

	return nil
}

// GetUpdatedRefs 获取仓库中最近更新的引用
func GetUpdatedRefs(repoPath string) ([]RefUpdate, error) {
	// 首先需要导入bytes包
	var out bytes.Buffer

	// 获取当前所有引用
	showRefCmd := exec.Command("git", "show-ref")
	showRefCmd.Dir = repoPath
	showRefCmd.Stdout = &out

	if err := showRefCmd.Run(); err != nil {
		return nil, fmt.Errorf("执行git show-ref失败: %w", err)
	}

	currentRefs := make(map[string]string)
	scanner := bufio.NewScanner(&out)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) == 2 {
			hash := parts[0]
			refName := parts[1]
			currentRefs[refName] = hash
		}
	}

	// 获取最近的引用日志
	out.Reset()
	reflogCmd := exec.Command("git", "reflog", "--all", "--format=%H %gd %gs", "-n", "20")
	reflogCmd.Dir = repoPath
	reflogCmd.Stdout = &out

	if err := reflogCmd.Run(); err != nil {
		// 如果reflog命令失败，可能是新仓库，返回空结果
		return []RefUpdate{}, nil
	}

	// 解析reflog输出，提取引用更新信息
	var updates []RefUpdate
	processedRefs := make(map[string]bool)

	scanner = bufio.NewScanner(&out)
	for scanner.Scan() {
		line := scanner.Text()
		// 格式: <hash> <refname> <message>
		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 3 {
			continue
		}

		newHash := parts[0]
		refNameRaw := parts[1]
		message := parts[2]

		// 从reflog引用名提取实际引用名
		// 例如: refs/heads/master@{0} -> refs/heads/master
		refName := strings.Split(refNameRaw, "@")[0]

		// 避免处理重复的引用
		if processedRefs[refName] {
			continue
		}

		// 尝试从消息中提取旧哈希值
		// 格式通常是: "update by push" 或 "commit: <message>"
		oldHash := ""
		if strings.Contains(message, "update by push") || strings.Contains(message, "commit:") {
			// 获取前一个引用的哈希值
			oldHashCmd := exec.Command("git", "rev-parse", refName+"@{1}")
			oldHashCmd.Dir = repoPath
			oldHashBytes, err := oldHashCmd.Output()
			if err == nil {
				oldHash = strings.TrimSpace(string(oldHashBytes))
			}
		}

		// 如果无法从reflog获取旧哈希，使用空哈希
		if oldHash == "" {
			oldHash = "0000000000000000000000000000000000000000"
		}

		// 记录此引用已处理
		processedRefs[refName] = true

		// 添加到更新列表
		updates = append(updates, RefUpdate{
			RefName: refName,
			OldHash: oldHash,
			NewHash: newHash,
		})
	}

	// 如果没有找到任何更新，返回空列表
	if len(updates) == 0 {
		return []RefUpdate{}, nil
	}

	return updates, nil
}
