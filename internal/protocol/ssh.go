package protocol

import (
	"fmt"
	"log"
	"regexp"
	"strings"
)

// ParseSSHCommand 解析 SSH 请求
func ParseSSHCommand(cmd string) (verb, repo string, err error) {
	log.Printf("[DEBUG] 开始解析SSH命令: %s", cmd)

	if cmd == "" {
		log.Printf("[ERROR] SSH_ORIGINAL_COMMAND 环境变量未设置")
		return "", "", fmt.Errorf("SSH_ORIGINAL_COMMAND 环境变量未设置")
	}

	// 处理特殊命令，如创建仓库的命令
	log.Printf("[INFO] cmd: %s ",cmd)
	log.Printf("[INFO] cmd: %s ",cmd)
	if strings.Contains(cmd, "mkdir -p") && strings.Contains(cmd, "git init --bare") {
		log.Printf("[DEBUG] 检测到创建仓库命令")
		// 这是一个创建仓库的命令，提取仓库路径
		repoPathStart := strings.Index(cmd, "'")
		repoPathEnd := strings.Index(cmd[repoPathStart+1:], "'")
		log.Printf("[DEBUG] 仓库路径引号位置: 开始=%d, 结束=%d", repoPathStart, repoPathEnd)

		if repoPathStart >= 0 && repoPathEnd >= 0 {
			repoPath := cmd[repoPathStart+1 : repoPathStart+1+repoPathEnd]
			log.Printf("[DEBUG] 提取的仓库路径: %s", repoPath)

			// 修改：使用完整路径作为仓库名称，而不仅仅是最后一部分
			repoName := repoPath

			// 如果路径以 .git 结尾，移除它
			if strings.HasSuffix(repoName, ".git") {
				repoName = repoName[:len(repoName)-4]
				log.Printf("[DEBUG] 移除.git后缀后的仓库路径: %s", repoName)
			}

			// 检查仓库名称是否为绝对路径
			// if strings.HasPrefix(repoName, "/") {
			// 	log.Printf("[ERROR] 无效的仓库名称: 仓库名称不能是绝对路径 - %s", repoName)
			// 	return "", "", fmt.Errorf("无效的仓库名称: 仓库名称不能是绝对路径")
			// }

			log.Printf("[INFO] 解析结果: verb=init, repo=%s", repoName)
			return "init", repoName, nil
		}
		log.Printf("[ERROR] 无法从命令中提取仓库路径")
	}

	// 原有的 git 命令解析逻辑
	log.Printf("[DEBUG] 使用正则表达式解析git命令")
	parts := strings.Split(cmd, " ")
	log.Printf("[DEBUG] 命令分割结果: %v", parts)

	if len(parts) < 2 {
		log.Printf("[ERROR] 无效的SSH命令: %s", cmd)
		return "", "", fmt.Errorf("invalid SSH command: %s", cmd)
	}

	re := regexp.MustCompile(`^(git-upload-pack|git-receive-pack) '?(.*?)'?$`)
	matches := re.FindStringSubmatch(cmd)
	log.Printf("[DEBUG] 正则匹配结果: %v", matches)

	if len(matches) != 3 {
		log.Printf("[ERROR] 无效的SSH命令: %s", cmd)
		return "", "", fmt.Errorf("invalid SSH command: %s", cmd)
	}

	// 检查仓库名称是否为绝对路径
	if strings.HasPrefix(matches[2], "/") {
		log.Printf("[ERROR] 无效的仓库名称: 仓库名称不能是绝对路径 - %s", matches[2])
		return "", "", fmt.Errorf("无效的仓库名称: 仓库名称不能是绝对路径")
	}

	log.Printf("[INFO] 解析结果: verb=%s, repo=%s", matches[1], matches[2])
	return matches[1], matches[2], nil
}
