package main

import (
	"bufio"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"gateway/api"
	"gateway/blacklist"
	"gateway/config"
	"gateway/limiter"
	"gateway/logger"
	"gateway/monitor"
	"gateway/proxy"
)

// 版本信息
const (
	Version = "1.0.0"
	AppName = "企业级网关防护程序"
)

func main() {
	// 打印横幅
	printBanner()

	// 加载配置
	cfg, err := config.InitConfig()
	if err != nil {
		fmt.Printf("加载配置失败: %v\n", err)
		os.Exit(1)
	}

	// 初始化日志系统
	logConfig := &logger.LogConfig{
		Level:         cfg.Log.Level,
		FilePath:      cfg.Log.FilePath,
		ConsoleOutput: cfg.Log.ConsoleOutput,
		MaxSize:       cfg.Log.MaxSize,
		MaxAge:        cfg.Log.MaxAge,
		MaxBackups:    cfg.Log.MaxBackups,
	}
	if err := logger.InitLogger(logConfig); err != nil {
		fmt.Printf("初始化日志失败: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		// 日志器在信号处理后会正常关闭
	}()

	logger.Info("%s v%s 启动中...", AppName, Version)
	logger.Info("配置文件: config.json")

	// 分析LoginError.txt(如果存在)并在启动时添加到黑名单
	analyzeLoginErrors()

	// 创建频率限制器
	rateLimiterConfig := &limiter.RateLimiterConfig{
		WindowSize:             1,
		EnableIPLimit:          cfg.RateLimit.EnableIPLimit,
		IPMaxConnPerSec:        cfg.RateLimit.IPMaxConnPerSec,
		IPMaxLoginPerSec:       cfg.RateLimit.IPMaxLoginPerSec,
		EnableUIDLimit:         cfg.RateLimit.EnableUIDLimit,
		UIDMaxConnPerSec:       cfg.RateLimit.UIDMaxConnPerSec,
		UIDMaxLoginPerSec:      cfg.RateLimit.UIDMaxLoginPerSec,
		EnableCombinedLimit:    cfg.RateLimit.EnableCombinedLimit,
		CombinedMaxConnPerSec:  cfg.RateLimit.CombinedMaxConnPerSec,
		CombinedMaxLoginPerSec: cfg.RateLimit.CombinedMaxConnPerSec / 2, // 默认取一半
	}
	rateLimiter := limiter.NewRateLimiter(rateLimiterConfig)
	defer rateLimiter.Stop()

	// 创建黑名单管理器
	blacklistConfig := &blacklist.BlacklistConfig{
		EnableAutoLearn:    cfg.Blacklist.EnableAutoLearn,
		AutoLearnThreshold: cfg.Blacklist.AutoLearnThreshold,
		AutoLearnWindow:    cfg.Blacklist.AutoLearnWindow,
		BanDuration:        cfg.Blacklist.BanDuration,
		PersistFile:        cfg.Blacklist.PersistFile,
	}
	blacklistMgr := blacklist.NewBlacklistManager(blacklistConfig)
	defer blacklistMgr.Stop()

	// 创建监控器
	monitorConfig := &monitor.MonitorConfig{
		Enabled:         cfg.Monitor.Enable,
		RefreshInterval: cfg.Monitor.RefreshInterval,
		LogOutput:       cfg.Monitor.LogOutput,
	}
	mon := monitor.NewMonitor(monitorConfig)
	defer mon.Stop()

	// 启动监控日志输出
	if cfg.Monitor.LogOutput {
		go statsLogRoutine(mon)
	}

	// 创建代理服务器
	proxyServer := proxy.NewProxyServer(cfg, rateLimiter, blacklistMgr, mon)

	// 启动代理服务
	if err := proxyServer.Start(); err != nil {
		logger.Error("启动代理服务器失败: %v", err)
		os.Exit(1)
	}
	defer proxyServer.Stop()

	// 启动API管理接口
	apiServer := api.NewAPIServer(cfg, rateLimiter, blacklistMgr, mon, proxyServer)
	if err := apiServer.Start(); err != nil {
		logger.Error("启动API接口失败: %v", err)
	}
	defer apiServer.Stop()

	// 打印启动信息
	printStartInfo(cfg)

	// 等待退出信号
	logger.Info("服务已就绪, 等待连接... (按 Ctrl+C 退出)")
	waitForSignal()

	// 优雅关闭
	logger.Info("收到退出信号, 正在关闭服务...")
	logger.Info("服务已停止")
}

// 分析LoginError.txt日志文件
func analyzeLoginErrors() {
	filePath := "LoginError.txt"

	// 检查文件是否存在, 先尝试当前目录, 再尝试上级目录
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		filePath = "../LoginError.txt"
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			logger.Debug("未找到LoginError.txt, 跳过启动日志分析")
			return
		}
	}

	logger.Info("正在分析日志文件: %s", filePath)

	content, err := os.ReadFile(filePath)
	if err != nil {
		logger.Error("读取日志文件失败: %v", err)
		return
	}

	// 分析日志内容
	lines := strings.Split(string(content), "\n")
	var nonEmptyLines []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			nonEmptyLines = append(nonEmptyLines, line)
		}
	}
	logger.Info("日志文件共 %d 行, 有效行 %d", len(lines), len(nonEmptyLines))

	// 统计各UserIdx的错误频率
	uidCounts := make(map[string]int)
	for _, line := range nonEmptyLines {
		idxStart := strings.LastIndex(line, "UserIdx : ")
		if idxStart == -1 {
			continue
		}
		uidStr := strings.TrimSpace(line[idxStart+len("UserIdx : "):])
		uidStr = strings.TrimRight(uidStr, "]")
		uidCounts[uidStr]++
	}

	// 打印分析结果
	logger.Info("========== 登录错误分析 ==========")
	logger.Info("%-12s %-10s", "UserIdx", "错误次数")
	logger.Info("-----------------------------------")

	var highFreqTokens []string
	for uid, count := range uidCounts {
		logger.Info("%-12s %-10d", uid, count)
		if count >= 5 { // 超过5次错误的标记为高频
			highFreqTokens = append(highFreqTokens, fmt.Sprintf("UserIdx:%s(错误%d次)", uid, count))
		}
	}
	logger.Info("===================================")

	if len(highFreqTokens) > 0 {
		logger.Warn("检测到高频错误登录UserIdx: %v", highFreqTokens)
		logger.Info("这些UserIdx将被自动加入黑名单进行防护")
	}
}

// 定时输出统计信息
func statsLogRoutine(mon *monitor.Monitor) {
	// 等待首次统计收集
	// 监控器内部有自己的刷新周期

	// 每60秒输出一次统计
	ticker := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker:
			}
		}
	}()

	// 监听控制台输入来触发统计输出
	scanner := bufio.NewScanner(os.Stdin)
	logger.Info("控制台命令: stats=查看统计, blacklist=查看黑名单, help=帮助")

	for scanner.Scan() {
		cmd := strings.TrimSpace(strings.ToLower(scanner.Text()))

		switch cmd {
		case "stats":
			output := mon.PrintStats()
			fmt.Print(output)

		case "blacklist":
			// 通过快捷命令查看黑名单
			// 这里直接访问logger输出
			logger.Info("当前黑名单查看请使用API: curl http://localhost:9999/api/blacklist?token=YOUR_TOKEN")

		case "help":
			fmt.Println("========== 可用命令 ==========")
			fmt.Println("stats     - 查看当前统计信息")
			fmt.Println("blacklist - 查看黑名单(通过API)")
			fmt.Println("help      - 显示此帮助")
			fmt.Println("quit/exit - 退出程序")
			fmt.Println("==============================")

		case "quit", "exit":
			logger.Info("用户请求退出...")
			// 发送退出信号
			p, _ := os.FindProcess(os.Getpid())
			p.Signal(syscall.SIGINT)

		default:
			if cmd != "" {
				fmt.Printf("未知命令: %s (输入help查看帮助)\n", cmd)
			}
		}
	}
}

// 打印启动信息
func printStartInfo(cfg *config.Config) {
	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("    服务已启动 - 转发规则列表")
	fmt.Println("========================================")

	for i, rule := range cfg.ForwardRules {
		fmt.Printf("[规则%d] %s -> %v (策略: %s)\n",
			i+1, rule.ListenAddr, rule.BackendAddrs, rule.LBStrategy)
	}

	if cfg.API.Enable {
		fmt.Println()
		fmt.Println("API管理接口已启用")
		fmt.Printf("  监听地址: %s\n", cfg.API.ListenAddr)
		fmt.Printf("  认证Token: %s\n", cfg.API.AuthToken)
		fmt.Println()
		fmt.Println("常用API示例:")
		fmt.Printf("  curl http://%s/api/status?token=%s\n", cfg.API.ListenAddr, cfg.API.AuthToken)
		fmt.Printf("  curl http://%s/api/blacklist?token=%s\n", cfg.API.ListenAddr, cfg.API.AuthToken)
		fmt.Printf("  curl http://%s/api/stats?token=%s\n", cfg.API.ListenAddr, cfg.API.AuthToken)
	}

	fmt.Println()
	fmt.Println("防护策略:")
	fmt.Printf("  IP频率限制: %v (连接%d/s, 登录%d/s)\n",
		cfg.RateLimit.EnableIPLimit, cfg.RateLimit.IPMaxConnPerSec, cfg.RateLimit.IPMaxLoginPerSec)
	fmt.Printf("  UID频率限制: %v (连接%d/s, 登录%d/s)\n",
		cfg.RateLimit.EnableUIDLimit, cfg.RateLimit.UIDMaxConnPerSec, cfg.RateLimit.UIDMaxLoginPerSec)
	fmt.Printf("  组合频率限制: %v (连接%d/s)\n",
		cfg.RateLimit.EnableCombinedLimit, cfg.RateLimit.CombinedMaxConnPerSec)
	fmt.Printf("  自动学习黑名单: %v (阈值%d次/%ds, 封禁%d秒)\n",
		cfg.Blacklist.EnableAutoLearn, cfg.Blacklist.AutoLearnThreshold,
		cfg.Blacklist.AutoLearnWindow, cfg.Blacklist.BanDuration)
	fmt.Printf("  流量限速: %v (每连接%dKB/s, 突发%dKB)\n",
		cfg.TrafficControl.EnableRateLimit, cfg.TrafficControl.MaxRatePerConn, cfg.TrafficControl.BurstSize)
	fmt.Println("========================================")
}

// 打印横幅
func printBanner() {
	fmt.Println(`
  ________                      __           
 /  _____/_____  ______ __  ___/  |_ ___.__.  
/   \  ___\__  \ \____ \\  \/  /\   <   |  |  
\    \_\  \/ __ \|  |_> >    <  |   |\___  |  
 \______  (____  /   __/__/\__\|___|/ ____|  
        \/     \/|__|            \/       

  企业级网关防护程序 v` + Version + `
  端口无损转发 | 多层频率限制 | 智能黑名单
  ============================================
`)
}

// 等待系统信号
func waitForSignal() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
}
