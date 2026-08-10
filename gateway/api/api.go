package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"gateway/blacklist"
	"gateway/config"
	"gateway/limiter"
	"gateway/logger"
	"gateway/monitor"
	"gateway/protocol"
	"gateway/proxy"
	"gateway/web"
)

// API服务器
type APIServer struct {
	config       *config.Config
	rateLimiter  *limiter.RateLimiter
	blacklistMgr *blacklist.BlacklistManager
	monitor      *monitor.Monitor
	proxyServer  *proxy.ProxyServer
	server       *http.Server
	mux          *http.ServeMux
}

// API响应结构
type APIResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// 创建API服务器
func NewAPIServer(cfg *config.Config, rl *limiter.RateLimiter, bl *blacklist.BlacklistManager, mon *monitor.Monitor, ps *proxy.ProxyServer) *APIServer {
	api := &APIServer{
		config:       cfg,
		rateLimiter:  rl,
		blacklistMgr: bl,
		monitor:      mon,
		proxyServer:  ps,
		mux:          http.NewServeMux(),
	}

	api.registerRoutes()

	return api
}

// 注册路由
func (api *APIServer) registerRoutes() {
	// 状态和统计
	api.mux.HandleFunc("/api/status", api.authMiddleware(api.handleStatus))
	api.mux.HandleFunc("/api/stats", api.authMiddleware(api.handleStats))
	api.mux.HandleFunc("/api/stats/snapshot", api.authMiddleware(api.handleStatsSnapshot))

	// 黑名单管理
	api.mux.HandleFunc("/api/blacklist", api.authMiddleware(api.handleBlacklist))
	api.mux.HandleFunc("/api/blacklist/add", api.authMiddleware(api.handleBlacklistAdd))
	api.mux.HandleFunc("/api/blacklist/remove", api.authMiddleware(api.handleBlacklistRemove))
	api.mux.HandleFunc("/api/blacklist/clear", api.authMiddleware(api.handleBlacklistClear))

	// 白名单管理
	api.mux.HandleFunc("/api/whitelist", api.authMiddleware(api.handleWhitelist))
	api.mux.HandleFunc("/api/whitelist/add", api.authMiddleware(api.handleWhitelistAdd))

	// 频率限制管理
	api.mux.HandleFunc("/api/ratelimit/active", api.authMiddleware(api.handleRateLimitActive))
	api.mux.HandleFunc("/api/ratelimit/reset", api.authMiddleware(api.handleRateLimitReset))

	// 配置管理
	api.mux.HandleFunc("/api/config", api.authMiddleware(api.handleConfig))
	api.mux.HandleFunc("/api/config/reload", api.authMiddleware(api.handleConfigReload))

	// 日志分析
	api.mux.HandleFunc("/api/analysis/ip", api.authMiddleware(api.handleIPAnalysis))
	api.mux.HandleFunc("/api/analysis/uid", api.authMiddleware(api.handleUIDAnalysis))
	api.mux.HandleFunc("/api/analysis/top-attackers", api.authMiddleware(api.handleTopAttackers))
	api.mux.HandleFunc("/api/analysis/log", api.authMiddleware(api.handleLogAnalysis))

	// 健康检查(无需认证)
	api.mux.HandleFunc("/api/health", api.handleHealth)

	// 协议层统计 (奔溃预警数据)
	api.mux.HandleFunc("/api/protocol/stats", api.authMiddleware(api.handleProtocolStats))

	// Web可视化仪表盘路由
	api.mux.HandleFunc("/", api.handleDashboard)
	api.mux.HandleFunc("/dashboard", api.handleDashboard)
}

// 认证中间件
func (api *APIServer) authMiddleware(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 如果未配置Token，则不需要认证
		if api.config.API.AuthToken == "" {
			handler(w, r)
			return
		}

		token := r.Header.Get("Authorization")
		token = strings.TrimPrefix(token, "Bearer ")

		// 也支持从URL参数中获取
		if token == "" {
			token = r.URL.Query().Get("token")
		}

		if token != api.config.API.AuthToken {
			api.writeJSON(w, http.StatusUnauthorized, APIResponse{
				Code:    401,
				Message: "认证失败: 无效的Token",
			})
			return
		}

		handler(w, r)
	}
}

// 健康检查
func (api *APIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	api.writeJSON(w, http.StatusOK, APIResponse{
		Code:    200,
		Message: "OK",
		Data: map[string]interface{}{
			"status": "running",
		},
	})
}

// Web仪表盘页面
func (api *APIServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write(web.GetDashboardHTML())
}

// 协议层统计 - 奔溃预警数据
func (api *APIServer) handleProtocolStats(w http.ResponseWriter, r *http.Request) {
	if api.proxyServer == nil {
		api.writeJSON(w, http.StatusOK, APIResponse{Code: 200, Message: "代理服务未初始化"})
		return
	}

	var allStats []map[string]interface{}
	cfg := config.GetConfig()

	for _, rule := range cfg.ForwardRules {
		stats := api.proxyServer.GetBackendProtoStats(rule.ListenAddr)
		for i, st := range stats {
			backendAddr := ""
			if i < len(rule.BackendAddrs) {
				backendAddr = rule.BackendAddrs[i]
			}
			health := protocol.CalcCrashRisk(&st)

			allStats = append(allStats, map[string]interface{}{
				"listen_addr":       rule.ListenAddr,
				"backend_addr":      backendAddr,
				"total_logins":      atomicInt64(&st.TotalLogins),
				"total_login_acks":  atomicInt64(&st.TotalLoginAcks),
				"total_login_nacks": atomicInt64(&st.TotalLoginNacks),
				"login_fail_rate":   fmt.Sprintf("%.1f%%", st.LoginFailRate*100),
				"total_heartbeats":  atomicInt64(&st.TotalHeartbeats),
				"heartbeat_loss":    fmt.Sprintf("%.1f%%", st.HeartbeatLossRate*100),
				"backend_timeouts":  atomicInt64(&st.TotalBackendTimeouts),
				"health":            health.String(),
				"health_code":       int(health),
			})
		}
	}

	api.writeJSON(w, http.StatusOK, APIResponse{
		Code:    200,
		Message: "OK",
		Data:    allStats,
	})
}

// 辅助函数 - 读取atomic int64
func atomicInt64(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

// 获取状态
func (api *APIServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := api.monitor.GetStatus()
	api.writeJSON(w, http.StatusOK, APIResponse{
		Code:    200,
		Message: "OK",
		Data:    status,
	})
}

// 获取统计
func (api *APIServer) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := api.monitor.GetStatsSnapshot()
	api.writeJSON(w, http.StatusOK, APIResponse{
		Code:    200,
		Message: "OK",
		Data:    stats,
	})
}

// 获取统计快照
func (api *APIServer) handleStatsSnapshot(w http.ResponseWriter, r *http.Request) {
	gs := api.monitor.GetGlobalStats()
	ps := api.monitor.GetPortStats()
	bs := api.monitor.GetBackendStats()

	api.writeJSON(w, http.StatusOK, APIResponse{
		Code:    200,
		Message: "OK",
		Data: map[string]interface{}{
			"global":   gs,
			"ports":    ps,
			"backends": bs,
		},
	})
}

// 获取黑名单列表
func (api *APIServer) handleBlacklist(w http.ResponseWriter, r *http.Request) {
	ipList := api.blacklistMgr.GetIPBlacklist()
	uidList := api.blacklistMgr.GetUIDBlacklist()

	api.writeJSON(w, http.StatusOK, APIResponse{
		Code:    200,
		Message: "OK",
		Data: map[string]interface{}{
			"ip_blacklist":  ipList,
			"uid_blacklist": uidList,
		},
	})
}

// 添加黑名单
func (api *APIServer) handleBlacklistAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.writeJSON(w, http.StatusMethodNotAllowed, APIResponse{
			Code:    405,
			Message: "仅支持POST方法",
		})
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		api.writeJSON(w, http.StatusBadRequest, APIResponse{
			Code:    400,
			Message: "读取请求体失败",
		})
		return
	}

	var req struct {
		Type   string `json:"type"` // ip / uid / combined
		IP     string `json:"ip"`
		UID    int    `json:"uid"`
		Reason string `json:"reason"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		api.writeJSON(w, http.StatusBadRequest, APIResponse{
			Code:    400,
			Message: "解析请求体失败: " + err.Error(),
		})
		return
	}

	switch req.Type {
	case "ip":
		if req.IP == "" {
			api.writeJSON(w, http.StatusBadRequest, APIResponse{
				Code:    400,
				Message: "IP不能为空",
			})
			return
		}
		api.blacklistMgr.AddIPBlacklist(req.IP, req.Reason, "manual")
		logger.Info("API: 手动添加IP黑名单 %s, 原因: %s", req.IP, req.Reason)

	case "uid":
		if req.UID <= 0 {
			api.writeJSON(w, http.StatusBadRequest, APIResponse{
				Code:    400,
				Message: "UID不能为空",
			})
			return
		}
		api.blacklistMgr.AddUIDBlacklist(req.UID, req.Reason, "manual")
		logger.Info("API: 手动添加UID黑名单 %d, 原因: %s", req.UID, req.Reason)

	case "combined":
		if req.IP == "" || req.UID <= 0 {
			api.writeJSON(w, http.StatusBadRequest, APIResponse{
				Code:    400,
				Message: "IP和UID都不能为空",
			})
			return
		}
		api.blacklistMgr.AddCombinedBlacklist(req.IP, req.UID, req.Reason, "manual")
		logger.Info("API: 手动添加组合黑名单 %s:%d, 原因: %s", req.IP, req.UID, req.Reason)

	default:
		api.writeJSON(w, http.StatusBadRequest, APIResponse{
			Code:    400,
			Message: "无效的黑名单类型: " + req.Type,
		})
		return
	}

	api.writeJSON(w, http.StatusOK, APIResponse{
		Code:    200,
		Message: "添加成功",
	})
}

// 移除黑名单
func (api *APIServer) handleBlacklistRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.writeJSON(w, http.StatusMethodNotAllowed, APIResponse{
			Code:    405,
			Message: "仅支持POST方法",
		})
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		api.writeJSON(w, http.StatusBadRequest, APIResponse{Code: 400, Message: "读取请求体失败"})
		return
	}

	var req struct {
		Type string `json:"type"`
		IP   string `json:"ip"`
		UID  int    `json:"uid"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		api.writeJSON(w, http.StatusBadRequest, APIResponse{Code: 400, Message: "解析失败"})
		return
	}

	switch req.Type {
	case "ip":
		api.blacklistMgr.RemoveIPBlacklist(req.IP)
	case "uid":
		api.blacklistMgr.RemoveUIDBlacklist(req.UID)
	case "combined":
		api.blacklistMgr.RemoveCombinedBlacklist(req.IP, req.UID)
	default:
		api.writeJSON(w, http.StatusBadRequest, APIResponse{Code: 400, Message: "无效类型"})
		return
	}

	api.writeJSON(w, http.StatusOK, APIResponse{Code: 200, Message: "移除成功"})
}

// 清空黑名单
func (api *APIServer) handleBlacklistClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.writeJSON(w, http.StatusMethodNotAllowed, APIResponse{Code: 405, Message: "仅支持POST方法"})
		return
	}

	api.blacklistMgr.ClearAll()
	logger.Info("API: 清空所有黑名单")
	api.writeJSON(w, http.StatusOK, APIResponse{Code: 200, Message: "已清空所有黑名单"})
}

// 获取白名单
func (api *APIServer) handleWhitelist(w http.ResponseWriter, r *http.Request) {
	whitelist := api.blacklistMgr.GetWhitelist()
	api.writeJSON(w, http.StatusOK, APIResponse{
		Code:    200,
		Message: "OK",
		Data:    whitelist,
	})
}

// 添加白名单
func (api *APIServer) handleWhitelistAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.writeJSON(w, http.StatusMethodNotAllowed, APIResponse{Code: 405, Message: "仅支持POST方法"})
		return
	}

	body, _ := io.ReadAll(r.Body)
	var req struct {
		IP   string `json:"ip"`
		Note string `json:"note"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		api.writeJSON(w, http.StatusBadRequest, APIResponse{Code: 400, Message: "解析失败"})
		return
	}

	if req.IP == "" {
		api.writeJSON(w, http.StatusBadRequest, APIResponse{Code: 400, Message: "IP不能为空"})
		return
	}

	api.blacklistMgr.AddIPWhitelist(req.IP, req.Note)
	logger.Info("API: 添加IP白名单 %s", req.IP)
	api.writeJSON(w, http.StatusOK, APIResponse{Code: 200, Message: "白名单已添加"})
}

// 获取活跃频率限制
func (api *APIServer) handleRateLimitActive(w http.ResponseWriter, r *http.Request) {
	ips := api.rateLimiter.GetActiveIPs()
	uids := api.rateLimiter.GetActiveUIDs()

	api.writeJSON(w, http.StatusOK, APIResponse{
		Code:    200,
		Message: "OK",
		Data: map[string]interface{}{
			"active_ips":  ips,
			"active_uids": uids,
		},
	})
}

// 重置频率限制
func (api *APIServer) handleRateLimitReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.writeJSON(w, http.StatusMethodNotAllowed, APIResponse{Code: 405, Message: "仅支持POST方法"})
		return
	}

	body, _ := io.ReadAll(r.Body)
	var req struct {
		Type string `json:"type"`
		IP   string `json:"ip"`
		UID  int    `json:"uid"`
	}

	json.Unmarshal(body, &req)

	switch req.Type {
	case "ip":
		api.rateLimiter.ResetIP(req.IP)
	case "uid":
		api.rateLimiter.ResetUID(req.UID)
	default:
		api.writeJSON(w, http.StatusBadRequest, APIResponse{Code: 400, Message: "无效类型"})
		return
	}

	api.writeJSON(w, http.StatusOK, APIResponse{Code: 200, Message: "重置成功"})
}

// 获取配置
func (api *APIServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	cfg := config.GetConfig()
	api.writeJSON(w, http.StatusOK, APIResponse{
		Code:    200,
		Message: "OK",
		Data:    cfg,
	})
}

// 重新加载配置
func (api *APIServer) handleConfigReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.writeJSON(w, http.StatusMethodNotAllowed, APIResponse{Code: 405, Message: "仅支持POST方法"})
		return
	}

	api.writeJSON(w, http.StatusOK, APIResponse{
		Code:    200,
		Message: "配置已重新加载(需要重启服务生效部分配置)",
	})
}

// IP分析
func (api *APIServer) handleIPAnalysis(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		api.writeJSON(w, http.StatusBadRequest, APIResponse{Code: 400, Message: "请提供IP参数"})
		return
	}

	result := logger.GetIPFreqAnalysis(ip, 3600*time.Second) // 最近1小时
	if result == nil {
		api.writeJSON(w, http.StatusOK, APIResponse{Code: 200, Message: "无数据"})
		return
	}

	api.writeJSON(w, http.StatusOK, APIResponse{
		Code:    200,
		Message: "OK",
		Data:    result,
	})
}

// UID分析
func (api *APIServer) handleUIDAnalysis(w http.ResponseWriter, r *http.Request) {
	uidStr := r.URL.Query().Get("uid")
	if uidStr == "" {
		api.writeJSON(w, http.StatusBadRequest, APIResponse{Code: 400, Message: "请提供uid参数"})
		return
	}

	var uid int
	fmt.Sscanf(uidStr, "%d", &uid)

	result := logger.GetUIDFreqAnalysis(uid, 3600*time.Second)
	if result == nil {
		api.writeJSON(w, http.StatusOK, APIResponse{Code: 200, Message: "无数据"})
		return
	}

	api.writeJSON(w, http.StatusOK, APIResponse{
		Code:    200,
		Message: "OK",
		Data:    result,
	})
}

// Top攻击者
func (api *APIServer) handleTopAttackers(w http.ResponseWriter, r *http.Request) {
	attackers := logger.GetTopAttackers(20)
	api.writeJSON(w, http.StatusOK, APIResponse{
		Code:    200,
		Message: "OK",
		Data:    attackers,
	})
}

// 日志分析 - 支持上传LoginError.txt进行分析
func (api *APIServer) handleLogAnalysis(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.writeJSON(w, http.StatusMethodNotAllowed, APIResponse{Code: 405, Message: "仅支持POST方法"})
		return
	}

	var logContent string

	// 尝试按multipart表单解析（文件上传）
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "multipart/form-data") {
		if err := r.ParseMultipartForm(10 << 20); err == nil {
			file, _, err := r.FormFile("logfile")
			if err == nil {
				content, _ := io.ReadAll(file)
				file.Close()
				logContent = string(content)
			}
		}
	}

	// 如果不是multipart，尝试直接读取请求体
	if logContent == "" {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			api.writeJSON(w, http.StatusBadRequest, APIResponse{Code: 400, Message: "请提供日志文件或内容"})
			return
		}

		rawStr := string(body)

		// 尝试按JSON解析 {"content": "..."}
		var jsonReq struct {
			Content string `json:"content"`
		}
		if err := json.Unmarshal(body, &jsonReq); err == nil && jsonReq.Content != "" {
			logContent = jsonReq.Content
		} else {
			logContent = rawStr
		}
	}

	if logContent == "" {
		api.writeJSON(w, http.StatusBadRequest, APIResponse{Code: 400, Message: "日志内容为空"})
		return
	}

	blocked := api.blacklistMgr.AnalyzeLogAndBlock(logContent)
	logger.Info("API: 日志分析完成, 自动封禁 %d 个条目", len(blocked))

	api.writeJSON(w, http.StatusOK, APIResponse{
		Code:    200,
		Message: "分析完成",
		Data: map[string]interface{}{
			"blocked_entries": blocked,
		},
	})
}

// 启动API服务器
func (api *APIServer) Start() error {
	if !api.config.API.Enable {
		logger.Info("API管理接口未启用")
		return nil
	}

	api.server = &http.Server{
		Addr:    api.config.API.ListenAddr,
		Handler: api.mux,
	}

	logger.Info("API管理接口启动: http://%s", api.config.API.ListenAddr)
	logger.Info("API健康检查: http://%s/api/health", api.config.API.ListenAddr)

	go func() {
		if err := api.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("API服务器错误: %v", err)
		}
	}()

	return nil
}

// 停止API服务器
func (api *APIServer) Stop() {
	if api.server != nil {
		api.server.Close()
		logger.Info("API服务器已停止")
	}
}

// 写JSON响应
func (api *APIServer) writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}
