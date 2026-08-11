package proxy

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"gateway/blacklist"
	"gateway/config"
	"gateway/limiter"
	"gateway/logger"
	"gateway/monitor"
	"gateway/protocol"
)

// 代理服务器
type ProxyServer struct {
	config        *config.Config
	rateLimiter   *limiter.RateLimiter
	blacklistMgr  *blacklist.BlacklistManager
	monitor       *monitor.Monitor
	listeners     []net.Listener
	stopChan      chan struct{}
	running       atomic.Bool
	backendRouter *BackendRouter
}

// 后端路由器
type BackendRouter struct {
	rules map[string]*RouteEntry
	mu    sync.RWMutex
}

// 路由条目
type RouteEntry struct {
	Rule         config.ForwardRule
	BackendConns []int64
	BackendAlive []bool
	// 新增: 协议层统计(奔溃预警用)
	ProtoStats []protocol.ProtocolStats
	mu         sync.RWMutex
}

// 创建代理服务器
func NewProxyServer(cfg *config.Config, rl *limiter.RateLimiter, bl *blacklist.BlacklistManager, mon *monitor.Monitor) *ProxyServer {
	ps := &ProxyServer{
		config:       cfg,
		rateLimiter:  rl,
		blacklistMgr: bl,
		monitor:      mon,
		stopChan:     make(chan struct{}),
		backendRouter: &BackendRouter{
			rules: make(map[string]*RouteEntry),
		},
	}
	return ps
}

// 初始化后端路由
func (ps *ProxyServer) initBackendRouter() {
	for _, rule := range ps.config.ForwardRules {
		entry := &RouteEntry{
			Rule:         rule,
			BackendConns: make([]int64, len(rule.BackendAddrs)),
			BackendAlive: make([]bool, len(rule.BackendAddrs)),
			ProtoStats:   make([]protocol.ProtocolStats, len(rule.BackendAddrs)),
		}
		for i := range rule.BackendAddrs {
			entry.BackendAlive[i] = true
		}
		ps.backendRouter.rules[rule.ListenAddr] = entry
	}
}

// 启动代理服务器
func (ps *ProxyServer) Start() error {
	ps.initBackendRouter()

	for _, rule := range ps.config.ForwardRules {
		listener, err := net.Listen("tcp", rule.ListenAddr)
		if err != nil {
			return fmt.Errorf("监听 %s 失败: %v", rule.ListenAddr, err)
		}
		ps.listeners = append(ps.listeners, listener)
		logger.Info("代理监听启动: %s -> 后端 %v", rule.ListenAddr, rule.BackendAddrs)

		go ps.acceptLoop(listener, rule)
	}

	go ps.healthCheckRoutine()
	ps.running.Store(true)
	return nil
}

// 接受连接循环
func (ps *ProxyServer) acceptLoop(listener net.Listener, rule config.ForwardRule) {
	for {
		select {
		case <-ps.stopChan:
			return
		default:
			if tcpListener, ok := listener.(*net.TCPListener); ok {
				tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
			}

			conn, err := listener.Accept()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				select {
				case <-ps.stopChan:
					return
				default:
					logger.Error("接受连接失败 %s: %v", rule.ListenAddr, err)
					continue
				}
			}

			// 在建立连接前检查后端健康状态
			if ps.isBackendCritical(rule) {
				logger.Warn("后端危险状态, 拒绝新连接: %s", rule.ListenAddr)
				conn.Close()
				ps.monitor.RecordReject(rule.ListenAddr, "backend_critical")
				continue
			}

			go ps.handleConnection(conn, rule)
		}
	}
}

// 检查后端是否处于危险状态
func (ps *ProxyServer) isBackendCritical(rule config.ForwardRule) bool {
	entry, ok := ps.backendRouter.rules[rule.ListenAddr]
	if !ok {
		return false
	}
	entry.mu.RLock()
	defer entry.mu.RUnlock()

	criticalCount := 0
	for i := range rule.BackendAddrs {
		if entry.BackendAlive[i] {
			health := protocol.CalcCrashRisk(&entry.ProtoStats[i])
			if health == protocol.HealthCritical || health == protocol.HealthDown {
				criticalCount++
			}
		}
	}
	// 所有存活后端都危险时才拒绝
	aliveCount := 0
	for _, a := range entry.BackendAlive {
		if a {
			aliveCount++
		}
	}
	return aliveCount > 0 && criticalCount >= aliveCount
}

// 处理单个连接 - 核心转发逻辑(带协议嗅探)
func (ps *ProxyServer) handleConnection(clientConn net.Conn, rule config.ForwardRule) {
	defer clientConn.Close()

	// 清理IP地址(去掉端口)
	clientIP := limiter.ExtractIP(clientConn.RemoteAddr().String())
	clientIP = limiter.CleanIP(clientIP)

	startTime := time.Now()
	var bytesRead, bytesWritten int64

	ps.monitor.RecordConn(rule.ListenAddr)

	defer func() {
		duration := time.Since(startTime).Seconds()
		ps.monitor.RecordConnClose(rule.ListenAddr, bytesRead, bytesWritten, duration)
	}()

	// ===== 步骤1: 读取首批数据做协议嗅探(200ms超时) =====
	// 注意: 这里读到的数据会在步骤4中转发给后端，不会丢失
	var uid int
	var firstBuf []byte
	clientConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	sniffBuf := make([]byte, 4096)
	n, sniffErr := clientConn.Read(sniffBuf)
	clientConn.SetReadDeadline(time.Time{}) // 清除超时,后续由copy函数管理

	if n > 0 {
		firstBuf = sniffBuf[:n]

		// 尝试解析AG登录包提取UserIdx
		if n >= protocol.MsgLoginSize {
			if login, ok := protocol.ParseLogin(firstBuf); ok {
				uid = int(login.DistConnectionIndex)
				logger.Debug("协议嗅探: 检出登录包 UserID=%d, UserIdx=%d",
					login.Root.DwObjectID, login.DistConnectionIndex)
			}
		} else if n >= 4 {
			cat := uint16(firstBuf[0]) | uint16(firstBuf[1])<<8
			proto := uint16(firstBuf[2]) | uint16(firstBuf[3])<<8
			logger.Debug("协议嗅探: 首包类型=%s/%s", protocol.CategoryName(cat), protocol.ProtocolName(proto))
		}
	}
	// 忽略嗅探读取超时错误(正常情况,客户端可能慢发)
	_ = sniffErr

	// ===== 步骤2: 安全过滤(黑名单/频率限制) =====
	isWhitelisted := ps.blacklistMgr.IsIPWhitelisted(clientIP)
	if isWhitelisted {
		logger.Debug("白名单IP通过: %s", clientIP)
	}

	if !isWhitelisted {
		if blocked, reason := ps.blacklistMgr.IsBlacklisted(clientIP, uid); blocked {
			logger.Warn("黑名单拒绝: %s, UserIdx=%d, 原因: %s", clientIP, uid, reason)
			ps.monitor.RecordReject(rule.ListenAddr, "blacklist")
			logger.LogConnEntry(logger.ConnLogEntry{
				Timestamp: startTime, ClientIP: clientIP, UserIdx: uid,
				State: 4, Action: "rejected", RejectReason: "blacklist",
			})
			return
		}

		result := ps.rateLimiter.CheckAll(clientIP, uid, false)
		if !result.Allowed {
			logger.Warn("频率限制拒绝: %s, UserIdx=%d, 原因: %s", clientIP, uid, result.Reason)
			ps.monitor.RecordReject(rule.ListenAddr, result.Reason)
			logger.LogConnEntry(logger.ConnLogEntry{
				Timestamp: startTime, ClientIP: clientIP, UserIdx: uid,
				State: 4, Action: "rejected", RejectReason: result.Reason,
			})
			ps.blacklistMgr.RecordReject(clientIP, uid)
			return
		}
	}

	// ===== 步骤3: 选择后端并连接 =====
	backendAddr := ps.selectBackend(rule)
	if backendAddr == "" {
		logger.Error("无可用后端服务器: %s", rule.ListenAddr)
		ps.monitor.RecordReject(rule.ListenAddr, "no_backend")
		return
	}

	backendConn, err := net.DialTimeout("tcp", backendAddr, time.Duration(rule.Timeout)*time.Second)
	if err != nil {
		logger.Error("连接后端 %s 失败: %v", backendAddr, err)
		ps.monitor.RecordReject(rule.ListenAddr, "backend_fail")
		ps.markBackendDown(rule.ListenAddr, backendAddr)
		return
	}
	defer backendConn.Close()

	ps.recordBackendConn(rule.ListenAddr, backendAddr)
	backendIdx := ps.findBackendIndex(rule, backendAddr)

	logger.Info("连接建立: %s -> %s -> %s (UserIdx=%d)", clientIP, rule.ListenAddr, backendAddr, uid)
	logger.LogConnEntry(logger.ConnLogEntry{
		Timestamp: startTime, ClientIP: clientIP, UserIdx: uid,
		State: 4, Action: "connect",
	})

	// ===== 步骤4: 先转发嗅探时读到的首批数据给后端(无损!) =====
	if len(firstBuf) > 0 {
		// 协议统计: 登录请求从首包解析
		if n >= protocol.MsgLoginSize {
			if _, ok := protocol.ParseLogin(firstBuf); ok {
				ps.recordProtoLogin(rule, backendIdx)
			}
		}
		if _, werr := backendConn.Write(firstBuf); werr != nil {
			logger.Error("转发首包到后端失败: %v", werr)
			return
		}
		bytesRead += int64(len(firstBuf))
	}

	// ===== 步骤5: 双工转发后续数据(带协议嗅探) =====
	var wg sync.WaitGroup
	wg.Add(2)

	// 客户端 -> 后端
	go func() {
		defer wg.Done()
		defer backendConn.Close()
		ps.copyAndSniffClient(backendConn, clientConn, rule, backendIdx, &bytesRead, uid, clientIP, startTime)
	}()

	// 后端 -> 客户端
	go func() {
		defer wg.Done()
		defer clientConn.Close()
		ps.copyAndSniffBackend(clientConn, backendConn, rule, backendIdx, &bytesWritten)
	}()

	wg.Wait()
}

// 客户端->后端 数据拷贝(后续数据嗅探)
func (ps *ProxyServer) copyAndSniffClient(dst net.Conn, src net.Conn, rule config.ForwardRule, backendIdx int, bytesCount *int64, uid int, clientIP string, startTime time.Time) {
	buf := make([]byte, 32768)
	for {
		src.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, err := src.Read(buf)
		if n > 0 {
			// 协议嗅探: 检测后续登录请求(客户端可能发多个登录包)
			if n >= protocol.MsgLoginSize {
				if login, ok := protocol.ParseLogin(buf[:n]); ok {
					realUID := int(login.DistConnectionIndex)
					logger.Debug("协议嗅探: 后续登录包 UserIdx=%d", realUID)
					// 记录登录请求
					ps.recordProtoLogin(rule, backendIdx)
				}
			}

			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
			*bytesCount += int64(n)
		}
		if err != nil {
			// 100ms读超时是正常的(客户端可能在等后端响应), 继续循环
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			// EOF或其他错误才退出
			break
		}
	}
}

// 后端->客户端 数据拷贝(带协议嗅探NACK)
func (ps *ProxyServer) copyAndSniffBackend(dst net.Conn, src net.Conn, rule config.ForwardRule, backendIdx int, bytesCount *int64) {
	buf := make([]byte, 32768)
	for {
		src.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, err := src.Read(buf)
		if n > 0 {
			// 协议嗅探: 检测后端响应
			ps.sniffBackendResponse(buf[:n], rule, backendIdx)

			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
			*bytesCount += int64(n)
		}
		if err != nil {
			// 区分正常断连和异常超时
			// io.EOF = 对方正常关闭连接, 不是崩溃, 不记录为超时
			// 只有真正的超时错误(net.Error.Timeout()==true)才记录
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// 读写超时是正常的(我们设置了100ms ReadDeadline), 忽略
				continue
			}
			// 其他错误(非EOF, 非Timeout)才可能指示问题
			if err.Error() != "EOF" && backendIdx >= 0 {
				ps.recordProtoTimeout(rule, backendIdx)
			}
			break
		}
	}
}

// 嗅探后端响应
func (ps *ProxyServer) sniffBackendResponse(data []byte, rule config.ForwardRule, backendIdx int) {
	// 调试日志: 先打印所有后端回包信息(Info级别确保一定能看到)
	if len(data) >= 4 {
		cat := uint16(data[0]) | uint16(data[1])<<8
		proto := uint16(data[2]) | uint16(data[3])<<8
		logger.Info("后端响应: Cat=%d Proto=%d len=%d 规则=%s 后端索引=%d", cat, proto, len(data), rule.ListenAddr, backendIdx)
	} else {
		logger.Info("后端响应: 数据不足4字节 len=%d 规则=%s 后端索引=%d", len(data), rule.ListenAddr, backendIdx)
	}

	if len(data) < 4 || backendIdx < 0 {
		return
	}

	cat := uint16(data[0]) | uint16(data[1])<<8
	proto := uint16(data[2]) | uint16(data[3])<<8

	if cat == protocol.CategoryUserConn {
		switch proto {
		case protocol.ProtoUserLoginNack:
			// 后端返回登录失败 ← 奔溃前兆
			ps.recordProtoNack(rule, backendIdx)
			logger.Warn("协议告警: 后端返回LOGIN_NACK (规则=%s, 后端=%d)", rule.ListenAddr, backendIdx)

		case protocol.ProtoUserLoginAck:
			ps.recordProtoAck(rule, backendIdx)

		case protocol.ProtoConnectionCheck:
			// 后端发送心跳 - 记录
			ps.recordProtoHeartbeat(rule, backendIdx)
		}
	}
}

// 记录协议统计
func (ps *ProxyServer) recordProtoLogin(rule config.ForwardRule, backendIdx int) {
	if backendIdx < 0 {
		return
	}
	entry, ok := ps.backendRouter.rules[rule.ListenAddr]
	if !ok {
		return
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if backendIdx < len(entry.ProtoStats) {
		entry.ProtoStats[backendIdx].TotalLogins++
		entry.ProtoStats[backendIdx].Touch()
	}
}

func (ps *ProxyServer) recordProtoNack(rule config.ForwardRule, backendIdx int) {
	if backendIdx < 0 {
		return
	}
	entry, ok := ps.backendRouter.rules[rule.ListenAddr]
	if !ok {
		return
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if backendIdx < len(entry.ProtoStats) {
		entry.ProtoStats[backendIdx].TotalLoginNacks++
		entry.ProtoStats[backendIdx].Touch()
		entry.ProtoStats[backendIdx].BackendHealth = protocol.CalcCrashRisk(&entry.ProtoStats[backendIdx])
	}
}

func (ps *ProxyServer) recordProtoAck(rule config.ForwardRule, backendIdx int) {
	if backendIdx < 0 {
		return
	}
	entry, ok := ps.backendRouter.rules[rule.ListenAddr]
	if !ok {
		return
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if backendIdx < len(entry.ProtoStats) {
		entry.ProtoStats[backendIdx].TotalLoginAcks++
		entry.ProtoStats[backendIdx].Touch()
		entry.ProtoStats[backendIdx].BackendHealth = protocol.CalcCrashRisk(&entry.ProtoStats[backendIdx])
	}
}

func (ps *ProxyServer) recordProtoHeartbeat(rule config.ForwardRule, backendIdx int) {
	if backendIdx < 0 {
		return
	}
	entry, ok := ps.backendRouter.rules[rule.ListenAddr]
	if !ok {
		return
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if backendIdx < len(entry.ProtoStats) {
		entry.ProtoStats[backendIdx].TotalHeartbeats++
		entry.ProtoStats[backendIdx].Touch()
	}
}

func (ps *ProxyServer) recordProtoTimeout(rule config.ForwardRule, backendIdx int) {
	if backendIdx < 0 {
		return
	}
	entry, ok := ps.backendRouter.rules[rule.ListenAddr]
	if !ok {
		return
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if backendIdx < len(entry.ProtoStats) {
		entry.ProtoStats[backendIdx].TotalBackendTimeouts++
		entry.ProtoStats[backendIdx].Touch()
		entry.ProtoStats[backendIdx].BackendHealth = protocol.CalcCrashRisk(&entry.ProtoStats[backendIdx])
	}
}

// 查找后端索引
func (ps *ProxyServer) findBackendIndex(rule config.ForwardRule, addr string) int {
	entry, ok := ps.backendRouter.rules[rule.ListenAddr]
	if !ok {
		return -1
	}
	entry.mu.RLock()
	defer entry.mu.RUnlock()
	for i, a := range entry.Rule.BackendAddrs {
		if a == addr {
			return i
		}
	}
	return -1
}

// 获取后端协议统计
func (ps *ProxyServer) GetBackendProtoStats(listenAddr string) []protocol.ProtocolStats {
	entry, ok := ps.backendRouter.rules[listenAddr]
	if !ok {
		return nil
	}
	entry.mu.RLock()
	defer entry.mu.RUnlock()

	result := make([]protocol.ProtocolStats, len(entry.ProtoStats))
	copy(result, entry.ProtoStats)
	return result
}

// 选择后端
func (ps *ProxyServer) selectBackend(rule config.ForwardRule) string {
	entry, ok := ps.backendRouter.rules[rule.ListenAddr]
	if !ok {
		return ""
	}
	entry.mu.RLock()
	defer entry.mu.RUnlock()

	var available []int
	for i, alive := range entry.BackendAlive {
		if alive {
			health := protocol.CalcCrashRisk(&entry.ProtoStats[i])
			// 排除宕机和危险状态的后端
			if health != protocol.HealthDown {
				available = append(available, i)
			}
		}
	}

	if len(available) == 0 {
		return ""
	}

	switch rule.LBStrategy {
	case "least_conn":
		return ps.leastConnSelect(entry, available)
	case "random":
		return ps.randomSelect(available, rule)
	default:
		return ps.roundRobinSelect(entry)
	}
}

func (ps *ProxyServer) roundRobinSelect(entry *RouteEntry) string {
	for i := 0; i < len(entry.Rule.BackendAddrs); i++ {
		if entry.BackendAlive[i] {
			health := protocol.CalcCrashRisk(&entry.ProtoStats[i])
			if health != protocol.HealthDown {
				return entry.Rule.BackendAddrs[i]
			}
		}
	}
	return ""
}

func (ps *ProxyServer) leastConnSelect(entry *RouteEntry, available []int) string {
	if len(available) == 0 {
		return ""
	}
	minIdx := available[0]
	minConns := atomic.LoadInt64(&entry.BackendConns[minIdx])
	for _, idx := range available[1:] {
		conns := atomic.LoadInt64(&entry.BackendConns[idx])
		if conns < minConns {
			minConns = conns
			minIdx = idx
		}
	}
	return entry.Rule.BackendAddrs[minIdx]
}

func (ps *ProxyServer) randomSelect(available []int, rule config.ForwardRule) string {
	if len(available) == 0 {
		return ""
	}
	idx := available[0]
	if len(available) > 1 {
		idx = available[int(time.Now().UnixNano())%len(available)]
	}
	return rule.BackendAddrs[idx]
}

func (ps *ProxyServer) markBackendDown(listenAddr, backendAddr string) {
	entry, ok := ps.backendRouter.rules[listenAddr]
	if !ok {
		return
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	for i, addr := range entry.Rule.BackendAddrs {
		if addr == backendAddr {
			entry.BackendAlive[i] = false
			ps.monitor.UpdateBackend(backendAddr, false, 1)
			logger.Warn("后端标记为不可用: %s", backendAddr)
			break
		}
	}
}

func (ps *ProxyServer) recordBackendConn(listenAddr, backendAddr string) {
	entry, ok := ps.backendRouter.rules[listenAddr]
	if !ok {
		return
	}
	for i, addr := range entry.Rule.BackendAddrs {
		if addr == backendAddr {
			atomic.AddInt64(&entry.BackendConns[i], 1)
			ps.monitor.RecordBackendConn(backendAddr, 1)
			break
		}
	}
}

// 健康检查(含ProtoStats衰减恢复)
func (ps *ProxyServer) healthCheckRoutine() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			ps.checkBackends()
		case <-ps.stopChan:
			return
		}
	}
}

func (ps *ProxyServer) checkBackends() {
	ps.backendRouter.mu.RLock()
	defer ps.backendRouter.mu.RUnlock()

	for _, entry := range ps.backendRouter.rules {
		for i, addr := range entry.Rule.BackendAddrs {
			// 情况1: BackendAlive=false(TCP不通) → TCP探测恢复
			if !entry.BackendAlive[i] {
				conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
				if err == nil {
					conn.Close()
					entry.BackendAlive[i] = true
					entry.ProtoStats[i].Reset()
					ps.monitor.UpdateBackend(addr, true, 0)
					logger.Info("后端TCP恢复可用: %s (已重置ProtoStats)", addr)
				}
				continue
			}

			// 情况2: BackendAlive=true 但 ProtoStats判为宕机/危险 → 衰减 + TCP探测
			health := protocol.CalcCrashRisk(&entry.ProtoStats[i])
			if health == protocol.HealthDown || health == protocol.HealthCritical {
				// 先尝试ProtoStats衰减(闲置超30秒自动减小计数)
				if entry.ProtoStats[i].DecayIfIdle(30 * time.Second) {
					logger.Info("后端ProtoStats衰减恢复: %s -> 正常", addr)
					continue
				}

				// 衰减还不够, TCP主动探测
				conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
				if err == nil {
					conn.Close()
					// TCP通了, 强制重置ProtoStats
					entry.ProtoStats[i].Reset()
					ps.monitor.UpdateBackend(addr, true, 0)
					logger.Info("后端TCP探测通过, 重置ProtoStats: %s", addr)
				}
			}
		}
	}
}

func (ps *ProxyServer) Stop() {
	ps.running.Store(false)
	close(ps.stopChan)
	for _, listener := range ps.listeners {
		listener.Close()
	}
	logger.Info("代理服务器已停止")
}

func (ps *ProxyServer) IsRunning() bool {
	return ps.running.Load()
}
