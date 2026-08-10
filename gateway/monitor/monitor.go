package monitor

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// 全局统计信息
type GlobalStats struct {
	// 连接统计
	TotalConns      int64 // 总连接数
	ActiveConns     int64 // 活跃连接数
	TotalRejects    int64 // 总拒绝数
	TotalBytesRead  int64 // 总读取字节
	TotalBytesWrite int64 // 总写入字节

	// 实时统计
	ConnPerSec       float64 // 每秒连接数
	RejectPerSec     float64 // 每秒拒绝数
	BytesReadPerSec  float64 // 每秒读取字节
	BytesWritePerSec float64 // 每秒写入字节
	AvgConnTime      float64 // 平均连接时长

	// 开始时间
	StartTime time.Time
	// 运行时长
	Uptime time.Duration
}

// 单端口统计信息
type PortStats struct {
	ListenAddr      string
	TotalConns      int64
	ActiveConns     int64
	TotalRejects    int64
	TotalBytesRead  int64
	TotalBytesWrite int64
}

// 后端服务器统计
type BackendStats struct {
	Addr          string
	TotalConns    int64
	ActiveConns   int64
	FailCount     int64
	IsAlive       bool
	LastCheckTime time.Time
}

// 连接统计快照
type ConnSnapshot struct {
	Count int64
	Time  time.Time
}

// 监控器
type Monitor struct {
	stats        GlobalStats
	portStats    map[string]*PortStats    // 按监听地址统计
	backendStats map[string]*BackendStats // 按后端地址统计
	connHistory  []ConnSnapshot           // 连接历史快照
	mu           sync.RWMutex

	config   *MonitorConfig
	stopChan chan struct{}
	ticker   *time.Ticker
}

// 监控配置
type MonitorConfig struct {
	Enabled         bool
	RefreshInterval int // 秒
	LogOutput       bool
}

// 创建监控器
func NewMonitor(cfg *MonitorConfig) *Monitor {
	m := &Monitor{
		portStats:    make(map[string]*PortStats),
		backendStats: make(map[string]*BackendStats),
		connHistory:  make([]ConnSnapshot, 0, 3600), // 保留1小时数据
		config:       cfg,
		stopChan:     make(chan struct{}),
		ticker:       time.NewTicker(time.Duration(cfg.RefreshInterval) * time.Second),
	}
	m.stats.StartTime = time.Now()

	// 启动定期刷新
	go m.refreshRoutine()

	return m
}

// 记录新连接
func (m *Monitor) RecordConn(listenAddr string) {
	atomic.AddInt64(&m.stats.TotalConns, 1)
	atomic.AddInt64(&m.stats.ActiveConns, 1)

	m.mu.Lock()
	defer m.mu.Unlock()

	ps, ok := m.portStats[listenAddr]
	if !ok {
		ps = &PortStats{ListenAddr: listenAddr}
		m.portStats[listenAddr] = ps
	}
	ps.TotalConns++
	ps.ActiveConns++
}

// 记录连接关闭
func (m *Monitor) RecordConnClose(listenAddr string, bytesRead, bytesWrite int64, duration float64) {
	atomic.AddInt64(&m.stats.ActiveConns, -1)
	atomic.AddInt64(&m.stats.TotalBytesRead, bytesRead)
	atomic.AddInt64(&m.stats.TotalBytesWrite, bytesWrite)

	m.mu.Lock()
	defer m.mu.Unlock()

	ps, ok := m.portStats[listenAddr]
	if ok {
		ps.ActiveConns--
		ps.TotalBytesRead += bytesRead
		ps.TotalBytesWrite += bytesWrite
	}

	// 累计平均连接时长
	total := atomic.LoadInt64(&m.stats.TotalConns)
	if total > 0 {
		m.stats.AvgConnTime = (m.stats.AvgConnTime*float64(total-1) + duration) / float64(total)
	}
}

// 记录被拒绝连接
func (m *Monitor) RecordReject(listenAddr, reason string) {
	atomic.AddInt64(&m.stats.TotalRejects, 1)

	m.mu.Lock()
	defer m.mu.Unlock()

	ps, ok := m.portStats[listenAddr]
	if !ok {
		ps = &PortStats{ListenAddr: listenAddr}
		m.portStats[listenAddr] = ps
	}
	ps.TotalRejects++
}

// 更新后端服务器统计
func (m *Monitor) UpdateBackend(addr string, isAlive bool, failCount int64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	bs, ok := m.backendStats[addr]
	if !ok {
		bs = &BackendStats{Addr: addr}
		m.backendStats[addr] = bs
	}
	bs.IsAlive = isAlive
	bs.FailCount = failCount
	bs.LastCheckTime = time.Now()
}

// 记录后端连接数
func (m *Monitor) RecordBackendConn(addr string, delta int64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	bs, ok := m.backendStats[addr]
	if !ok {
		bs = &BackendStats{Addr: addr}
		m.backendStats[addr] = bs
	}
	bs.TotalConns++
	bs.ActiveConns += delta
}

// 获取全局统计
func (m *Monitor) GetGlobalStats() GlobalStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	s := m.stats
	s.Uptime = time.Since(s.StartTime)
	return s
}

// 获取端口统计
func (m *Monitor) GetPortStats() []PortStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]PortStats, 0, len(m.portStats))
	for _, ps := range m.portStats {
		result = append(result, *ps)
	}
	return result
}

// 获取后端统计
func (m *Monitor) GetBackendStats() []BackendStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]BackendStats, 0, len(m.backendStats))
	for _, bs := range m.backendStats {
		result = append(result, *bs)
	}
	return result
}

// 获取详细状态信息
func (m *Monitor) GetStatus() map[string]interface{} {
	gs := m.GetGlobalStats()
	ps := m.GetPortStats()
	bs := m.GetBackendStats()

	return map[string]interface{}{
		"global":         gs,
		"ports":          ps,
		"backends":       bs,
		"uptime_seconds": int64(gs.Uptime.Seconds()), // 前端用的秒数
	}
}

// 获取统计数据快照
func (m *Monitor) GetStatsSnapshot() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	snapshot := map[string]interface{}{
		"total_conns":       atomic.LoadInt64(&m.stats.TotalConns),
		"active_conns":      atomic.LoadInt64(&m.stats.ActiveConns),
		"total_rejects":     atomic.LoadInt64(&m.stats.TotalRejects),
		"total_bytes_read":  atomic.LoadInt64(&m.stats.TotalBytesRead),
		"total_bytes_write": atomic.LoadInt64(&m.stats.TotalBytesWrite),
		"conn_per_sec":      m.stats.ConnPerSec,
		"reject_per_sec":    m.stats.RejectPerSec,
		"uptime_seconds":    int64(m.stats.Uptime.Seconds()),
	}
	return snapshot
}

// 刷新统计信息
func (m *Monitor) refreshRoutine() {
	prevConns := int64(0)
	prevRejects := int64(0)
	prevBytesRead := int64(0)
	prevBytesWrite := int64(0)

	for {
		select {
		case <-m.ticker.C:
			m.mu.Lock()

			// 计算实时速率
			curConns := atomic.LoadInt64(&m.stats.TotalConns)
			curRejects := atomic.LoadInt64(&m.stats.TotalRejects)
			curBytesRead := atomic.LoadInt64(&m.stats.TotalBytesRead)
			curBytesWrite := atomic.LoadInt64(&m.stats.TotalBytesWrite)
			interval := float64(m.config.RefreshInterval)

			m.stats.ConnPerSec = float64(curConns-prevConns) / interval
			m.stats.RejectPerSec = float64(curRejects-prevRejects) / interval
			m.stats.BytesReadPerSec = float64(curBytesRead-prevBytesRead) / interval
			m.stats.BytesWritePerSec = float64(curBytesWrite-prevBytesWrite) / interval

			// 保存连接历史快照
			m.connHistory = append(m.connHistory, ConnSnapshot{
				Count: curConns,
				Time:  time.Now(),
			})

			// 限制历史数据大小
			if len(m.connHistory) > 86400 {
				m.connHistory = m.connHistory[1:]
			}

			prevConns = curConns
			prevRejects = curRejects
			prevBytesRead = curBytesRead
			prevBytesWrite = curBytesWrite

			m.mu.Unlock()

		case <-m.stopChan:
			return
		}
	}
}

// 获取连接历史
func (m *Monitor) GetConnHistory(limit int) []ConnSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if limit <= 0 || limit > len(m.connHistory) {
		limit = len(m.connHistory)
	}

	start := len(m.connHistory) - limit
	return m.connHistory[start:]
}

// 打印统计信息
func (m *Monitor) PrintStats() string {
	gs := m.GetGlobalStats()
	ps := m.GetPortStats()

	output := fmt.Sprintf("========== 网关统计 ==========\n")
	output += fmt.Sprintf("运行时间: %v\n", gs.Uptime.Round(time.Second))
	output += fmt.Sprintf("总连接数: %d | 活跃连接: %d\n", gs.TotalConns, gs.ActiveConns)
	output += fmt.Sprintf("总拒绝数: %d\n", gs.TotalRejects)
	output += fmt.Sprintf("总流量: 接收 %.2f MB | 发送 %.2f MB\n",
		float64(gs.TotalBytesRead)/1024/1024, float64(gs.TotalBytesWrite)/1024/1024)
	output += fmt.Sprintf("实时速率: %.1f conn/s | %.1f reject/s\n", gs.ConnPerSec, gs.RejectPerSec)
	output += fmt.Sprintf("流量速率: 接收 %.2f KB/s | 发送 %.2f KB/s\n",
		gs.BytesReadPerSec/1024, gs.BytesWritePerSec/1024)
	output += fmt.Sprintf("平均连接时长: %.2f 秒\n", gs.AvgConnTime)

	if len(ps) > 0 {
		output += fmt.Sprintf("\n--- 端口统计 ---\n")
		for _, p := range ps {
			output += fmt.Sprintf("  %s: 连接=%d 活跃=%d 拒绝=%d\n",
				p.ListenAddr, p.TotalConns, p.ActiveConns, p.TotalRejects)
		}
	}

	output += fmt.Sprintf("==============================\n")
	return output
}

// 停止监控器
func (m *Monitor) Stop() {
	m.ticker.Stop()
	close(m.stopChan)
}
