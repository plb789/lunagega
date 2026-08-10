package limiter

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// 频率限制器类型
type LimitType int

const (
	LimitTypeIP       LimitType = 0
	LimitTypeUID      LimitType = 1
	LimitTypeCombined LimitType = 2
	LimitTypeLogin    LimitType = 3 // 登录尝试
)

// 频率限制记录
type limitRecord struct {
	Count      int
	StartTime  time.Time
	LastAccess time.Time
}

// 频率限制器
type RateLimiter struct {
	// IP频率记录
	ipRecords map[string]*limitRecord
	// 用户ID频率记录
	uidRecords map[int]*limitRecord
	// IP+UID组合频率记录
	combinedRecords map[string]*limitRecord
	// 互斥锁
	mu sync.RWMutex
	// 配置
	config *RateLimiterConfig
	// 清理定时器
	stopCleanup chan struct{}
}

// 频率限制配置
type RateLimiterConfig struct {
	// 窗口大小(秒)
	WindowSize int
	// IP限制
	EnableIPLimit    bool
	IPMaxConnPerSec  int
	IPMaxLoginPerSec int
	// UID限制
	EnableUIDLimit    bool
	UIDMaxConnPerSec  int
	UIDMaxLoginPerSec int
	// 组合限制
	EnableCombinedLimit    bool
	CombinedMaxConnPerSec  int
	CombinedMaxLoginPerSec int
}

// 检查结果
type LimitResult struct {
	Allowed   bool
	Reason    string
	LimitType LimitType
}

// 默认配置
func DefaultLimiterConfig() *RateLimiterConfig {
	return &RateLimiterConfig{
		WindowSize:             1, // 1秒窗口
		EnableIPLimit:          true,
		IPMaxConnPerSec:        10,
		IPMaxLoginPerSec:       3,
		EnableUIDLimit:         true,
		UIDMaxConnPerSec:       5,
		UIDMaxLoginPerSec:      2,
		EnableCombinedLimit:    true,
		CombinedMaxConnPerSec:  3,
		CombinedMaxLoginPerSec: 2,
	}
}

// 创建频率限制器
func NewRateLimiter(cfg *RateLimiterConfig) *RateLimiter {
	if cfg == nil {
		cfg = DefaultLimiterConfig()
	}

	rl := &RateLimiter{
		ipRecords:       make(map[string]*limitRecord),
		uidRecords:      make(map[int]*limitRecord),
		combinedRecords: make(map[string]*limitRecord),
		config:          cfg,
		stopCleanup:     make(chan struct{}),
	}

	// 启动定期清理
	go rl.cleanupRoutine()

	return rl
}

// 检查连接频率 - 全面检查所有限制
func (rl *RateLimiter) CheckAll(ip string, uid int, isLogin bool) *LimitResult {
	// 构建组合键
	combinedKey := fmt.Sprintf("%s:%d", ip, uid)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	windowSize := time.Duration(rl.config.WindowSize) * time.Second

	// 检查IP频率限制
	if rl.config.EnableIPLimit {
		result := rl.checkRecord(ip, rl.ipRecords, now, windowSize,
			rl.config.IPMaxConnPerSec, rl.config.IPMaxLoginPerSec, isLogin, LimitTypeIP)
		if !result.Allowed {
			return result
		}
	}

	// 检查用户ID频率限制
	if rl.config.EnableUIDLimit && uid > 0 {
		result := rl.checkRecord(uid, rl.uidRecords, now, windowSize,
			rl.config.UIDMaxConnPerSec, rl.config.UIDMaxLoginPerSec, isLogin, LimitTypeUID)
		if !result.Allowed {
			return result
		}
	}

	// 检查组合频率限制
	if rl.config.EnableCombinedLimit && uid > 0 {
		result := rl.checkRecord(combinedKey, rl.combinedRecords, now, windowSize,
			rl.config.CombinedMaxConnPerSec, rl.config.CombinedMaxLoginPerSec, isLogin, LimitTypeCombined)
		if !result.Allowed {
			return result
		}
	}

	// 更新所有计数器（仅在允许通过时才更新）
	if rl.config.EnableIPLimit {
		rl.updateRecord(ip, rl.ipRecords, now)
	}
	if rl.config.EnableUIDLimit && uid > 0 {
		rl.updateRecord(uid, rl.uidRecords, now)
	}
	if rl.config.EnableCombinedLimit && uid > 0 {
		rl.updateRecord(combinedKey, rl.combinedRecords, now)
	}

	return &LimitResult{Allowed: true}
}

// 检查单个记录 - 泛型检查方法
func (rl *RateLimiter) checkRecord(key interface{}, records interface{}, now time.Time,
	windowSize time.Duration, maxConn int, maxLogin int, isLogin bool, limitType LimitType) *LimitResult {

	var record *limitRecord
	switch r := records.(type) {
	case map[string]*limitRecord:
		k := key.(string)
		record = r[k]
	case map[int]*limitRecord:
		k := key.(int)
		record = r[k]
	}

	if record == nil {
		return &LimitResult{Allowed: true}
	}

	// 检查是否在新窗口内
	if now.Sub(record.StartTime) > windowSize {
		return &LimitResult{Allowed: true}
	}

	// 检查连接数
	if isLogin && maxLogin > 0 && record.Count >= maxLogin {
		limitName := "IP"
		if limitType == LimitTypeUID {
			limitName = "用户ID"
		} else if limitType == LimitTypeCombined {
			limitName = "IP+UID组合"
		}
		return &LimitResult{
			Allowed:   false,
			Reason:    fmt.Sprintf("[%s]登录频率超限: 当前%d次/秒, 允许%d次/秒", limitName, record.Count, maxLogin),
			LimitType: limitType,
		}
	}

	if !isLogin && maxConn > 0 && record.Count >= maxConn {
		limitName := "IP"
		if limitType == LimitTypeUID {
			limitName = "用户ID"
		} else if limitType == LimitTypeCombined {
			limitName = "IP+UID组合"
		}
		return &LimitResult{
			Allowed:   false,
			Reason:    fmt.Sprintf("[%s]连接频率超限: 当前%d次/秒, 允许%d次/秒", limitName, record.Count, maxConn),
			LimitType: limitType,
		}
	}

	return &LimitResult{Allowed: true}
}

// 更新频率记录
func (rl *RateLimiter) updateRecord(key interface{}, records interface{}, now time.Time) {
	windowSize := time.Duration(rl.config.WindowSize) * time.Second

	switch r := records.(type) {
	case map[string]*limitRecord:
		k := key.(string)
		rec := r[k]
		if rec == nil || now.Sub(rec.StartTime) > windowSize {
			r[k] = &limitRecord{
				Count:      1,
				StartTime:  now,
				LastAccess: now,
			}
		} else {
			rec.Count++
			rec.LastAccess = now
		}
	case map[int]*limitRecord:
		k := key.(int)
		rec := r[k]
		if rec == nil || now.Sub(rec.StartTime) > windowSize {
			r[k] = &limitRecord{
				Count:      1,
				StartTime:  now,
				LastAccess: now,
			}
		} else {
			rec.Count++
			rec.LastAccess = now
		}
	}
}

// 获取IP当前频率信息
func (rl *RateLimiter) GetIPRate(ip string) int {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	rec, ok := rl.ipRecords[ip]
	if !ok {
		return 0
	}
	windowSize := time.Duration(rl.config.WindowSize) * time.Second
	if time.Since(rec.StartTime) > windowSize {
		return 0
	}
	return rec.Count
}

// 获取UID当前频率信息
func (rl *RateLimiter) GetUIDRate(uid int) int {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	rec, ok := rl.uidRecords[uid]
	if !ok {
		return 0
	}
	windowSize := time.Duration(rl.config.WindowSize) * time.Second
	if time.Since(rec.StartTime) > windowSize {
		return 0
	}
	return rec.Count
}

// 获取所有活跃IP的统计信息
func (rl *RateLimiter) GetActiveIPs() map[string]int {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	result := make(map[string]int)
	windowSize := time.Duration(rl.config.WindowSize) * time.Second

	for ip, rec := range rl.ipRecords {
		if time.Since(rec.StartTime) <= windowSize {
			result[ip] = rec.Count
		}
	}
	return result
}

// 获取所有活跃UID的统计信息
func (rl *RateLimiter) GetActiveUIDs() map[int]int {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	result := make(map[int]int)
	windowSize := time.Duration(rl.config.WindowSize) * time.Second

	for uid, rec := range rl.uidRecords {
		if time.Since(rec.StartTime) <= windowSize {
			result[uid] = rec.Count
		}
	}
	return result
}

// 重置IP限制
func (rl *RateLimiter) ResetIP(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.ipRecords, ip)
}

// 重置UID限制
func (rl *RateLimiter) ResetUID(uid int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.uidRecords, uid)
}

// 更新配置
func (rl *RateLimiter) UpdateConfig(cfg *RateLimiterConfig) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.config = cfg
}

// 定期清理过期记录
func (rl *RateLimiter) cleanupRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.cleanup()
		case <-rl.stopCleanup:
			return
		}
	}
}

// 清理过期记录
func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	windowSize := time.Duration(rl.config.WindowSize) * time.Second * 3 // 保留3倍窗口期
	cutoff := time.Now().Add(-windowSize)

	cleanMap := func(records map[string]*limitRecord) {
		for key, rec := range records {
			if rec.LastAccess.Before(cutoff) {
				delete(records, key)
			}
		}
	}
	cleanUIDMap := func(records map[int]*limitRecord) {
		for key, rec := range records {
			if rec.LastAccess.Before(cutoff) {
				delete(records, key)
			}
		}
	}

	cleanMap(rl.ipRecords)
	cleanUIDMap(rl.uidRecords)
	cleanMap(rl.combinedRecords)
}

// 从客户端地址提取IP
func ExtractIP(clientAddr string) string {
	host, _, err := net.SplitHostPort(clientAddr)
	if err != nil {
		return clientAddr
	}
	return host
}

// 从数据中提取用户ID - 用于协议解析
type UIDExtractor func(data []byte) int

// 检查并清洗IP
func CleanIP(ip string) string {
	return strings.TrimSpace(ip)
}

// 停止频率限制器
func (rl *RateLimiter) Stop() {
	close(rl.stopCleanup)
}
