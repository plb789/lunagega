package blacklist

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// 黑名单条目
type BlacklistEntry struct {
	// IP地址
	IP string `json:"ip"`
	// 用户ID, 0表示不限UID
	UID int `json:"uid"`
	// 组合键 IP:UID
	Combined string `json:"combined"`
	// 原因
	Reason string `json:"reason"`
	// 加入时间
	AddedTime time.Time `json:"added_time"`
	// 过期时间, 零值表示永不过期
	ExpireTime time.Time `json:"expire_time"`
	// 来源: manual 手动 / auto 自动学习
	Source string `json:"source"`
}

// 白名单条目
type WhitelistEntry struct {
	// IP地址
	IP string `json:"ip"`
	// 备注
	Note string `json:"note"`
	// 加入时间
	AddedTime time.Time `json:"added_time"`
}

// 黑名单管理器
type BlacklistManager struct {
	// IP黑名单
	ipBlacklist map[string]*BlacklistEntry
	// UID黑名单
	uidBlacklist map[int]*BlacklistEntry
	// 组合黑名单
	combinedBlacklist map[string]*BlacklistEntry
	// IP白名单
	ipWhitelist map[string]*WhitelistEntry
	// 互斥锁
	mu sync.RWMutex
	// 配置
	config *BlacklistConfig
	// 禁止列表存储文件路径
	persistFile string
	// 自动学习计数器: IP -> (窗口 -> 拒绝次数)
	autoLearnCounters map[string]*autoLearnRecord
	// 停止通道
	stopCleanup chan struct{}
}

// 自动学习记录
type autoLearnRecord struct {
	RejectCount int
	StartTime   time.Time
}

// 黑名单配置
type BlacklistConfig struct {
	EnableAutoLearn    bool
	AutoLearnThreshold int
	AutoLearnWindow    int // 秒
	BanDuration        int // 秒, 0表示永久
	PersistFile        string
}

// 默认黑名单配置
func DefaultBlacklistConfig() *BlacklistConfig {
	return &BlacklistConfig{
		EnableAutoLearn:    true,
		AutoLearnThreshold: 10,
		AutoLearnWindow:    60,
		BanDuration:        3600,
		PersistFile:        "blacklist.json",
	}
}

// 创建黑名单管理器
func NewBlacklistManager(cfg *BlacklistConfig) *BlacklistManager {
	if cfg == nil {
		cfg = DefaultBlacklistConfig()
	}

	bm := &BlacklistManager{
		ipBlacklist:       make(map[string]*BlacklistEntry),
		uidBlacklist:      make(map[int]*BlacklistEntry),
		combinedBlacklist: make(map[string]*BlacklistEntry),
		ipWhitelist:       make(map[string]*WhitelistEntry),
		config:            cfg,
		persistFile:       cfg.PersistFile,
		autoLearnCounters: make(map[string]*autoLearnRecord),
		stopCleanup:       make(chan struct{}),
	}

	// 从文件加载持久化黑名单
	bm.loadFromFile()

	// 启动清理过期条目
	go bm.cleanupRoutine()

	return bm
}

// 检查IP是否在黑名单中
func (bm *BlacklistManager) IsIPBlacklisted(ip string) (*BlacklistEntry, bool) {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	entry, ok := bm.ipBlacklist[ip]
	if !ok {
		return nil, false
	}

	// 检查是否已过期
	if !entry.ExpireTime.IsZero() && time.Now().After(entry.ExpireTime) {
		return nil, false
	}

	return entry, true
}

// 检查UID是否在黑名单中
func (bm *BlacklistManager) IsUIDBlacklisted(uid int) (*BlacklistEntry, bool) {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	entry, ok := bm.uidBlacklist[uid]
	if !ok {
		return nil, false
	}

	if !entry.ExpireTime.IsZero() && time.Now().After(entry.ExpireTime) {
		return nil, false
	}

	return entry, true
}

// 检查组合是否在黑名单中
func (bm *BlacklistManager) IsCombinedBlacklisted(ip string, uid int) (*BlacklistEntry, bool) {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	combinedKey := fmt.Sprintf("%s:%d", ip, uid)
	entry, ok := bm.combinedBlacklist[combinedKey]
	if !ok {
		return nil, false
	}

	if !entry.ExpireTime.IsZero() && time.Now().After(entry.ExpireTime) {
		return nil, false
	}

	return entry, true
}

// 全面检查是否在黑名单中
func (bm *BlacklistManager) IsBlacklisted(ip string, uid int) (bool, string) {
	// 先检查IP
	if entry, ok := bm.IsIPBlacklisted(ip); ok {
		return true, fmt.Sprintf("IP黑名单: %s", entry.Reason)
	}

	// 再检查UID
	if uid > 0 {
		if entry, ok := bm.IsUIDBlacklisted(uid); ok {
			return true, fmt.Sprintf("UID黑名单: %s", entry.Reason)
		}
	}

	// 最后检查组合
	if uid > 0 {
		if entry, ok := bm.IsCombinedBlacklisted(ip, uid); ok {
			return true, fmt.Sprintf("组合黑名单: %s", entry.Reason)
		}
	}

	return false, ""
}

// 检查IP是否在白名单中
func (bm *BlacklistManager) IsIPWhitelisted(ip string) bool {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	_, ok := bm.ipWhitelist[ip]
	return ok
}

// 添加IP到黑名单
func (bm *BlacklistManager) AddIPBlacklist(ip, reason, source string) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	entry := &BlacklistEntry{
		IP:        ip,
		Reason:    reason,
		AddedTime: time.Now(),
		Source:    source,
	}

	if bm.config.BanDuration > 0 {
		entry.ExpireTime = time.Now().Add(time.Duration(bm.config.BanDuration) * time.Second)
	}

	bm.ipBlacklist[ip] = entry
	bm.saveToFile()
}

// 添加UID到黑名单
func (bm *BlacklistManager) AddUIDBlacklist(uid int, reason, source string) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	entry := &BlacklistEntry{
		UID:       uid,
		Reason:    reason,
		AddedTime: time.Now(),
		Source:    source,
	}

	if bm.config.BanDuration > 0 {
		entry.ExpireTime = time.Now().Add(time.Duration(bm.config.BanDuration) * time.Second)
	}

	bm.uidBlacklist[uid] = entry
	bm.saveToFile()
}

// 添加IP+UID组合到黑名单
func (bm *BlacklistManager) AddCombinedBlacklist(ip string, uid int, reason, source string) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	combinedKey := fmt.Sprintf("%s:%d", ip, uid)
	entry := &BlacklistEntry{
		IP:       ip,
		UID:      uid,
		Combined: combinedKey,
		Reason:   reason,
		AddedTime: time.Now(),
		Source:    source,
	}

	if bm.config.BanDuration > 0 {
		entry.ExpireTime = time.Now().Add(time.Duration(bm.config.BanDuration) * time.Second)
	}

	bm.combinedBlacklist[combinedKey] = entry
	bm.saveToFile()
}

// 添加IP到白名单
func (bm *BlacklistManager) AddIPWhitelist(ip, note string) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	bm.ipWhitelist[ip] = &WhitelistEntry{
		IP:        ip,
		Note:      note,
		AddedTime: time.Now(),
	}
}

// 移除IP黑名单
func (bm *BlacklistManager) RemoveIPBlacklist(ip string) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	delete(bm.ipBlacklist, ip)
	bm.saveToFile()
}

// 移除UID黑名单
func (bm *BlacklistManager) RemoveUIDBlacklist(uid int) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	delete(bm.uidBlacklist, uid)
	bm.saveToFile()
}

// 移除组合黑名单
func (bm *BlacklistManager) RemoveCombinedBlacklist(ip string, uid int) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	combinedKey := fmt.Sprintf("%s:%d", ip, uid)
	delete(bm.combinedBlacklist, combinedKey)
	bm.saveToFile()
}

// 记录被拒绝的连接，用于自动学习
func (bm *BlacklistManager) RecordReject(ip string, uid int) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	if !bm.config.EnableAutoLearn {
		return
	}

	// 更新自动学习计数器
	now := time.Now()
	windowSize := time.Duration(bm.config.AutoLearnWindow) * time.Second

	key := ip
	if uid > 0 {
		key = fmt.Sprintf("%s:%d", ip, uid)
	}

	rec, ok := bm.autoLearnCounters[key]
	if !ok || now.Sub(rec.StartTime) > windowSize {
		bm.autoLearnCounters[key] = &autoLearnRecord{
			RejectCount: 1,
			StartTime:   now,
		}
		return
	}

	rec.RejectCount++

	// 达到阈值自动加入黑名单
	if rec.RejectCount >= bm.config.AutoLearnThreshold {
		// 检查当前是否已在黑名单中
		if _, ok := bm.ipBlacklist[ip]; !ok {
			if uid > 0 {
				combinedKey := fmt.Sprintf("%s:%d", ip, uid)
				if _, ok := bm.combinedBlacklist[combinedKey]; !ok {
					// 先加IP黑名单
					entry := &BlacklistEntry{
						IP:        ip,
						Reason:    fmt.Sprintf("自动学习: %d秒内被拒绝%d次", bm.config.AutoLearnWindow, rec.RejectCount),
						AddedTime: now,
						Source:    "auto",
					}
					if bm.config.BanDuration > 0 {
						entry.ExpireTime = now.Add(time.Duration(bm.config.BanDuration) * time.Second)
					}
					bm.ipBlacklist[ip] = entry
					bm.saveToFile()
				}
			} else {
				entry := &BlacklistEntry{
					IP:        ip,
					Reason:    fmt.Sprintf("自动学习: %d秒内被拒绝%d次", bm.config.AutoLearnWindow, rec.RejectCount),
					AddedTime: now,
					Source:    "auto",
				}
				if bm.config.BanDuration > 0 {
					entry.ExpireTime = now.Add(time.Duration(bm.config.BanDuration) * time.Second)
				}
				bm.ipBlacklist[ip] = entry
				bm.saveToFile()
			}
		}
	}
}

// 清除所有黑名单
func (bm *BlacklistManager) ClearAll() {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	bm.ipBlacklist = make(map[string]*BlacklistEntry)
	bm.uidBlacklist = make(map[int]*BlacklistEntry)
	bm.combinedBlacklist = make(map[string]*BlacklistEntry)
	bm.autoLearnCounters = make(map[string]*autoLearnRecord)
	bm.saveToFile()
}

// 获取黑名单列表
func (bm *BlacklistManager) GetIPBlacklist() []BlacklistEntry {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	result := make([]BlacklistEntry, 0, len(bm.ipBlacklist))
	for _, entry := range bm.ipBlacklist {
		result = append(result, *entry)
	}
	return result
}

// 获取UID黑名单列表
func (bm *BlacklistManager) GetUIDBlacklist() []BlacklistEntry {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	result := make([]BlacklistEntry, 0, len(bm.uidBlacklist))
	for _, entry := range bm.uidBlacklist {
		result = append(result, *entry)
	}
	return result
}

// 获取白名单列表
func (bm *BlacklistManager) GetWhitelist() []WhitelistEntry {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	result := make([]WhitelistEntry, 0, len(bm.ipWhitelist))
	for _, entry := range bm.ipWhitelist {
		result = append(result, *entry)
	}
	return result
}

// 持久化到文件
func (bm *BlacklistManager) saveToFile() {
	if bm.persistFile == "" {
		return
	}

	data := struct {
		IPBlacklist       []BlacklistEntry  `json:"ip_blacklist"`
		UIDBlacklist      []BlacklistEntry  `json:"uid_blacklist"`
		CombinedBlacklist []BlacklistEntry  `json:"combined_blacklist"`
		IPWhitelist       []WhitelistEntry  `json:"ip_whitelist"`
	}{
		IPBlacklist:       make([]BlacklistEntry, 0, len(bm.ipBlacklist)),
		UIDBlacklist:      make([]BlacklistEntry, 0, len(bm.uidBlacklist)),
		CombinedBlacklist: make([]BlacklistEntry, 0, len(bm.combinedBlacklist)),
		IPWhitelist:       make([]WhitelistEntry, 0, len(bm.ipWhitelist)),
	}

	for _, entry := range bm.ipBlacklist {
		data.IPBlacklist = append(data.IPBlacklist, *entry)
	}
	for _, entry := range bm.uidBlacklist {
		data.UIDBlacklist = append(data.UIDBlacklist, *entry)
	}
	for _, entry := range bm.combinedBlacklist {
		data.CombinedBlacklist = append(data.CombinedBlacklist, *entry)
	}
	for _, entry := range bm.ipWhitelist {
		data.IPWhitelist = append(data.IPWhitelist, *entry)
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(bm.persistFile, jsonData, 0644)
}

// 从文件加载
func (bm *BlacklistManager) loadFromFile() {
	if bm.persistFile == "" {
		return
	}

	data, err := os.ReadFile(bm.persistFile)
	if err != nil {
		return
	}

	var loaded struct {
		IPBlacklist       []BlacklistEntry  `json:"ip_blacklist"`
		UIDBlacklist      []BlacklistEntry  `json:"uid_blacklist"`
		CombinedBlacklist []BlacklistEntry  `json:"combined_blacklist"`
		IPWhitelist       []WhitelistEntry  `json:"ip_whitelist"`
	}

	if err := json.Unmarshal(data, &loaded); err != nil {
		return
	}

	for _, entry := range loaded.IPBlacklist {
		// 检查是否过期
		if !entry.ExpireTime.IsZero() && time.Now().After(entry.ExpireTime) {
			continue
		}
		e := entry
		bm.ipBlacklist[entry.IP] = &e
	}

	for _, entry := range loaded.UIDBlacklist {
		if !entry.ExpireTime.IsZero() && time.Now().After(entry.ExpireTime) {
			continue
		}
		e := entry
		bm.uidBlacklist[entry.UID] = &e
	}

	for _, entry := range loaded.CombinedBlacklist {
		if !entry.ExpireTime.IsZero() && time.Now().After(entry.ExpireTime) {
			continue
		}
		e := entry
		bm.combinedBlacklist[entry.Combined] = &e
	}

	for _, entry := range loaded.IPWhitelist {
		e := entry
		bm.ipWhitelist[entry.IP] = &e
	}
}

// 清理过期条目
func (bm *BlacklistManager) cleanupRoutine() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			bm.cleanupExpired()
		case <-bm.stopCleanup:
			return
		}
	}
}

// 清理过期黑名单
func (bm *BlacklistManager) cleanupExpired() {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	now := time.Now()

	// 清理IP黑名单
	for ip, entry := range bm.ipBlacklist {
		if !entry.ExpireTime.IsZero() && now.After(entry.ExpireTime) {
			delete(bm.ipBlacklist, ip)
		}
	}

	// 清理UID黑名单
	for uid, entry := range bm.uidBlacklist {
		if !entry.ExpireTime.IsZero() && now.After(entry.ExpireTime) {
			delete(bm.uidBlacklist, uid)
		}
	}

	// 清理组合黑名单
	for key, entry := range bm.combinedBlacklist {
		if !entry.ExpireTime.IsZero() && now.After(entry.ExpireTime) {
			delete(bm.combinedBlacklist, key)
		}
	}

	// 清理自动学习计数器
	windowSize := time.Duration(bm.config.AutoLearnWindow*2) * time.Second
	for key, rec := range bm.autoLearnCounters {
		if now.Sub(rec.StartTime) > windowSize {
			delete(bm.autoLearnCounters, key)
		}
	}
}

// 根据日志文件分析并自动加入黑名单
func (bm *BlacklistManager) AnalyzeLogAndBlock(logContent string) []string {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	now := time.Now()
	windowSize := time.Duration(bm.config.AutoLearnWindow) * time.Second
	var blockedIPs []string

	// 解析日志行,提取时间戳和用户ID
	lines := strings.Split(logContent, "\n")
	ipCounts := make(map[string]int)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 解析时间戳格式: [2026-08-10 17:11:49]
		if len(line) < 22 {
			continue
		}
		timeStr := line[1:20] // 提取时间部分: 2026-08-10 17:11:49
		t, err := time.Parse("2006-01-02 15:04:05", timeStr)
		if err != nil {
			continue
		}

		// 检查是否在时间窗口内
		if now.Sub(t) > windowSize {
			continue
		}

		// 提取UserIdx
		idxStart := strings.LastIndex(line, "UserIdx : ")
		if idxStart == -1 {
			continue
		}

		uidStr := strings.TrimSpace(line[idxStart+len("UserIdx : "):])
		uidStr = strings.TrimRight(uidStr, "]")

		// 使用UserIdx作为标识来统计频率
		key := "UserIdx:" + uidStr
		ipCounts[key]++
	}

	// 将高频UserIdx加入黑名单
	for key, count := range ipCounts {
		if count >= bm.config.AutoLearnThreshold {
			parts := strings.Split(key, ":")
			if len(parts) == 2 {
				uidStr := parts[1]
				// 使用UserIdx作为封禁标识
				existingKey := key
				if _, exists := bm.ipBlacklist[existingKey]; !exists {
					entry := &BlacklistEntry{
						IP:        existingKey,
						Reason:    fmt.Sprintf("日志分析: %d秒内出现%d次异常登录", bm.config.AutoLearnWindow, count),
						AddedTime: now,
						Source:    "auto_analysis",
					}
					if bm.config.BanDuration > 0 {
						entry.ExpireTime = now.Add(time.Duration(bm.config.BanDuration) * time.Second)
					}
					bm.ipBlacklist[existingKey] = entry
					blockedIPs = append(blockedIPs, fmt.Sprintf("%s(出现%d次)", uidStr, count))
				}
			}
		}
	}

	if len(blockedIPs) > 0 {
		bm.saveToFile()
	}

	return blockedIPs
}

// 停止黑名单管理器
func (bm *BlacklistManager) Stop() {
	close(bm.stopCleanup)
}
