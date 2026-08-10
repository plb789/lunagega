package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// 日志级别定义
const (
	LevelDebug = iota
	LevelInfo
	LevelWarn
	LevelError
)

// 日志级别字符串映射
var levelNames = map[int]string{
	LevelDebug: "DEBUG",
	LevelInfo:  "INFO",
	LevelWarn:  "WARN",
	LevelError: "ERROR",
}

// 日志记录器
type Logger struct {
	debugLogger *log.Logger
	infoLogger  *log.Logger
	warnLogger  *log.Logger
	errorLogger *log.Logger
	level       int
	file        *os.File
	mu          sync.Mutex
	config      *LogConfig
}

// 日志配置
type LogConfig struct {
	Level         string
	FilePath      string
	ConsoleOutput bool
	MaxSize       int // MB
	MaxAge        int // 天
	MaxBackups    int
}

// 连接日志条目 - 用于分析
type ConnLogEntry struct {
	Timestamp   time.Time
	ClientIP    string
	UserIdx     int
	State       int
	Action      string // connect / login / disconnect / rejected
	BytesRead   int64
	BytesWrite  int64
	Duration    float64
	RejectReason string
}

// 日志分析器
type LogAnalyzer struct {
	entries   []ConnLogEntry
	mu        sync.RWMutex
	maxSize   int
}

var (
	defaultLogger *Logger
	analyzer      *LogAnalyzer
	once          sync.Once
)

// 初始化默认日志器
func InitLogger(cfg *LogConfig) error {
	var err error
	defaultLogger, err = NewLogger(cfg)
	if err != nil {
		return err
	}

	// 初始化分析器
	analyzer = &LogAnalyzer{
		entries: make([]ConnLogEntry, 0, 10000),
		maxSize: 100000,
	}
	return nil
}

// 创建新日志器
func NewLogger(cfg *LogConfig) (*Logger, error) {
	l := &Logger{
		config: cfg,
	}

	// 设置日志级别
	switch strings.ToLower(cfg.Level) {
	case "debug":
		l.level = LevelDebug
	case "info":
		l.level = LevelInfo
	case "warn":
		l.level = LevelWarn
	case "error":
		l.level = LevelError
	default:
		l.level = LevelInfo
	}

	// 创建日志目录
	if cfg.FilePath != "" {
		dir := filepath.Dir(cfg.FilePath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("创建日志目录失败: %v", err)
		}
	}

	// 打开日志文件
	if err := l.rotateLogFile(); err != nil {
		return nil, err
	}

	// 设置输出目标
	var writers []io.Writer
	if l.file != nil {
		writers = append(writers, l.file)
	}
	if cfg.ConsoleOutput {
		writers = append(writers, os.Stdout)
	}

	var writer io.Writer
	if len(writers) == 0 {
		writer = io.Discard
	} else if len(writers) == 1 {
		writer = writers[0]
	} else {
		writer = io.MultiWriter(writers...)
	}

	// 创建各级别日志器
	l.debugLogger = log.New(writer, "[DEBUG] ", log.LstdFlags)
	l.infoLogger = log.New(writer, "[INFO]  ", log.LstdFlags)
	l.warnLogger = log.New(writer, "[WARN]  ", log.LstdFlags)
	l.errorLogger = log.New(writer, "[ERROR] ", log.LstdFlags)

	return l, nil
}

// 轮转日志文件
func (l *Logger) rotateLogFile() error {
	if l.config.FilePath == "" {
		return nil
	}

	// 检查是否需要轮转
	if l.file != nil {
		info, err := l.file.Stat()
		if err != nil {
			return fmt.Errorf("获取日志文件信息失败: %v", err)
		}
		maxBytes := int64(l.config.MaxSize) * 1024 * 1024
		if info.Size() < maxBytes {
			return nil
		}
		// 关闭旧文件
		l.file.Close()
	}

	// 轮转旧日志文件
	rotateFiles(l.config.FilePath, l.config.MaxBackups, l.config.MaxAge)

	// 打开新日志文件
	file, err := os.OpenFile(l.config.FilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("打开日志文件失败: %v", err)
	}
	l.file = file
	return nil
}

// 轮转日志文件
func rotateFiles(basePath string, maxBackups int, maxAge int) {
	ext := filepath.Ext(basePath)
	prefix := basePath[:len(basePath)-len(ext)]

	// 删除旧备份
	for i := maxBackups; i >= 0; i-- {
		var oldPath string
		if i == 0 {
			oldPath = basePath
		} else {
			oldPath = fmt.Sprintf("%s.%d%s", prefix, i, ext)
		}

		if _, err := os.Stat(oldPath); err == nil {
			if i == maxBackups || i == 0 {
				os.Remove(oldPath)
			} else {
				newPath := fmt.Sprintf("%s.%d%s", prefix, i+1, ext)
				os.Rename(oldPath, newPath)
			}
		}
	}

	// 清理过期日志
	cutoff := time.Now().AddDate(0, 0, -maxAge)
	for i := 1; i <= maxBackups; i++ {
		path := fmt.Sprintf("%s.%d%s", prefix, i, ext)
		if info, err := os.Stat(path); err == nil {
			if info.ModTime().Before(cutoff) {
				os.Remove(path)
			}
		}
	}
}

// 格式化日志消息
func (l *Logger) logf(level int, format string, v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if level < l.level {
		return
	}

	// 定期检查是否需要轮转
	if l.file != nil {
		if info, _ := l.file.Stat(); info != nil {
			maxBytes := int64(l.config.MaxSize) * 1024 * 1024
			if info.Size() >= maxBytes {
				l.rotateLogFile()
			}
		}
	}

	msg := fmt.Sprintf(format, v...)
	switch level {
	case LevelDebug:
		l.debugLogger.Output(3, msg)
	case LevelInfo:
		l.infoLogger.Output(3, msg)
	case LevelWarn:
		l.warnLogger.Output(3, msg)
	case LevelError:
		l.errorLogger.Output(3, msg)
	}
}

// 关闭日志器
func (l *Logger) Close() {
	if l.file != nil {
		l.file.Close()
	}
}

// 全局日志方法
func Debug(format string, v ...interface{}) {
	if defaultLogger != nil {
		defaultLogger.logf(LevelDebug, format, v...)
	}
}

func Info(format string, v ...interface{}) {
	if defaultLogger != nil {
		defaultLogger.logf(LevelInfo, format, v...)
	}
}

func Warn(format string, v ...interface{}) {
	if defaultLogger != nil {
		defaultLogger.logf(LevelWarn, format, v...)
	}
}

func Error(format string, v ...interface{}) {
	if defaultLogger != nil {
		defaultLogger.logf(LevelError, format, v...)
	}
}

// 记录连接日志到分析器
func LogConnEntry(entry ConnLogEntry) {
	if analyzer == nil {
		return
	}
	analyzer.mu.Lock()
	defer analyzer.mu.Unlock()

	analyzer.entries = append(analyzer.entries, entry)
	if len(analyzer.entries) > analyzer.maxSize {
		// 只保留最近的数据
		analyzer.entries = analyzer.entries[len(analyzer.entries)-analyzer.maxSize:]
	}
}

// 获取IP频率分析
func GetIPFreqAnalysis(ip string, duration time.Duration) *IPFreqAnalysis {
	if analyzer == nil {
		return nil
	}
	analyzer.mu.RLock()
	defer analyzer.mu.RUnlock()

	cutoff := time.Now().Add(-duration)
	result := &IPFreqAnalysis{
		IP:            ip,
		Duration:      duration,
		States:        make(map[int]int),
		RejectReasons: make(map[string]int),
	}

	for _, entry := range analyzer.entries {
		if entry.Timestamp.Before(cutoff) {
			continue
		}
		if ip != "" && entry.ClientIP != ip {
			continue
		}
		result.TotalConns++
		result.States[entry.State]++
		if entry.BytesRead > 0 {
			result.TotalBytesRead += entry.BytesRead
		}
		if entry.BytesWrite > 0 {
			result.TotalBytesWrite += entry.BytesWrite
		}
		if entry.RejectReason != "" {
			result.TotalRejects++
			result.RejectReasons[entry.RejectReason]++
		}
	}

	// 计算每秒频率
	secs := duration.Seconds()
	if secs > 0 {
		result.ConnPerSec = float64(result.TotalConns) / secs
		result.RejectPerSec = float64(result.TotalRejects) / secs
	}

	return result
}

// 获取用户ID频率分析
func GetUIDFreqAnalysis(uid int, duration time.Duration) *UIDFreqAnalysis {
	if analyzer == nil {
		return nil
	}
	analyzer.mu.RLock()
	defer analyzer.mu.RUnlock()

	cutoff := time.Now().Add(-duration)
	result := &UIDFreqAnalysis{
		UID:      uid,
		Duration: duration,
	}

	for _, entry := range analyzer.entries {
		if entry.Timestamp.Before(cutoff) {
			continue
		}
		if entry.UserIdx != uid {
			continue
		}
		result.TotalConns++
		if entry.RejectReason != "" {
			result.TotalRejects++
		}
	}

	secs := duration.Seconds()
	if secs > 0 {
		result.ConnPerSec = float64(result.TotalConns) / secs
	}

	return result
}

// 获取Top攻击者
func GetTopAttackers(topN int) []AttackerInfo {
	if analyzer == nil {
		return nil
	}
	analyzer.mu.RLock()
	defer analyzer.mu.RUnlock()

	// 统计每个IP被拒绝次数
	ipRejects := make(map[string]int)
	for _, entry := range analyzer.entries {
		if entry.RejectReason != "" {
			ipRejects[entry.ClientIP]++
		}
	}

	// 排序取TopN
	type kv struct {
		IP    string
		Count int
	}
	var sorted []kv
	for ip, count := range ipRejects {
		sorted = append(sorted, kv{ip, count})
	}
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].Count > sorted[i].Count {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	if topN > len(sorted) {
		topN = len(sorted)
	}

	result := make([]AttackerInfo, topN)
	for i := 0; i < topN; i++ {
		result[i] = AttackerInfo{
			IP:     sorted[i].IP,
			Rejects: sorted[i].Count,
		}
	}
	return result
}

// IP频率分析结果
type IPFreqAnalysis struct {
	IP              string
	Duration        time.Duration
	TotalConns      int
	TotalRejects    int
	TotalBytesRead  int64
	TotalBytesWrite int64
	ConnPerSec      float64
	RejectPerSec    float64
	States          map[int]int
	RejectReasons   map[string]int
}

// 用户ID频率分析结果
type UIDFreqAnalysis struct {
	UID          int
	Duration     time.Duration
	TotalConns   int
	TotalRejects int
	ConnPerSec   float64
}

// 攻击者信息
type AttackerInfo struct {
	IP      string
	Rejects int
}
