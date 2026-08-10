package config

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sync"
)

// 转发规则 - 定义单个端口转发规则
type ForwardRule struct {
	// 监听地址
	ListenAddr string `json:"listen_addr"`
	// 后端地址列表
	BackendAddrs []string `json:"backend_addrs"`
	// 负载均衡策略: round_robin / least_conn / random
	LBStrategy string `json:"lb_strategy"`
	// 读写超时(秒)
	Timeout int `json:"timeout"`
}

// 频率限制配置
type RateLimitConfig struct {
	// 是否启用IP频率限制
	EnableIPLimit bool `json:"enable_ip_limit"`
	// 每个IP每秒最大连接数
	IPMaxConnPerSec int `json:"ip_max_conn_per_sec"`
	// 每个IP每秒最大登录数
	IPMaxLoginPerSec int `json:"ip_max_login_per_sec"`
	// 是否启用用户ID频率限制
	EnableUIDLimit bool `json:"enable_uid_limit"`
	// 每个用户ID每秒最大连接数
	UIDMaxConnPerSec int `json:"uid_max_conn_per_sec"`
	// 每个用户ID每秒最大登录数
	UIDMaxLoginPerSec int `json:"uid_max_login_per_sec"`
	// 组合策略: 是否同时检查IP+UID
	EnableCombinedLimit bool `json:"enable_combined_limit"`
	// 组合策略下每秒最大连接数
	CombinedMaxConnPerSec int `json:"combined_max_conn_per_sec"`
}

// 黑名单配置
type BlacklistConfig struct {
	// 是否启用自动学习
	EnableAutoLearn bool `json:"enable_auto_learn"`
	// 自动学习阈值: 超过此频率次数自动加入黑名单
	AutoLearnThreshold int `json:"auto_learn_threshold"`
	// 自动学习时间窗口(秒)
	AutoLearnWindow int `json:"auto_learn_window"`
	// 黑名单封禁时长(秒), 0表示永久
	BanDuration int `json:"ban_duration"`
	// 黑名单存储文件路径
	PersistFile string `json:"persist_file"`
}

// 流量控制配置
type TrafficControlConfig struct {
	// 是否启用流量限速
	EnableRateLimit bool `json:"enable_rate_limit"`
	// 每个连接最大速率(KB/s)
	MaxRatePerConn int `json:"max_rate_per_conn"`
	// 突发流量大小(KB)
	BurstSize int `json:"burst_size"`
}

// 监控配置
type MonitorConfig struct {
	// 是否启用监控
	Enable bool `json:"enable"`
	// 统计刷新间隔(秒)
	RefreshInterval int `json:"refresh_interval"`
	// 是否输出到日志
	LogOutput bool `json:"log_output"`
}

// 日志配置
type LogConfig struct {
	// 日志级别: debug / info / warn / error
	Level string `json:"level"`
	// 日志文件路径
	FilePath string `json:"file_path"`
	// 是否开启控制台输出
	ConsoleOutput bool `json:"console_output"`
	// 日志轮转最大文件大小(MB)
	MaxSize int `json:"max_size"`
	// 日志轮转保留天数
	MaxAge int `json:"max_age"`
	// 日志轮转保留文件数
	MaxBackups int `json:"max_backups"`
}

// API管理接口配置
type APIConfig struct {
	// 是否启用API接口
	Enable bool `json:"enable"`
	// API监听地址
	ListenAddr string `json:"listen_addr"`
	// API访问密钥
	AuthToken string `json:"auth_token"`
}

// 主配置结构体
type Config struct {
	// 转发规则列表
	ForwardRules []ForwardRule `json:"forward_rules"`
	// 频率限制配置
	RateLimit RateLimitConfig `json:"rate_limit"`
	// 黑名单配置
	Blacklist BlacklistConfig `json:"blacklist"`
	// 流量控制配置
	TrafficControl TrafficControlConfig `json:"traffic_control"`
	// 监控配置
	Monitor MonitorConfig `json:"monitor"`
	// 日志配置
	Log LogConfig `json:"log"`
	// API配置
	API APIConfig `json:"api"`
}

// 全局配置实例
var (
	globalConfig *Config
	configMutex  sync.RWMutex
	configFile   string
)

// 命令行参数
var (
	argConfigFile  = flag.String("config", "config.json", "配置文件路径")
	argShowVersion = flag.Bool("version", false, "显示版本信息")
	argLogLevel    = flag.String("log-level", "", "日志级别(覆盖配置文件)")
	argAPIPort     = flag.Int("api-port", 0, "API管理端口(覆盖配置文件)")
)

// 生成默认配置
func DefaultConfig() *Config {
	return &Config{
		ForwardRules: []ForwardRule{
			{
				ListenAddr:   "0.0.0.0:9000",
				BackendAddrs: []string{"127.0.0.1:8080"},
				LBStrategy:   "round_robin",
				Timeout:      30,
			},
		},
		RateLimit: RateLimitConfig{
			EnableIPLimit:        true,
			IPMaxConnPerSec:      10,
			IPMaxLoginPerSec:     3,
			EnableUIDLimit:       true,
			UIDMaxConnPerSec:     5,
			UIDMaxLoginPerSec:    2,
			EnableCombinedLimit:  true,
			CombinedMaxConnPerSec: 3,
		},
		Blacklist: BlacklistConfig{
			EnableAutoLearn:    true,
			AutoLearnThreshold: 10,
			AutoLearnWindow:    60,
			BanDuration:        3600,
			PersistFile:        "blacklist.json",
		},
		TrafficControl: TrafficControlConfig{
			EnableRateLimit: true,
			MaxRatePerConn:  1024,
			BurstSize:       2048,
		},
		Monitor: MonitorConfig{
			Enable:          true,
			RefreshInterval: 10,
			LogOutput:       true,
		},
		Log: LogConfig{
			Level:         "info",
			FilePath:      "logs/gateway.log",
			ConsoleOutput: true,
			MaxSize:       100,
			MaxAge:        30,
			MaxBackups:    10,
		},
		API: APIConfig{
			Enable:     true,
			ListenAddr: "0.0.0.0:9999",
			AuthToken:  "admin-token-change-me",
		},
	}
}

// 加载配置文件
func LoadConfig(filePath string) (*Config, error) {
	// 先使用默认配置
	cfg := DefaultConfig()

	// 如果配置文件存在则读取
	if _, err := os.Stat(filePath); err == nil {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("读取配置文件失败: %v", err)
		}
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("解析配置文件失败: %v", err)
		}
	} else if os.IsNotExist(err) {
		// 配置文件不存在，生成默认配置文件
		if err := SaveConfig(filePath, cfg); err != nil {
			return nil, fmt.Errorf("生成默认配置文件失败: %v", err)
		}
	} else {
		return nil, fmt.Errorf("检查配置文件失败: %v", err)
	}

	return cfg, nil
}

// 保存配置文件
func SaveConfig(filePath string, cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置失败: %v", err)
	}
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("写入配置文件失败: %v", err)
	}
	return nil
}

// 初始化配置
func InitConfig() (*Config, error) {
	flag.Parse()

	if *argShowVersion {
		fmt.Println("Gateway 企业级网关防护程序 v1.0.0")
		os.Exit(0)
	}

	// 加载配置文件
	cfg, err := LoadConfig(*argConfigFile)
	if err != nil {
		return nil, err
	}

	// 命令行参数覆盖配置文件
	if *argLogLevel != "" {
		cfg.Log.Level = *argLogLevel
	}
	if *argAPIPort > 0 {
		cfg.API.ListenAddr = fmt.Sprintf("0.0.0.0:%d", *argAPIPort)
	}

	configFile = *argConfigFile
	globalConfig = cfg
	return cfg, nil
}

// 获取全局配置（线程安全）
func GetConfig() *Config {
	configMutex.RLock()
	defer configMutex.RUnlock()
	return globalConfig
}

// 更新全局配置（线程安全）
func UpdateConfig(cfg *Config) error {
	configMutex.Lock()
	defer configMutex.Unlock()

	// 保存到文件
	if err := SaveConfig(configFile, cfg); err != nil {
		return err
	}

	globalConfig = cfg
	return nil
}
