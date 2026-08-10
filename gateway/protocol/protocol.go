package protocol

import (
	"encoding/binary"
	"sync"
	"time"
)

// ============================================================
// AG游戏服务器协议解析模块
// 基于 Agent/AgentNetworkMsgParser.cpp 和 ServerSystem.cpp 分析
// ============================================================

// MSGROOT 消息头结构 (10字节)
// 对应 C++ 结构:
//
//	WORD  Category     // 消息类别 (0-1字节)
//	WORD  Protocol     // 协议号   (2-3字节)
//	BYTE  CheckSum     // 校验和(序列号) (4字节)
//	BYTE  Code         // 加密CRC字符  (5字节)
//	DWORD dwObjectID   // 对象ID/UserID (6-9字节)
type MSGROOT struct {
	Category   uint16 // 消息类别
	Protocol   uint16 // 协议号
	CheckSum   uint8  // 校验和(递增序列号)
	Code       uint8  // 加密CRC字符
	DwObjectID uint32 // 对象ID(登录时为UserID)
}

// MSG_DWORD3BYTE2 登录包结构 (20字节)
// MSGROOT(10) + DWORD + DWORD + BYTE + BYTE = 20字节
type MSGLogin struct {
	Root                MSGROOT
	DistAuthKey         uint32 // Distribute服务器认证密钥
	DistConnectionIndex uint32 // Distribute连接索引(即UserIdx)
	UserLevel           uint8  // 用户等级
	Reserved            uint8  // 保留
}

// 消息类别常量 (根据AG源码命名推断)
const (
	CategoryMonitor   uint16 = 1 // MP_MONITOR 监控类
	CategorySignal    uint16 = 2 // MP_SIGNAL  信号类
	CategoryUserConn  uint16 = 3 // MP_USERCONN 用户连接类
	CategoryMapServer uint16 = 4 // MP_MAPSERVER MapServer通信类
)

// MP_USERCONN 协议号常量
const (
	ProtoUserLoginSyn           uint16 = 0  // 用户登录请求
	ProtoUserLoginAck           uint16 = 1  // 登录成功应答
	ProtoUserLoginNack          uint16 = 2  // 登录失败应答 ← 关键检测点
	ProtoNotifyOverlappedLogin  uint16 = 3  // 重复登录通知
	ProtoForceDisconnectOverlap uint16 = 4  // 强制断开重复登录
	ProtoDisconnectedOnLogin    uint16 = 5  // 登录过程中断连
	ProtoDisconnectSyn          uint16 = 6  // 断开连接同步
	ProtoConnectionCheck        uint16 = 7  // 心跳检测包
	ProtoConnectionCheckOk      uint16 = 8  // 心跳响应
	ProtoCharacterListSyn       uint16 = 9  // 角色列表同步
	ProtoCharacterSelectSyn     uint16 = 10 // 角色选择同步
	ProtoGameInSyn              uint16 = 11 // 进入游戏
	ProtoGameInAck              uint16 = 12 // 进入游戏应答
	ProtoChangeMapSyn           uint16 = 13 // 切换地图
	ProtoDisconnectedByOverlap  uint16 = 14 // 因重复登录被断开
	ProtoNowaitExitPlayer       uint16 = 15 // 不等待玩家退出
)

// 消息总大小常量
const (
	MsgRootSize  = 10 // MSGROOT大小
	MsgLoginSize = 20 // 登录包总大小
	MsgBaseSize  = 10 // MSGBASE大小(心跳包等)
)

// 解析MSGROOT消息头
func ParseRoot(data []byte) (*MSGROOT, bool) {
	if len(data) < MsgRootSize {
		return nil, false
	}
	return &MSGROOT{
		Category:   binary.LittleEndian.Uint16(data[0:2]),
		Protocol:   binary.LittleEndian.Uint16(data[2:4]),
		CheckSum:   data[4],
		Code:       data[5],
		DwObjectID: binary.LittleEndian.Uint32(data[6:10]),
	}, true
}

// 解析登录包
func ParseLogin(data []byte) (*MSGLogin, bool) {
	if len(data) < MsgLoginSize {
		return nil, false
	}

	root, ok := ParseRoot(data)
	if !ok {
		return nil, false
	}

	return &MSGLogin{
		Root:                *root,
		DistAuthKey:         binary.LittleEndian.Uint32(data[10:14]),
		DistConnectionIndex: binary.LittleEndian.Uint32(data[14:18]),
		UserLevel:           data[18],
		Reserved:            data[19],
	}, true
}

// 是否为用户连接类别消息
func IsUserConn(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	cat := binary.LittleEndian.Uint16(data[0:2])
	return cat == CategoryUserConn || cat == CategoryMapServer
}

// 是否为登录请求包
func IsLoginRequest(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	cat := binary.LittleEndian.Uint16(data[0:2])
	proto := binary.LittleEndian.Uint16(data[2:4])
	return cat == CategoryUserConn && proto == ProtoUserLoginSyn
}

// 是否为登录失败应答包 (从后端返回的NACK)
func IsLoginNack(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	cat := binary.LittleEndian.Uint16(data[0:2])
	proto := binary.LittleEndian.Uint16(data[2:4])
	return cat == CategoryUserConn && proto == ProtoUserLoginNack
}

// 是否为登录成功应答包
func IsLoginAck(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	cat := binary.LittleEndian.Uint16(data[0:2])
	proto := binary.LittleEndian.Uint16(data[2:4])
	return cat == CategoryUserConn && proto == ProtoUserLoginAck
}

// 是否为心跳包 (服务器->客户端)
func IsHeartbeat(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	cat := binary.LittleEndian.Uint16(data[0:2])
	proto := binary.LittleEndian.Uint16(data[2:4])
	return cat == CategoryUserConn && proto == ProtoConnectionCheck
}

// 是否为心跳响应 (客户端->服务器)
func IsHeartbeatResponse(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	cat := binary.LittleEndian.Uint16(data[0:2])
	proto := binary.LittleEndian.Uint16(data[2:4])
	return cat == CategoryUserConn && proto == ProtoConnectionCheckOk
}

// 获取消息类别名称
func CategoryName(cat uint16) string {
	switch cat {
	case CategoryMonitor:
		return "MONITOR"
	case CategorySignal:
		return "SIGNAL"
	case CategoryUserConn:
		return "USERCONN"
	case CategoryMapServer:
		return "MAPSERVER"
	default:
		return "UNKNOWN"
	}
}

// 获取协议名称
func ProtocolName(proto uint16) string {
	switch proto {
	case ProtoUserLoginSyn:
		return "LOGIN_SYN"
	case ProtoUserLoginAck:
		return "LOGIN_ACK"
	case ProtoUserLoginNack:
		return "LOGIN_NACK"
	case ProtoNotifyOverlappedLogin:
		return "OVERLAP_NOTIFY"
	case ProtoForceDisconnectOverlap:
		return "OVERLAP_FORCE_DISC"
	case ProtoDisconnectedOnLogin:
		return "LOGIN_DISCONNECT"
	case ProtoDisconnectSyn:
		return "DISCONNECT"
	case ProtoConnectionCheck:
		return "HEARTBEAT"
	case ProtoConnectionCheckOk:
		return "HEARTBEAT_OK"
	case ProtoCharacterListSyn:
		return "CHARLIST"
	case ProtoCharacterSelectSyn:
		return "CHARSELECT"
	case ProtoGameInSyn:
		return "GAMEIN"
	case ProtoGameInAck:
		return "GAMEIN_ACK"
	case ProtoChangeMapSyn:
		return "CHANGEMAP"
	case ProtoDisconnectedByOverlap:
		return "KICKED_OVERLAP"
	default:
		return "UNKNOWN"
	}
}

// 后端健康状态
type BackendHealth int

const (
	HealthNormal   BackendHealth = 0 // 正常
	HealthDegraded BackendHealth = 1 // 降级(响应变慢)
	HealthCritical BackendHealth = 2 // 危险(大量失败)
	HealthDown     BackendHealth = 3 // 宕机
)

// 后端健康状态字符串
func (h BackendHealth) String() string {
	switch h {
	case HealthNormal:
		return "正常"
	case HealthDegraded:
		return "降级"
	case HealthCritical:
		return "危险"
	case HealthDown:
		return "宕机"
	default:
		return "未知"
	}
}

// 协议统计信息 - 用于奔溃预警
type ProtocolStats struct {
	// 登录统计
	TotalLogins     int64 // 总登录数
	TotalLoginAcks  int64 // 登录成功数
	TotalLoginNacks int64 // 登录失败数
	// 连接统计
	TotalHeartbeats         int64 // 心跳发送数
	TotalHeartbeatResponses int64 // 心跳响应数
	// 后端响应统计
	TotalBackendResponses int64 // 后端总响应数
	TotalBackendTimeouts  int64 // 后端异常超时数(不含正常EOF)
	// 奔溃预警
	LoginFailRate     float64 // 登录失败率
	HeartbeatLossRate float64 // 心跳丢失率
	BackendHealth     BackendHealth
	// 时间戳 (用于自动衰减和恢复)
	LastUpdateTime time.Time // 最后更新时间
	mu             sync.Mutex
}

// 更新最后活跃时间
func (s *ProtocolStats) Touch() {
	s.mu.Lock()
	s.LastUpdateTime = time.Now()
	s.mu.Unlock()
}

// 衰减统计数据(闲置超过30秒自动衰减, 60秒完全清零)
func (s *ProtocolStats) DecayIfIdle(maxIdleDuration time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.LastUpdateTime.IsZero() {
		return false
	}

	idle := time.Since(s.LastUpdateTime)
	if idle < maxIdleDuration {
		return false
	}

	// 超过30秒, 开始衰减: 每30秒减半
	decayRounds := int(idle / maxIdleDuration)
	for i := 0; i < decayRounds && i < 5; i++ { // 最多衰减5轮(2.5分钟清零)
		s.TotalLogins /= 2
		s.TotalLoginAcks /= 2
		s.TotalLoginNacks /= 2
		s.TotalBackendTimeouts /= 2
		s.TotalHeartbeats /= 2
		s.TotalHeartbeatResponses /= 2
	}

	// 检查是否已衰减到零
	allZero := s.TotalLogins == 0 && s.TotalLoginNacks == 0 &&
		s.TotalBackendTimeouts == 0 && s.TotalHeartbeats == 0
	if allZero {
		s.BackendHealth = HealthNormal
		return true // 表示已恢复
	}

	s.BackendHealth = CalcCrashRisk(s)
	return s.BackendHealth == HealthNormal
}

// 强制重置统计(健康检查通过后调用)
func (s *ProtocolStats) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.TotalLogins = 0
	s.TotalLoginAcks = 0
	s.TotalLoginNacks = 0
	s.TotalBackendTimeouts = 0
	s.TotalHeartbeats = 0
	s.TotalHeartbeatResponses = 0
	s.BackendHealth = HealthNormal
	s.LastUpdateTime = time.Time{}
}

// 计算奔溃预警等级
func CalcCrashRisk(stats *ProtocolStats) BackendHealth {
	if stats.TotalBackendTimeouts > 10 && stats.TotalBackendResponses == 0 {
		return HealthDown
	}

	// 登录失败率 >= 50% → 危险
	if stats.TotalLogins >= 5 {
		failRate := float64(stats.TotalLoginNacks) / float64(stats.TotalLogins)
		if failRate >= 0.5 {
			return HealthCritical
		} else if failRate >= 0.3 {
			return HealthDegraded
		}
	}

	// 心跳丢失率 >= 30% → 降级
	if stats.TotalHeartbeats >= 3 {
		lossRate := 1.0 - float64(stats.TotalHeartbeatResponses)/float64(stats.TotalHeartbeats)
		if lossRate >= 0.3 {
			return HealthDegraded
		}
	}

	return HealthNormal
}
