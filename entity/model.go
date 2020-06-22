package entity

import (
	"time"
)

type CaptureMsg struct {
	MsgType      string    `xorm:"not null pk VARCHAR(32)"`  //消息类型 请求还是响应
	MsgUuid      string    `xorm:"not null pk VARCHAR(128)"` //消息唯一编码
	MsgTime      time.Time `xorm:"not null  DateTime"`
	MsgCost      int64     `xorm:"not null  BigInt"` //消息耗时
	MsgData      []byte    `xorm:"-"`                //隐藏字段，不进行表映射,消息内容
	MsgLen       int       `xorm:"Int"`              //消息长度
	MsgHex       string    `xorm:"Text"`             //消息二进制
	MsgDumpHex   string    `xorm:"Text"`             //消息可以看的二进制
	MsgSrcIp     string    `xorm:"VARCHAR(64)"`      //消息发起的原始IP地址
	MsgSrcPort   string    `xorm:"VARCHAR(32)"`      //消息的原始端口
	MsgDstIp     string    `xorm:"VARCHAR(64)"`      //消息的目的IP
	MsgDstPort   string    `xorm:"VARCHAR(32)"`      //消息的目的端口
	SysId        string    `xorm:"VARCHAR(64)"`      //采集系统的标识码
	SysSubid     string    `xorm:"VARCHAR(64)"`      //子系统标识码
	ProtocolType string    `xorm:"VARCHAR(64)"`      //通讯协议类型  tcp/udp/http/dubbo 等
	ParseFun     string    `xorm:"VARCHAR(64)"`      //报文解析组件名称默认DefaultParse
	BpfFilter    string    `xorm:"VARCHAR(128)"`     //采集的过滤表达式
	CreateTime   int64     `xorm:"updated"`
}
