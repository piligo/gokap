package capture

import (
	"encoding/hex"
	"fmt"
	"time"
)

type MessageParse func(*Message) (string, error)

type Message struct {
	MsgType     string //REQ/RESP 请求类型:请求/响应
	MsgID       string //消息ID(由请求的IP+端口+ACK组成的MD5值，注意响应的要一致)
	SrcIP       string //源IP
	DstIP       string //目的IP
	SrcPort     uint16 //原始端口
	DstPort     uint16 //目的端口
	Data        []byte //消息内容
	DataLen     int //消息长度
	IsComplete  bool //消息是否完整
	Protocol    string //协议类型 TCP/HTTP/DUBBO
	CaptureTime time.Time
	//ParseFun   []MessageParse //解析处理函数
}

func DefaultParse(m *Message) (string, error) {
	return string(m.Data), nil
}

func NewMessage(pc *PacketComposition) *Message {
	pc.CheckSeqMissing()
	m := &Message{
		MsgType:     "REQ",
		MsgID:       pc.ID,
		SrcIP:       pc.GetSrcIP(),
		DstIP:       pc.GetDstIP(),
		SrcPort:     pc.GetSrcPort(),
		DstPort:     pc.GetDstPort(),
		Data:        pc.GetData(),
		DataLen:     len(pc.GetData()),
		IsComplete:  !pc.SeqMissing,
		Protocol:    "TCP",
		CaptureTime: pc.TimeStamp,
		//ParseFun:   make([]MessageParse, 0),
	}

	if !pc.IsComing {
		m.MsgType = "RESP"
	}

	return m
}

func (m *Message) SetProtocol(p string) {
	m.Protocol = p
}

func (m *Message) String() string {
	out := fmt.Sprintf("MsgType:%s MsgID:%s \nSrcIP: %s:%d ->DstIP: %s:%d \nDataLen:%d Protocol:%s IsComplete:%v\nDumpHexdData->\n%s",
		m.MsgType,
		m.MsgID,
		m.SrcIP,
		m.SrcPort,
		m.DstIP,
		m.DstPort,
		m.DataLen,
		m.Protocol,
		m.IsComplete,
		hex.Dump(m.Data),
	)
	return out
}
