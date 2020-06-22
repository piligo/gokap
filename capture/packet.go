package capture

import (
	"github.com/google/gopacket/layers"
	"net"
	"time"
)

type Packet struct {
	IsComing  bool //请求还是响应
	SrcIP     net.IP //源IPd
	DstIP     net.IP //目的IP
	TCP       *layers.TCP //TCP层
	TimeStamp time.Time //时间戳
	Device    string //采集的网卡名称
}

func (p *Packet) GetSrcPort() uint16 {
	return uint16(p.TCP.SrcPort)
}
func (p *Packet) GetDstPort() uint16 {
	return uint16(p.TCP.DstPort)
}
func (p *Packet) GetSeq() uint32 {
	return p.TCP.Seq
}
func (p *Packet) GetAck() uint32 {
	return p.TCP.Ack
}

func (p *Packet) DataLen() int {
	return len(p.TCP.Payload)
}

func (p *Packet) IsFin() bool {
	return p.TCP.FIN
}

func (p *Packet) Data() []byte {
	return p.TCP.Payload
}

func NewPacket(sip, dip net.IP, tcp *layers.TCP, iscome bool, dev string) *Packet {
	p := &Packet{
		SrcIP:     sip,
		DstIP:     dip,
		TCP:       tcp,
		IsComing:  iscome,
		Device:    dev,
		TimeStamp: time.Now(),
	}
	return p
}
