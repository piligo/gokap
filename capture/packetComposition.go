package capture

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	//"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

type Int32Slice []uint32

func (s Int32Slice) Len() int { return len(s) }

func (s Int32Slice) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

func (s Int32Slice) Less(i, j int) bool { return s[i] < s[j] }

type PacketComposition struct {
	IsComing    bool //请求还是响应报文 true为请求
	IsFin       bool //是否已经结束
	TimeStamp   time.Time //时间戳接收包的最新时间 开始时间戳
	Seqs        []uint32 //seq数据包列表
	Seq2Packets map[uint32]*Packet  //seq对应的包
	SeqMissing  bool //是否有序列包缺失
	MissSeq     uint32 //缺少的SEQ 包
	ID          string //序列ID 消息ID(由请求的IP+端口+ACK组成的MD5值，注意响应的要一致)
}

func (p *PacketComposition) GenID() {
	data := make([]byte, 16+2+2+4)
	//当有第一个包就可以确认ID了
	if len(p.Seq2Packets) > 0 {
		//源IP地址16+源端口2+目的端口2+ACK值 这个可以确认请求和响应信息
		//IP 16+PORT 2+PORT 2 + ACK 4
		//序列排序获取到最小的Seq
		p.SortSeq()
		seq := p.Seqs[0]
		packet, ok := p.Seq2Packets[seq]
		if !ok {
			return
		}
		//请求信息
		if p.IsComing {
			copy(data[:16], packet.SrcIP)
			binary.BigEndian.PutUint16(data[16:18], packet.GetSrcPort())
			binary.BigEndian.PutUint16(data[18:20], packet.GetDstPort())
			binary.BigEndian.PutUint32(data[20:24], packet.TCP.Ack)

		} else {
			//取最小的SEQ就是 原来REQ的ACK的值
			copy(data[:16], packet.DstIP)
			binary.BigEndian.PutUint16(data[16:18], packet.GetDstPort())
			binary.BigEndian.PutUint16(data[18:20], packet.GetSrcPort())
			binary.BigEndian.PutUint32(data[20:24], seq)
		}

		md := md5.Sum(data)
		//hex.Encode(uuid, sha[:20])
		//p.ID = hex.Dump([]byte(md))
		p.ID = hex.EncodeToString(md[:])
	} else {
		p.ID = "NULL-FFFFFFFF"
	}
	//return p.ID

}

func (p *PacketComposition) SortSeq() {
	sort.Sort(Int32Slice(p.Seqs))
}

func (p *PacketComposition) AddPacket(packet *Packet) {
	//如果没有负载数据,不加入到里面
	if packet.DataLen() == 0 {
		return
	}
	pseq := packet.TCP.Seq
	if _, ok := p.Seq2Packets[packet.TCP.Seq]; !ok {
		p.Seqs = append(p.Seqs, pseq)
	}
	p.Seq2Packets[pseq] = packet
	p.TimeStamp = time.Now()
}

//创建一个新的
func NewPacketComposition(packet *Packet) *PacketComposition {
	p := &PacketComposition{
		IsComing:    packet.IsComing,
		IsFin:       packet.TCP.FIN,
		TimeStamp:   time.Now(),
		Seqs:        make([]uint32, 0),
		Seq2Packets: make(map[uint32]*Packet),
		SeqMissing:  false,
	}
	p.Seqs = append(p.Seqs, packet.TCP.Seq)
	p.Seq2Packets[packet.TCP.Seq] = packet
	p.GenID()
	return p
}

func (p *PacketComposition) name() {

}

func (p *PacketComposition) String() string {

	iocoming := fmt.Sprintf("IsComing:%v ", p.IsComing)
	isFin := fmt.Sprintf(" IsFin:%v ", p.IsFin)
	seqsNum := fmt.Sprintf(" SeqNums:%v ", len(p.Seqs))
	seqs := fmt.Sprintf(" Seqs:%v ", p.Seqs)
	out := fmt.Sprintf(" Data:\n%s", hex.Dump(p.GetData()))
	return strings.Join([]string{
		iocoming,
		isFin,
		seqsNum,
		seqs,
		out,
	}, "\n")
}

func (p *PacketComposition) GetData() []byte {
	p.SortSeq()
	var databuf bytes.Buffer
	for _, s := range p.Seqs {
		packet, _ := p.Seq2Packets[s]
		databuf.Write(packet.Data())
	}
	return databuf.Bytes()
}

func (p *PacketComposition) GetSrcPort() uint16 {
	for _, packet := range p.Seq2Packets {
		return packet.GetSrcPort()
	}
	return 0
}

func (p *PacketComposition) GetDstPort() uint16 {
	for _, packet := range p.Seq2Packets {
		return packet.GetDstPort()
	}
	return 0
}

func (p *PacketComposition) GetSrcIP() string {
	for _, v := range p.Seq2Packets {
		return v.SrcIP.String()
	}
	return "NoneIP"
}

func (p *PacketComposition) GetDstIP() string {
	for _, v := range p.Seq2Packets {
		return v.DstIP.String()
	}
	return "NoneIP"
}

//检查是否有缺失的包
func (p *PacketComposition) CheckSeqMissing() {
	//对于seq进行排序以后，如果seq+datalen 不是下一个seq的值则表示
	p.SeqMissing = false
	//先排序
	p.SortSeq()
	datalen := 0
	for i := 0; i < len(p.Seqs); i++ {
		pkt, ok := p.Seq2Packets[p.Seqs[i]]
		if !ok {
			p.SeqMissing = true
		}
		if i == 0 {
			datalen = pkt.DataLen()
			continue
		}
		if int(p.Seqs[i]-p.Seqs[i-1]) != datalen {
			p.SeqMissing = true
			//log.Println("SeqMissing -> ", p.Seqs[i-1], p.Seqs[i])
			p.MissSeq = p.Seqs[i-1] + uint32(datalen)
			break
		}
		datalen = pkt.DataLen()
	}

}
