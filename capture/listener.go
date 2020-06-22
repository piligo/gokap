package capture

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Listener struct {
	opt  *Option   //参数
	conn net.PacketConn //socket conn

	packetCh        chan *Packet //所有的接口采集的数据包都统一发送到这个地方进行处理
	ack2Composition map[uint32]*PacketComposition
	ack2SuperAck    map[uint32]uint32 //响应是 ack对应的请求ack
	superAck2Ack    map[uint32]uint32 //请求对应的响应的Ack
	messageCh       chan *Message     //这里出口所有组装好的消息数据

	mu          sync.Mutex //一个锁锁定下面handle的添加删除
	pcapHandles []*pcap.Handle 

	quit    chan bool  //退出chan
	readyCh chan bool  //是否已经准备好
}

func NewDefaultListener() *Listener {
	opt := NewDefaultOption()
	return NewListener(opt)
}

func NewListener(opt *Option) *Listener {
	l := &Listener{
		pcapHandles:     make([]*pcap.Handle, 0),
		quit:            make(chan bool),
		readyCh:         make(chan bool),
		messageCh:       make(chan *Message, 1000),
		packetCh:        make(chan *Packet, 10000),
		ack2Composition: make(map[uint32]*PacketComposition),
		ack2SuperAck:    make(map[uint32]uint32),
		superAck2Ack:    make(map[uint32]uint32),
	}
	l.SetOption(opt)

	//如果未配置则退出
	if l.opt.GetPort() == 0 {
		return nil
	}

	//启动数据处理
	//go l.processPacket()
	//启动监听
	go l.listen()
	//启动采集
	go l.capture()
	return l
}

func putReadyStatus(ready chan bool, stat bool) {
	ready <- stat
}

func (l *Listener) ack2Compositions() []uint32 {
	acks := make([]uint32, 0)
	for k, _ := range l.ack2Composition {
		acks = append(acks, k)
	}
	return acks
}

func (l *Listener) captureOne(device pcap.Interface, ready chan bool, bpfloop string) {
	defer putReadyStatus(ready, false)
	actopt := Opt2ActiveOpt(l.opt)
	inactive, err := NewPcapInactive(device, actopt)
	if err != nil {
		log.Fatalln("NewPcapInactive Fatal ->", err)
		return
	}
	//启动抓包，inactive 设置的参数见上面的
	handle, err := inactive.Activate()
	if err != nil {
		log.Fatalln(device.Name+" PCAP Activate error:", err)
		return
	}
	defer handle.Close()
	//将句柄添加到列表里面去
	l.mu.Lock()
	l.pcapHandles = append(l.pcapHandles, handle)
	l.mu.Unlock()

	//处理过滤器
	var bpfDstHost, bpfSrcHost string

	//回环接口127.0.0.1 src和dst一样
	if bpfloop != "" {
		bpfDstHost = bpfloop
		bpfSrcHost = bpfloop
	} else {
		var dstAddr []string
		var srcAddr []string
		for _, addr := range device.Addresses {
			dstAddr = append(dstAddr, "dst host "+addr.IP.String())
			srcAddr = append(srcAddr, "src host "+addr.IP.String())
		}
		bpfDstHost = strings.Join(dstAddr, " or ")
		bpfSrcHost = strings.Join(srcAddr, " or ")
	}
	log.Println("IsLook ", bpfloop, " bpfDstHost->", bpfDstHost, " bpfSrcHost->", bpfSrcHost)

	//处理过滤表达式
	bpf := "tcp dst port " + l.opt.Port + " and (" + bpfDstHost + ")"
	if l.opt.TrackResponse {
		bpf = fmt.Sprintf("(tcp dst port %d and (%s)) or (tcp src port %d and (%s)) ", l.opt.GetPort(), bpfDstHost, l.opt.GetPort(), bpfSrcHost)
	}

	if l.opt.BpfFilter != "" {
		bpf = l.opt.BpfFilter
	}

	log.Println("Set bpf->", bpf)

	err = handle.SetBPFFilter(bpf)
	if err != nil {
		log.Println(device.Name+" SetBPFFilter error:", err)
		return
	}
	//开始进入数据包采集
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.Lazy = true

	//开始正常采集了
	putReadyStatus(ready, true)
	for packet := range packetSource.Packets() {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		tcpLayerIP := packet.Layer(layers.LayerTypeIPv4)
		//转换协议提取数据包
		if tcpLayerIP == nil || tcpLayer == nil {
			continue
		}
		//数据处理
		tcpip, _ := tcpLayerIP.(*layers.IPv4)
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp.FIN || len(tcp.Payload) > 0 {
			l.packetCh <- l.buildPacket(tcpip, tcp, device.Name, packet.Metadata().Timestamp)
		}

	}

}

func parsePort(port string) uint16 {
	p, _ := strconv.Atoi(port)
	if strings.Contains(port, "(") {
		p, _ = strconv.Atoi(port[:strings.Index(port, "(")])
	}
	return uint16(p)
}

func (l *Listener) PrintLayersInfo(tcpip *layers.IPv4, tcp *layers.TCP) {
	IsComing := false
	if parsePort(tcp.DstPort.String()) == l.opt.GetPort() {
		IsComing = true
	}
	infostart := "=======<<<<<<< Resp recvie packet <<<<<<<<======="
	infoEnd := "=======<<<<<<< Resp recvie packet End <<<<========"
	if IsComing {
		infostart = "=======>>>>>>> Req recvie packet >>>>>>>>======="
		infoEnd = "=======>>>>>>> Req recvie packet End >>>========"
	}
	defer log.Println("")
	defer log.Println(infoEnd)
	log.Println("")
	log.Println(infostart)
	//log.Println("DF分片标志->", tcpip.Flags.String())
	//log.Println("srcIP  ->", tcpip.SrcIP, ":", tcp.SrcPort)
	//log.Println("dscIP  ->", tcpip.DstIP, ":", tcp.DstPort)
	log.Println("src", tcpip.SrcIP, ":", tcp.SrcPort, "-> dst", tcpip.DstIP, ":", tcp.DstPort)
	log.Println("Seq:", tcp.Seq, "ack:", tcp.Ack)
	log.Println("datalen->", len(tcp.Payload))
	//log.Println("Seq    ->", tcp.Seq)
	//log.Println("Ack    ->", tcp.Ack)
	log.Println("SYN->", tcp.SYN, " ACK->", tcp.Ack, " RSET->", tcp.RST, " FIN->", tcp.FIN)
}

//建立包数据
func (l *Listener) buildPacket(tcpip *layers.IPv4, tcp *layers.TCP, device string, TimeStamp time.Time) *Packet {

	IsComing := false
	if parsePort(tcp.DstPort.String()) == l.opt.GetPort() {
		IsComing = true
	}
	l.PrintLayersInfo(tcpip, tcp)
	packet := &Packet{
		IsComing:  IsComing,
		SrcIP:     tcpip.SrcIP,
		DstIP:     tcpip.DstIP,
		TCP:       tcp,
		TimeStamp: time.Now(),
		Device:    device,
	}
	return packet
}

func checkok(c []bool) bool {
	for _, v := range c {
		if v == true {
			return true
		}
	}
	return false
}

//进行数据采集
func (l *Listener) capture() {
	log.Println("start capture ->", l.opt.CaptureAddr)
	devices, err := FindPcapDevices(l.opt.CaptureAddr)
	if err != nil {
		log.Fatalln("FindPcapDevices ERR->", err)
		l.Close()
		return
	}
	log.Println("capture opt->", l.opt)
	//var wg sync.WaitGroup
	//wg.Add(len(devices))
	ready := make(chan bool)
	readyOk := make([]bool, 0)

	for _, device := range devices {
		bpfloop := ""
		loopback := IsLoopback(device)
		var allAddr []string
		if loopback {
			for _, dc := range devices {
				for _, addr := range dc.Addresses {
					allAddr = append(allAddr, "(dst host "+addr.IP.String()+" and src host "+addr.IP.String()+")")
				}
			}
			//这里过滤所有的地址地址进行拼接
			bpfloop = strings.Join(allAddr, " or ")
		}
		go l.captureOne(device, ready, bpfloop)
		rok := <-ready
		readyOk = append(readyOk, rok)
	}
	if checkok(readyOk) {
		l.readyCh <- true
	} else {
		close(ready)
		log.Fatalln("None Devices is Ready OK!!!!")
		l.Close()
	}

}

func (l *Listener) buildMessge(pc *PacketComposition) *Message {
	m := NewMessage(pc)
	return m
}

func (l *Listener) cleanPacketComposition(ack uint32) {
	log.Println("cleanPacketComposition->", ack)
	delete(l.ack2Composition, ack)
	//delete(l.ack2SuperAck, ack)
}
func (l *Listener) cleanSuperAck(ack uint32) {
	log.Println("cleanSuperAck->", ack)
	delete(l.ack2SuperAck, ack)
}

func (l *Listener) processTimeOut() {

}

func (l *Listener) listen() {
	gcTicker := time.Tick(l.opt.MessageExpire / 2)
	for {
		select {
		case <-l.quit:
			return
		case packet := <-l.packetCh:

			log.Println("processPacket ->ack", packet.GetAck(), "seq->", packet.GetSeq())
			log.Println("processPacket ack2Composition start : ", l.ack2Compositions(), " total:", len(l.ack2Composition))
			pc, ok := l.ack2Composition[packet.GetAck()]
			//不存在的时候添加数据包
			if !ok {
				pc = NewPacketComposition(packet)
				l.ack2Composition[packet.GetAck()] = pc
			} else {
				pc.AddPacket(packet)
			}

			//查找对应的请求包（或者响应包）
			bpc, ok := l.ack2Composition[packet.GetSeq()]
			if ok {
				bpc.IsFin = true
				l.ack2SuperAck[packet.GetAck()] = packet.GetSeq()
				//这个或许没有用先不添加了
				//l.superAck2Ack[packet.GetSeq()] = packet.GetAck()
				//这里表示请求的报文已经是完善的了
				msg := l.buildMessge(bpc)
				l.messageCh <- msg
				//将请求的清理掉
				log.Println("Recive Resp Clean Req ->", packet.GetSeq())
				l.cleanPacketComposition(packet.GetSeq())
			}

			//收到数据包了!
			//1、如果是请求包已经是FIN 下面这里将处理的就是请求的报文。SuperAck是空的
			//2、如果是响应包，则前面那步则已经处理的请求包，此时SuperAck是删除了!
			if packet.IsFin() {
				pc.IsFin = true
				//处理当前包了
				msg := l.buildMessge(pc)
				l.messageCh <- msg
				log.Println("Packet Fin  Clean ->", packet.GetAck())
				l.cleanPacketComposition(packet.GetAck())
				l.cleanSuperAck(packet.GetAck())
			}
			log.Println("processPacket ack2Composition end: ", l.ack2Compositions(), " total:", len(l.ack2Composition))

		case <-gcTicker:
			//为了避免加锁这个地方来处理超时的包
			//log.Println("------TK-------")
			now := time.Now()
			for ack, pc := range l.ack2Composition {
				if pc.IsFin {
					//查找是否存在父的如果存在父的则父的也标记为完成
					//子包都已经处理了，父包肯定处理完成了
					if pack, ok := l.ack2SuperAck[ack]; ok {
						if ppc, ok := l.ack2Composition[pack]; ok {
							ppc.IsFin = true
						}
					}
					l.messageCh <- l.buildMessge(pc)
					log.Println("FIN Time Out Clean ->", ack)
					l.cleanPacketComposition(ack)
					l.cleanSuperAck(ack)
				}
				//设置已经超时响应数据已经超时
				if now.Sub(pc.TimeStamp) > l.opt.MessageExpire {
					log.Println("TimeOut->", now.Sub(pc.TimeStamp).Seconds(), ack, l.opt.MessageExpire.Seconds())
					pc.IsFin = true
				}
			}

		}

	}
}

func (l *Listener) SetOption(opt *Option) {
	l.opt = opt
}
func (l *Listener) IsReady() bool {
	select {
	case <-l.readyCh:
		return true
	case <-time.After(5 * time.Second):
		return false
	}
}

func (l *Listener) Receiver() chan *Message {
	return l.messageCh
}

func (l *Listener) Close() {
	close(l.quit)
	if l.conn != nil {
		l.conn.Close()
	}
	for _, h := range l.pcapHandles {
		h.Close()
	}
}
