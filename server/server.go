package server

import (
	"log"
	"net"
	"strconv"
	"time"

	"github.com/piligo/gokap/capture"
	"github.com/piligo/gokap/entity"
)

func DealMsg(msgch chan *capture.Message, sysid string, syssubid string, captureType string, decodeName string, bfp string, minisize int, flag bool) {
	storeflag := flag //*g_isStore
	var storeCh chan *entity.CaptureMsg
	if storeflag {
		storeCh = GetStoreCh()
	}
	for {
		msg := <-msgch
		log.Println("deal msg->", msg.MsgType, msg.MsgID, msg.DataLen)
		if minisize > 0 && msg.DataLen <= minisize {
			log.Println("discard msg->", msg.MsgID)
			continue
		}
		if storeflag {
			smsg := newCaptureMsg(msg, sysid, syssubid, captureType, decodeName, bfp)
			storeCh <- smsg

		}
		log.Println("deal print msg->", msg)
	}

}

func newCaptureMsg(msg *capture.Message, sysid, syssubid, ptype, pfun, bpf string) *entity.CaptureMsg {
	m := &entity.CaptureMsg{
		MsgType:      msg.MsgType,
		MsgUuid:      msg.MsgID,
		MsgTime:      msg.CaptureTime,
		MsgData:      msg.Data,
		MsgLen:       msg.DataLen,
		MsgSrcIp:     msg.SrcIP,
		MsgSrcPort:   strconv.Itoa(int(msg.SrcPort)),
		MsgDstIp:     msg.DstIP,
		MsgDstPort:   strconv.Itoa(int(msg.DstPort)),
		SysId:        sysid,
		SysSubid:     syssubid,
		ProtocolType: ptype,
		ParseFun:     pfun,
		BpfFilter:    bpf,
	}
	return m
}

func NewCaptureOption(captureAddress, bfp string, packteexpire, msgexpire time.Duration) *capture.Option {
	captureAddr, port, err := net.SplitHostPort(captureAddress)
	if err != nil {
		log.Fatalln("newOpt: captureAddr input error,", captureAddress)
		return nil
	}
	fmsgExpire := capture.OptMessageExpire(packteexpire)
	fmsgTimeOut := capture.OptTimeOut(msgexpire)
	fcaptureAddr := capture.OptCaptureAddr(captureAddr)
	fcapturePort := capture.OptPort(port)
	fbpf := capture.OptBpfFilter(bfp)
	opt := capture.NewOption(
		fmsgExpire,
		fmsgTimeOut,
		fcaptureAddr,
		fcapturePort,
		fbpf,
	)
	return opt
}
