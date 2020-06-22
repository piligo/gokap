package server

import (
	"encoding/hex"
	"github.com/piligo/gokap/db"
	"github.com/piligo/gokap/entity"
	"log"
)

var (
	captureMsgCh = make(chan *entity.CaptureMsg, 100)
)

func StartStoreServer() error {
	//检查数据库连接是否正常
	if !db.IsReadyDb() {
		log.Fatalln("store db not ready!Please check db connect info !")
	}
	go HandleMsg()
	return nil
}

func GetStoreCh() chan *entity.CaptureMsg {
	return captureMsgCh
}

func HandleMsg() {
	log.Println("HandleMsg: Start store Msg Server ....")
	defer db.CloseDB()
	for {
		m := <-captureMsgCh
		log.Println("RECVIE MSG->", m.MsgType, m.MsgUuid, m.MsgTime, len(m.MsgData))
		//将数据进行编码转换为纯二进制和可以阅读的dumphex格式
		if len(m.MsgData) > 0 {
			m.MsgHex = hex.EncodeToString(m.MsgData)
			m.MsgDumpHex = hex.Dump(m.MsgData)
			m.MsgLen = len(m.MsgData)
			err := db.SaveCaptureMsg(m)
			if err != nil {
				log.Println("WARN storeMsg failed->", m.MsgUuid, err)
			} else {
				log.Println("------------store ok  ", m.MsgUuid, "-----------")
				log.Println("------------store msg dump --------------" + m.MsgUuid + "\n" + m.MsgDumpHex)
				log.Println("------------store ok2  ", m.MsgUuid, "-----------")
			}
		}

	}
}
