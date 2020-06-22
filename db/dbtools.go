package db

import (
	"errors"
	_ "github.com/go-sql-driver/mysql"
	"github.com/go-xorm/xorm"
	"github.com/piligo/gokap/entity"
	"log"
)

var (
	x *xorm.Engine
)

func InitDbConn(dbtype string, dburl string) {
	if dbtype == "" {
		dbtype = "mysql"
	}
	var err error
	x, err = xorm.NewEngine(dbtype, dburl)
	//x, err = xorm.NewEngine("mysql", "root:root@tcp(127.0.0.1:3306)/xorm?charset=utf8")
	if err != nil {
		log.Fatal("数据库连接失败: ", err)
	}
	log.Println(dbtype, "数据库连接成功!!")
	x.SetMaxOpenConns(100)
	x.SetMaxIdleConns(2)
}

func InitTables() error {
	if err := x.Sync(new(entity.CaptureMsg)); err != nil {
		log.Fatal("数据表创建和同步失败: ", err)
		return err
	}
	log.Println("初始化表成功！！")
	return nil
}

func IsReadyDb() bool {
	if x != nil && x.Ping() == nil {
		return true
	}
	return false
}

func SaveCaptureMsg(msg *entity.CaptureMsg) error {

	if !IsReadyDb() {
		log.Println("SaveCaptureMsg Failed Db not Connect Ok  Msg->", msg.MsgType, msg.MsgUuid)
		return errors.New("db not connect ok !" + msg.MsgUuid)
	}

	install, err := x.Insert(msg)
	if err != nil {
		log.Println("SaveCaptureMsg Failed Err->", err, " Msg->", msg.MsgType, msg.MsgUuid)
		return err
	}
	log.Println("SaveCaptureMsg Ok ->", install, " Msg->", msg.MsgType, msg.MsgUuid)
	return nil
}

func CloseDB() {
	if x != nil {
		x.Close()
	}
}
