package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"log"
	"os"
	"time"

	"github.com/piligo/gokap/capture"
	"github.com/piligo/gokap/db"
	"github.com/piligo/gokap/server"
)

var (
	CaptureAddress        string //监听的地址
	CaptureType           string //采集的类型[用于标识，存入数据库时好处理]
	DbType                string
	DbUrl                 string
	StoreFlag             bool
	MiniMsgSize           int
	SysID                 string
	SysSubID              string
	OptPacketExpire       time.Duration //包的过期时间
	OptMessageExpire      time.Duration //消息的超时时间
	MessageDecodeCompName string        //消息解码组件名称
	BFP                   string        //过滤采集时间
)

var rootCmd = &cobra.Command{
	Use:   "gokap",
	Short: "Print images information",
	Long:  "Print all images information",
	Run:   rootCmdRun,
}

func rootCmdRun(cmd *cobra.Command, args []string) {
	PrintInputInfo()
	//start server
	StartServer()
}

func StartServer() {
	startStoreServer()
	startCapture()
}

func startStoreServer() {
	if StoreFlag {
		db.InitDbConn(DbType, DbUrl)
		if db.IsReadyDb() == false {
			panic("store db is not ready")
		}
		server.StartStoreServer()
	}
	log.Println("Not Need Store Capture to databases !!!")
}

func startCapture() {
	opt := server.NewCaptureOption(CaptureAddress, BFP, OptPacketExpire, OptMessageExpire)
	if opt == nil {
		return
	}
	l := capture.NewListener(opt)
	defer l.Close()
	if !l.IsReady() {
		log.Fatalln("not interfaces is ready")
		return
	}
	server.DealMsg(l.Receiver(), SysID, SysSubID, CaptureType, MessageDecodeCompName, BFP, MiniMsgSize, StoreFlag)
}
func init() {
	rootCmd.AddCommand(initDBCmd)
	rootCmd.Flags().StringVarP(&CaptureAddress, "capaddr", "c", "0.0.0.0:12800", "capture address or intefacename,eg:0.0.0.0:8080 or eth0 ")
	rootCmd.Flags().StringVarP(&CaptureType, "captype", "t", "tcp", "capture message protocl eg:[tcp,dubbo,http,mq]")
	rootCmd.Flags().StringVarP(&DbType, "dbtype", "y", "mysql", "db type: [mysql、mymysql、postgres、tidb、sqlite、mssql、oracle ]")
	rootCmd.Flags().StringVarP(&DbUrl, "dburl", "d", "user:passwd@tcp(127.0.0.1:3306)/capturedb", "mysql db connect url")
	rootCmd.Flags().BoolVarP(&StoreFlag, "storeflag", "o", false, "store flag,whether capture message to mysql databases")
	rootCmd.Flags().IntVarP(&MiniMsgSize, "msgminisize", "m", 10, "the msg mini bytes,discard heart bytes ")
	rootCmd.Flags().StringVarP(&SysSubID, "syssubid", "b", "None", "sub system id ")
	rootCmd.Flags().StringVarP(&SysID, "sysid", "s", "KAP", "system id ")
	rootCmd.Flags().DurationVarP(&OptPacketExpire, "packetexpire", "p", 3*time.Second, "continuous packet interval second")
	rootCmd.Flags().DurationVarP(&OptMessageExpire, "msgexpire", "g", 60*time.Second, "msg response time out ")
	rootCmd.Flags().StringVarP(&MessageDecodeCompName, "decodename", "n", "None", "msg decode  compent name ")
	rootCmd.Flags().StringVarP(&BFP, "bfp", "f", "", "capture bpf fileter")

}
func PrintInputInfo() {
	log.Println("================ gokap start deal====================")
	log.Println("================ input info ========================")
	log.Println("CaptureAddress :", CaptureAddress)
	log.Println("CaptureType :", CaptureType)
	log.Println("DbType :", DbType)
	log.Println("DbUrl :", DbUrl)
	log.Println("StoreFlag :", StoreFlag)
	log.Println("MiniMsgSize :", MiniMsgSize)
	log.Println("SysID :", SysID)
	log.Println("SysSubID :", SysSubID)
	log.Println("OptPacketExpire :", OptPacketExpire)
	log.Println("OptMessageExpire :", OptMessageExpire)
	log.Println("MessageDecodeCompName :", MessageDecodeCompName)
	log.Println("BFP :", BFP)
	log.Println("================ input end ========================")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}
