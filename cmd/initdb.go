package cmd

import (
	"github.com/piligo/gokap/db"
	"github.com/spf13/cobra"
	"log"
)

var (
	initdburl  string
	initdbtype string
)

var initDBCmd = &cobra.Command{
	Use:   "db",
	Short: "init mysql db tables ",
	Long:  "init mysql db tables[store capture msg to databases. ] ",
	Run:   initDBCmdRun,
}

func init() {
	initDBCmd.Flags().StringVarP(&initdbtype, "dbtype", "y", "mysql", "mysql db connect url")
	initDBCmd.Flags().StringVarP(&DbUrl, "dburl", "d", "user:passwd@tcp(127.0.0.1:3306)/capturedb", "mysql db connect url")

}

func initDBCmdRun(cmd *cobra.Command, args []string) {
	log.Println(" start init mysql db tables")
	db.InitDbConn(initdbtype, DbUrl)
	if db.InitTables() != nil {
		log.Println("init mysql db tables failed !!!!")
	}
	log.Println("init mysql db tables ok!!!!")
}
