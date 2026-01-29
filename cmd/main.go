package main

import (
	"database/sql"
	"log"

	"github.com/go-sql-driver/mysql"
	"github.com/izzy-Ti/_server_setup/cmd/api"
	"github.com/izzy-Ti/_server_setup/config"
	"github.com/izzy-Ti/_server_setup/db"
)

func main() {
	db, err := db.MySqlStorage(mysql.Config{
		User:                 config.ENV.DBuser,
		Passwd:               config.ENV.DBPassword,
		DBName:               config.ENV.DBName,
		Net:                  "tcp",
		AllowNativePasswords: true,
		ParseTime:            true,
	})
	if err != nil {
		log.Fatal(err)
	}
	initStorage(db)
	server := api.NewApiServer(":8080", nil)
	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}
func initStorage(db *sql.DB) {
	err := db.Ping()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("DB connected")
}
