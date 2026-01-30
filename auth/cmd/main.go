package main

import (
	"context"
	"log"
	"net/http"

	"github.com/izzy-Ti/_server_setup/tree/main/auth/internals/db"
	"github.com/izzy-Ti/_server_setup/tree/main/auth/internals/server"
	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load()
	conn, err := db.Connect()
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close(context.Background())

	handler := server.New()
	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", handler))

}
