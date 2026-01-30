package db

import (
	"context"
	"log"
	"os"

	"github.com/jackc/pgx/v5"
)

func Connect() (*pgx.Conn, error) {
	log.Println("db connected")
	return pgx.Connect(context.Background(), os.Getenv("DATABASE_URL"))
}
