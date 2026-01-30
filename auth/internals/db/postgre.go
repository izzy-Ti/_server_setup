package db

import (
	"log"
	"os"

	"github.com/izzy-Ti/_server_setup/auth/internals/auth"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func Connect() (*gorm.DB, error) {

	dsn := os.Getenv("DATABASE_URL")
	log.Println("db connected")
	//return pgx.Connect(context.Background(), dsn)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})

	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	return db, err
}

func Migrate() {
	err := DB.AutoMigrate(&auth.User{})
	if err != nil {
		log.Fatal("Migration failed:", err)
	}
	log.Println("Database migrated")
}
