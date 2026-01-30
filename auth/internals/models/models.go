package models

type User struct {
	ID       uint   `gorm:"primaryKey"`
	Name     string `gorm:"not null"`
	Email    string `gorm:"uinqueIndex;not null"`
	Password string `gorm:"not null"`
}
