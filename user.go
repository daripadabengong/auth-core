package auth

import "github.com/google/uuid"

type User struct {
	ID        uuid.UUID
	Username  string
	FirstName string
	LastName  string
	Email     string
	Enabled   bool
}
