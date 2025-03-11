package domain

import (
	"time"
)

// User represents the user entity in the system
type User struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	Email     string    `json:"email" gorm:"uniqueIndex;not null"`
	Password  string    `json:"-" gorm:"not null"` // Password is never sent in JSON responses
	FirstName string    `json:"first_name" gorm:"not null"`
	LastName  string    `json:"last_name" gorm:"not null"`
	Active    bool      `json:"active" gorm:"default:true"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CreateUserRequest represents the request body for user creation
type CreateUserRequest struct {
	Email     string `json:"email" binding:"required,email"`
	Password  string `json:"password" binding:"required,min=8"`
	FirstName string `json:"first_name" binding:"required"`
	LastName  string `json:"last_name" binding:"required"`
}

// UpdateUserRequest represents the request body for user updates
type UpdateUserRequest struct {
	FirstName string `json:"first_name" binding:"required"`
	LastName  string `json:"last_name" binding:"required"`
}

// LoginRequest represents the request body for user login
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// TokenResponse represents the response containing JWT tokens
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

// UserRepository defines the interface for user-related database operations
type UserRepository interface {
	Create(user *User) error
	FindByID(id uint) (*User, error)
	FindByEmail(email string) (*User, error)
	Update(user *User) error
	Delete(id uint) error
	Exists(email string) (bool, error)
}
