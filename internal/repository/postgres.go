package repository

import (
	"auth-service/internal/domain"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// PostgresRepository implements the UserRepository interface
type PostgresRepository struct {
	db *gorm.DB
}

// NewPostgresRepository creates a new instance of PostgresRepository
func NewPostgresRepository(dsn string) (*PostgresRepository, error) {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	// Auto-migrate the schema
	if err := db.AutoMigrate(&domain.User{}); err != nil {
		return nil, err
	}

	return &PostgresRepository{db: db}, nil
}

// Create creates a new user
func (r *PostgresRepository) Create(user *domain.User) error {
	return r.db.Create(user).Error
}

// FindByID finds a user by ID
func (r *PostgresRepository) FindByID(id uint) (*domain.User, error) {
	var user domain.User
	if err := r.db.First(&user, id).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// FindByEmail finds a user by email
func (r *PostgresRepository) FindByEmail(email string) (*domain.User, error) {
	var user domain.User
	if err := r.db.Where("email = ?", email).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// Update updates a user
func (r *PostgresRepository) Update(user *domain.User) error {
	return r.db.Save(user).Error
}

// Delete deletes a user
func (r *PostgresRepository) Delete(id uint) error {
	return r.db.Delete(&domain.User{}, id).Error
}

// Exists checks if a user with the given email exists
func (r *PostgresRepository) Exists(email string) (bool, error) {
	var count int64
	err := r.db.Model(&domain.User{}).Where("email = ?", email).Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
