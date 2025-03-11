package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all configuration for the application
type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	JWT      JWTConfig
	Security SecurityConfig
}

// ServerConfig holds server-related configuration
type ServerConfig struct {
	Port         string
	Environment  string
	AllowedHosts []string
}

// DatabaseConfig holds database-related configuration
type DatabaseConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
	SSLMode  string
}

// JWTConfig holds JWT-related configuration
type JWTConfig struct {
	Secret            string
	Expiration        time.Duration
	RefreshExpiration time.Duration
}

// SecurityConfig holds security-related configuration
type SecurityConfig struct {
	BCryptCost        int
	MinPasswordLength int
	MaxLoginAttempts  int
	LoginTimeout      time.Duration
}

// LoadConfig loads configuration from environment variables
func LoadConfig() (*Config, error) {
	config := &Config{
		Server: ServerConfig{
			Port:         getEnvOrDefault("PORT", "8080"),
			Environment:  getEnvOrDefault("ENV", "development"),
			AllowedHosts: getEnvSliceOrDefault("ALLOWED_ORIGINS", []string{"http://localhost:3000"}),
		},
		Database: DatabaseConfig{
			Host:     getEnvOrDefault("DB_HOST", "localhost"),
			Port:     getEnvOrDefault("DB_PORT", "5432"),
			User:     getEnvOrDefault("DB_USER", "postgres"),
			Password: getEnvOrDefault("DB_PASSWORD", "postgres"),
			DBName:   getEnvOrDefault("DB_NAME", "auth_service"),
			SSLMode:  getEnvOrDefault("DB_SSL_MODE", "disable"),
		},
		JWT: JWTConfig{
			Secret:            getEnvOrDefault("JWT_SECRET", "your-secret-key-here"),
			Expiration:        getEnvDurationOrDefault("JWT_EXPIRATION", 24*time.Hour),
			RefreshExpiration: getEnvDurationOrDefault("JWT_REFRESH_EXPIRATION", 168*time.Hour),
		},
		Security: SecurityConfig{
			BCryptCost:        getEnvIntOrDefault("BCRYPT_COST", 10),
			MinPasswordLength: getEnvIntOrDefault("MIN_PASSWORD_LENGTH", 8),
			MaxLoginAttempts:  getEnvIntOrDefault("MAX_LOGIN_ATTEMPTS", 5),
			LoginTimeout:      getEnvDurationOrDefault("LOGIN_TIMEOUT", 15*time.Minute),
		},
	}

	return config, nil
}

// GetDSN returns the database connection string
func (c *DatabaseConfig) GetDSN() string {
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.DBName, c.SSLMode)
}

// Helper functions for environment variables
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvSliceOrDefault(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		return strings.Split(value, ",")
	}
	return defaultValue
}

func getEnvIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvDurationOrDefault(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}
