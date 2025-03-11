package service

import (
	"errors"
	"strconv"
	"time"

	"auth-service/internal/config"
	"auth-service/internal/domain"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound       = errors.New("user not found")
	ErrUserExists         = errors.New("user already exists")
	ErrInvalidToken       = errors.New("invalid token")
)

// AuthService handles authentication-related operations
type AuthService struct {
	userRepo domain.UserRepository
	config   *config.Config
}

// NewAuthService creates a new instance of AuthService
func NewAuthService(userRepo domain.UserRepository, config *config.Config) *AuthService {
	return &AuthService{
		userRepo: userRepo,
		config:   config,
	}
}

// Register creates a new user account
func (s *AuthService) Register(req *domain.CreateUserRequest) (*domain.User, error) {
	// Check if user already exists
	exists, err := s.userRepo.Exists(req.Email)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, ErrUserExists
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), s.config.Security.BCryptCost)
	if err != nil {
		return nil, err
	}

	// Create user
	user := &domain.User{
		Email:     req.Email,
		Password:  string(hashedPassword),
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Active:    true,
	}

	if err := s.userRepo.Create(user); err != nil {
		return nil, err
	}

	return user, nil
}

// Login authenticates a user and returns JWT tokens
func (s *AuthService) Login(req *domain.LoginRequest) (*domain.TokenResponse, error) {
	// Find user by email
	user, err := s.userRepo.FindByEmail(req.Email)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	// Generate tokens
	accessToken, err := s.generateAccessToken(user)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.generateRefreshToken(user)
	if err != nil {
		return nil, err
	}

	return &domain.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.config.JWT.Expiration.Seconds()),
		TokenType:    "Bearer",
	}, nil
}

// RefreshToken generates a new access token using a refresh token
func (s *AuthService) RefreshToken(refreshToken string) (*domain.TokenResponse, error) {
	// Parse and validate refresh token
	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(refreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.config.JWT.Secret), nil
	})

	if err != nil || !token.Valid {
		return nil, ErrInvalidToken
	}

	// Convert subject to uint
	userID, err := strconv.ParseUint(claims.Subject, 10, 32)
	if err != nil {
		return nil, ErrInvalidToken
	}

	// Find user
	user, err := s.userRepo.FindByID(uint(userID))
	if err != nil {
		return nil, ErrUserNotFound
	}

	// Generate new access token
	accessToken, err := s.generateAccessToken(user)
	if err != nil {
		return nil, err
	}

	return &domain.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.config.JWT.Expiration.Seconds()),
		TokenType:    "Bearer",
	}, nil
}

// generateAccessToken creates a new access token
func (s *AuthService) generateAccessToken(user *domain.User) (string, error) {
	claims := jwt.RegisteredClaims{
		Subject:   strconv.FormatUint(uint64(user.ID), 10),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.config.JWT.Expiration)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.config.JWT.Secret))
}

// generateRefreshToken creates a new refresh token
func (s *AuthService) generateRefreshToken(user *domain.User) (string, error) {
	claims := jwt.RegisteredClaims{
		Subject:   strconv.FormatUint(uint64(user.ID), 10),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.config.JWT.RefreshExpiration)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.config.JWT.Secret))
}
