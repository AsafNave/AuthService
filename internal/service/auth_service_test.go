package service

import (
	"auth-service/internal/config"
	"auth-service/internal/domain"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

// MockUserRepository is a mock implementation of domain.UserRepository
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Create(user *domain.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockUserRepository) FindByID(id uint) (*domain.User, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) FindByEmail(email string) (*domain.User, error) {
	args := m.Called(email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) Update(user *domain.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockUserRepository) Delete(id uint) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockUserRepository) Exists(email string) (bool, error) {
	args := m.Called(email)
	return args.Bool(0), args.Error(1)
}

// Helper function to create a test config
func createTestConfig() *config.Config {
	return &config.Config{
		JWT: config.JWTConfig{
			Secret:            "test-secret-key",
			Expiration:        time.Hour,
			RefreshExpiration: time.Hour * 24,
		},
		Security: config.SecurityConfig{
			BCryptCost: 4, // Use a low cost for tests
		},
	}
}

func TestRegister(t *testing.T) {
	// Test cases
	testCases := []struct {
		name          string
		request       *domain.CreateUserRequest
		setupMock     func(*MockUserRepository)
		expectedError error
	}{
		{
			name: "Successful registration",
			request: &domain.CreateUserRequest{
				Email:     "test@example.com",
				Password:  "password123",
				FirstName: "Test",
				LastName:  "User",
			},
			setupMock: func(repo *MockUserRepository) {
				repo.On("Exists", "test@example.com").Return(false, nil)
				repo.On("Create", mock.AnythingOfType("*domain.User")).Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "User already exists",
			request: &domain.CreateUserRequest{
				Email:     "existing@example.com",
				Password:  "password123",
				FirstName: "Existing",
				LastName:  "User",
			},
			setupMock: func(repo *MockUserRepository) {
				repo.On("Exists", "existing@example.com").Return(true, nil)
			},
			expectedError: ErrUserExists,
		},
		{
			name: "Repository error during exists check",
			request: &domain.CreateUserRequest{
				Email:     "error@example.com",
				Password:  "password123",
				FirstName: "Error",
				LastName:  "User",
			},
			setupMock: func(repo *MockUserRepository) {
				repo.On("Exists", "error@example.com").Return(false, errors.New("database error"))
			},
			expectedError: errors.New("database error"),
		},
		{
			name: "Repository error during create",
			request: &domain.CreateUserRequest{
				Email:     "createerror@example.com",
				Password:  "password123",
				FirstName: "Create",
				LastName:  "Error",
			},
			setupMock: func(repo *MockUserRepository) {
				repo.On("Exists", "createerror@example.com").Return(false, nil)
				repo.On("Create", mock.AnythingOfType("*domain.User")).Return(errors.New("create error"))
			},
			expectedError: errors.New("create error"),
		},
	}

	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup
			mockRepo := new(MockUserRepository)
			tc.setupMock(mockRepo)

			service := NewAuthService(mockRepo, createTestConfig())

			// Execute
			user, err := service.Register(tc.request)

			// Verify
			if tc.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tc.expectedError.Error(), err.Error())
				assert.Nil(t, user)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, user)
				assert.Equal(t, tc.request.Email, user.Email)
				assert.Equal(t, tc.request.FirstName, user.FirstName)
				assert.Equal(t, tc.request.LastName, user.LastName)
				assert.True(t, user.Active)

				// Verify password was hashed
				err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(tc.request.Password))
				assert.NoError(t, err)
			}

			// Verify all expectations were met
			mockRepo.AssertExpectations(t)
		})
	}
}

func TestLogin(t *testing.T) {
	// Create a hashed password for testing
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), 4)

	// Test cases
	testCases := []struct {
		name          string
		request       *domain.LoginRequest
		setupMock     func(*MockUserRepository)
		expectedError error
	}{
		{
			name: "Successful login",
			request: &domain.LoginRequest{
				Email:    "test@example.com",
				Password: "password123",
			},
			setupMock: func(repo *MockUserRepository) {
				repo.On("FindByEmail", "test@example.com").Return(&domain.User{
					ID:        1,
					Email:     "test@example.com",
					Password:  string(hashedPassword),
					FirstName: "Test",
					LastName:  "User",
					Active:    true,
				}, nil)
			},
			expectedError: nil,
		},
		{
			name: "User not found",
			request: &domain.LoginRequest{
				Email:    "nonexistent@example.com",
				Password: "password123",
			},
			setupMock: func(repo *MockUserRepository) {
				repo.On("FindByEmail", "nonexistent@example.com").Return(nil, errors.New("user not found"))
			},
			expectedError: ErrInvalidCredentials,
		},
		{
			name: "Invalid password",
			request: &domain.LoginRequest{
				Email:    "test@example.com",
				Password: "wrongpassword",
			},
			setupMock: func(repo *MockUserRepository) {
				repo.On("FindByEmail", "test@example.com").Return(&domain.User{
					ID:        1,
					Email:     "test@example.com",
					Password:  string(hashedPassword),
					FirstName: "Test",
					LastName:  "User",
					Active:    true,
				}, nil)
			},
			expectedError: ErrInvalidCredentials,
		},
	}

	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup
			mockRepo := new(MockUserRepository)
			tc.setupMock(mockRepo)

			service := NewAuthService(mockRepo, createTestConfig())

			// Execute
			tokenResponse, err := service.Login(tc.request)

			// Verify
			if tc.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tc.expectedError.Error(), err.Error())
				assert.Nil(t, tokenResponse)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, tokenResponse)

				// Verify token structure
				assert.NotEmpty(t, tokenResponse.AccessToken)
				assert.NotEmpty(t, tokenResponse.RefreshToken)
				assert.Equal(t, int64(time.Hour.Seconds()), tokenResponse.ExpiresIn)
				assert.Equal(t, "Bearer", tokenResponse.TokenType)

				// Verify token validity
				token, err := jwt.Parse(tokenResponse.AccessToken, func(token *jwt.Token) (interface{}, error) {
					return []byte("test-secret-key"), nil
				})
				assert.NoError(t, err)
				assert.True(t, token.Valid)

				// Verify claims
				claims, ok := token.Claims.(jwt.MapClaims)
				assert.True(t, ok)
				assert.Equal(t, "1", claims["sub"])
			}

			// Verify all expectations were met
			mockRepo.AssertExpectations(t)
		})
	}
}

func TestRefreshToken(t *testing.T) {
	// Setup a valid refresh token for testing
	testUser := &domain.User{
		ID:        1,
		Email:     "test@example.com",
		FirstName: "Test",
		LastName:  "User",
		Active:    true,
	}

	config := createTestConfig()
	claims := jwt.RegisteredClaims{
		Subject:   "1",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	validRefreshToken, _ := token.SignedString([]byte(config.JWT.Secret))

	// Create an expired token
	expiredClaims := jwt.RegisteredClaims{
		Subject:   "1",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
	}
	expiredToken := jwt.NewWithClaims(jwt.SigningMethodHS256, expiredClaims)
	expiredRefreshToken, _ := expiredToken.SignedString([]byte(config.JWT.Secret))

	// Test cases
	testCases := []struct {
		name          string
		refreshToken  string
		setupMock     func(*MockUserRepository)
		expectedError error
	}{
		{
			name:         "Successful token refresh",
			refreshToken: validRefreshToken,
			setupMock: func(repo *MockUserRepository) {
				repo.On("FindByID", uint(1)).Return(testUser, nil)
			},
			expectedError: nil,
		},
		{
			name:          "Invalid token",
			refreshToken:  "invalid.token.string",
			setupMock:     func(repo *MockUserRepository) {},
			expectedError: ErrInvalidToken,
		},
		{
			name:          "Expired token",
			refreshToken:  expiredRefreshToken,
			setupMock:     func(repo *MockUserRepository) {},
			expectedError: ErrInvalidToken,
		},
		{
			name:         "User not found",
			refreshToken: validRefreshToken,
			setupMock: func(repo *MockUserRepository) {
				repo.On("FindByID", uint(1)).Return(nil, errors.New("user not found"))
			},
			expectedError: ErrUserNotFound,
		},
	}

	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup
			mockRepo := new(MockUserRepository)
			tc.setupMock(mockRepo)

			service := NewAuthService(mockRepo, config)

			// Execute
			tokenResponse, err := service.RefreshToken(tc.refreshToken)

			// Verify
			if tc.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tc.expectedError.Error(), err.Error())
				assert.Nil(t, tokenResponse)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, tokenResponse)

				// Verify token structure
				assert.NotEmpty(t, tokenResponse.AccessToken)
				assert.Equal(t, tc.refreshToken, tokenResponse.RefreshToken)
				assert.Equal(t, int64(time.Hour.Seconds()), tokenResponse.ExpiresIn)
				assert.Equal(t, "Bearer", tokenResponse.TokenType)

				// Verify token validity
				token, err := jwt.Parse(tokenResponse.AccessToken, func(token *jwt.Token) (interface{}, error) {
					return []byte("test-secret-key"), nil
				})
				assert.NoError(t, err)
				assert.True(t, token.Valid)

				// Verify claims
				claims, ok := token.Claims.(jwt.MapClaims)
				assert.True(t, ok)
				assert.Equal(t, "1", claims["sub"])
			}

			// Verify all expectations were met
			mockRepo.AssertExpectations(t)
		})
	}
}
