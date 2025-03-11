package handler

import (
	"net/http"

	"auth-service/internal/domain"
	"auth-service/internal/service"

	"github.com/gin-gonic/gin"
)

// AuthHandler handles authentication-related HTTP requests
type AuthHandler struct {
	authService *service.AuthService
}

// NewAuthHandler creates a new instance of AuthHandler
func NewAuthHandler(authService *service.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
	}
}

// Register handles user registration
func (h *AuthHandler) Register(c *gin.Context) {
	var req domain.CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := h.authService.Register(&req)
	if err != nil {
		switch err {
		case service.ErrUserExists:
			c.JSON(http.StatusConflict, gin.H{"error": "User already exists"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		}
		return
	}

	c.JSON(http.StatusCreated, user)
}

// Login handles user login
func (h *AuthHandler) Login(c *gin.Context) {
	var req domain.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tokens, err := h.authService.Login(&req)
	if err != nil {
		switch err {
		case service.ErrInvalidCredentials:
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		}
		return
	}

	c.JSON(http.StatusOK, tokens)
}

// RefreshToken handles token refresh
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tokens, err := h.authService.RefreshToken(req.RefreshToken)
	if err != nil {
		switch err {
		case service.ErrInvalidToken:
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		case service.ErrUserNotFound:
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		}
		return
	}

	c.JSON(http.StatusOK, tokens)
}

// Logout handles user logout
func (h *AuthHandler) Logout(c *gin.Context) {
	// In a stateless JWT implementation, the client is responsible for removing the tokens
	// The server doesn't need to do anything
	c.Status(http.StatusOK)
}
