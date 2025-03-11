package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"auth-service/internal/config"
	"auth-service/internal/handler"
	"auth-service/internal/middleware"
	"auth-service/internal/repository"
	"auth-service/internal/service"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: .env file not found")
	}

	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize database repository
	userRepo, err := repository.NewPostgresRepository(cfg.Database.GetDSN())
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Initialize services
	authService := service.NewAuthService(userRepo, cfg)

	// Initialize handlers
	authHandler := handler.NewAuthHandler(authService)
	userHandler := handler.NewUserHandler(userRepo)

	// Set Gin mode
	if cfg.Server.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Initialize router
	router := gin.Default()

	// Add middleware, the Use is called for every request (this is a part of gin web framework)
	router.Use(middleware.CORSMiddleware(cfg))

	// Initialize routes
	initializeRoutes(router, authHandler, userHandler, cfg)

	// Create server
	srv := &http.Server{
		Addr:    ":" + cfg.Server.Port,
		Handler: router,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Server starting on port %s", cfg.Server.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v\n", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit //wait for signal to be received, as mentioned above, this is a blocking call for SIGINT(ctrl+C) and SIGTERM(docker stop)

	// Graceful shutdown
	log.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	log.Println("Server exiting")
}

func initializeRoutes(router *gin.Engine, authHandler *handler.AuthHandler, userHandler *handler.UserHandler, cfg *config.Config) {
	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
			"time":   time.Now(),
		})
	})

	// API v1 group
	v1 := router.Group("/api/v1")
	{
		// Auth routes
		auth := v1.Group("/auth")
		{
			auth.POST("/register", authHandler.Register)
			auth.POST("/login", authHandler.Login)
			auth.POST("/refresh", authHandler.RefreshToken)
			auth.POST("/logout", authHandler.Logout)
		}

		// Protected routes
		protected := v1.Group("")
		protected.Use(middleware.AuthMiddleware(cfg))
		{
			// User routes
			users := protected.Group("/users")
			{
				users.GET("/me", userHandler.GetCurrentUser)
				users.PUT("/me", userHandler.UpdateCurrentUser)
				users.DELETE("/me", userHandler.DeleteCurrentUser)
			}
		}
	}
}
