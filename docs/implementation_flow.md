# Authentication Service Implementation Flow

This document illustrates the technical implementation flow of the authentication processes in the codebase.

## Code Architecture

```mermaid
classDiagram
    class User {
        +uint ID
        +string Email
        +string Password
        +string FirstName
        +string LastName
        +bool Active
        +time.Time CreatedAt
        +time.Time UpdatedAt
    }
    
    class CreateUserRequest {
        +string Email
        +string Password
        +string FirstName
        +string LastName
    }
    
    class LoginRequest {
        +string Email
        +string Password
    }
    
    class TokenResponse {
        +string AccessToken
        +string RefreshToken
        +int64 ExpiresIn
        +string TokenType
    }
    
    class UserRepository {
        <<interface>>
        +Create(user *User) error
        +FindByID(id uint) (*User, error)
        +FindByEmail(email string) (*User, error)
        +Update(user *User) error
        +Delete(id uint) error
        +Exists(email string) (bool, error)
    }
    
    class AuthService {
        -UserRepository userRepo
        -Config config
        +Register(req *CreateUserRequest) (*User, error)
        +Login(req *LoginRequest) (*TokenResponse, error)
        +RefreshToken(refreshToken string) (*TokenResponse, error)
        -generateAccessToken(user *User) (string, error)
        -generateRefreshToken(user *User) (string, error)
    }
    
    class AuthHandler {
        -AuthService authService
        +Register(c *gin.Context)
        +Login(c *gin.Context)
        +RefreshToken(c *gin.Context)
        +Logout(c *gin.Context)
    }
    
    AuthHandler --> AuthService : uses
    AuthService --> UserRepository : uses
    AuthService ..> User : creates/manages
    AuthService ..> TokenResponse : generates
    AuthHandler ..> CreateUserRequest : receives
    AuthHandler ..> LoginRequest : receives
```

## Registration Implementation Flow

```mermaid
flowchart TD
    A[Client] -->|POST /register| B[AuthHandler.Register]
    B -->|Bind JSON| C{Valid Input?}
    C -->|No| D[Return 400 Bad Request]
    C -->|Yes| E[AuthService.Register]
    E -->|Check if user exists| F{User Exists?}
    F -->|Yes| G[Return ErrUserExists]
    F -->|No| H[Hash Password with bcrypt]
    H -->|Create User object| I[UserRepository.Create]
    I -->|Save to Database| J[Return User]
    
    G -->|Handler catches error| K[Return 409 Conflict]
    J -->|Handler returns user| L[Return 201 Created]
```

## Login Implementation Flow

```mermaid
flowchart TD
    A[Client] -->|POST /login| B[AuthHandler.Login]
    B -->|Bind JSON| C{Valid Input?}
    C -->|No| D[Return 400 Bad Request]
    C -->|Yes| E[AuthService.Login]
    E -->|Find user| F[UserRepository.FindByEmail]
    F -->|Get user| G{User Found?}
    G -->|No| H[Return ErrInvalidCredentials]
    G -->|Yes| I[Compare Password with bcrypt]
    I -->|Check| J{Password Correct?}
    J -->|No| K[Return ErrInvalidCredentials]
    J -->|Yes| L[Generate JWT Tokens]
    L -->|Create response| M[Return TokenResponse]
    
    H -->|Handler catches error| N[Return 401 Unauthorized]
    K -->|Handler catches error| N
    M -->|Handler returns tokens| O[Return 200 OK]
```

## Token Refresh Implementation Flow

```mermaid
flowchart TD
    A[Client] -->|POST /refresh| B[AuthHandler.RefreshToken]
    B -->|Bind JSON| C{Valid Input?}
    C -->|No| D[Return 400 Bad Request]
    C -->|Yes| E[AuthService.RefreshToken]
    E -->|Parse JWT| F{Token Valid?}
    F -->|No| G[Return ErrInvalidToken]
    F -->|Yes| H[Extract User ID]
    H -->|Find user| I[UserRepository.FindByID]
    I -->|Get user| J{User Found?}
    J -->|No| K[Return ErrUserNotFound]
    J -->|Yes| L[Generate New Access Token]
    L -->|Create response| M[Return TokenResponse]
    
    G -->|Handler catches error| N[Return 401 Unauthorized]
    K -->|Handler catches error| O[Return 404 Not Found]
    M -->|Handler returns tokens| P[Return 200 OK]
```

## Authentication Middleware Flow

```mermaid
flowchart TD
    A[Client Request] -->|With Authorization Header| B[AuthMiddleware]
    B -->|Extract Token| C{Token Present?}
    C -->|No| D[Return 401 Unauthorized]
    C -->|Yes| E[Parse JWT Token]
    E -->|Validate| F{Token Valid?}
    F -->|No| G[Return 401 Unauthorized]
    F -->|Yes| H[Extract User ID]
    H -->|Set in Context| I[Forward to Handler]
    I -->|Process Request| J[Return Response]
``` 