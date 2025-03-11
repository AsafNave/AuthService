# Authentication Flow Diagram

This document illustrates the flow of registration and login processes in the Authentication Service.

## Registration Flow

```mermaid
sequenceDiagram
    participant Client
    participant API as Auth API
    participant Service as Auth Service
    participant DB as Database
    
    Client->>API: POST /register {username, email, password}
    Note over API: Validate input
    
    alt Invalid Input
        API-->>Client: 400 Bad Request
    else Valid Input
        API->>Service: RegisterUser(username, email, password)
        Service->>Service: Hash Password
        Service->>DB: Check if user exists
        
        alt User Already Exists
            DB-->>Service: User exists
            Service-->>API: Error: User already exists
            API-->>Client: 409 Conflict
        else User Does Not Exist
            Service->>DB: Create User
            DB-->>Service: User Created
            Service-->>API: User Created Successfully
            API-->>Client: 201 Created {user_id, username, email}
        end
    end
```

## Login Flow

```mermaid
sequenceDiagram
    participant Client
    participant API as Auth API
    participant Service as Auth Service
    participant DB as Database
    
    Client->>API: POST /login {email, password}
    Note over API: Validate input
    
    alt Invalid Input
        API-->>Client: 400 Bad Request
    else Valid Input
        API->>Service: LoginUser(email, password)
        Service->>DB: Get User by Email
        
        alt User Not Found
            DB-->>Service: User not found
            Service-->>API: Error: Invalid credentials
            API-->>Client: 401 Unauthorized
        else User Found
            DB-->>Service: User data (with hashed password)
            Service->>Service: Compare passwords
            
            alt Password Incorrect
                Service-->>API: Error: Invalid credentials
                API-->>Client: 401 Unauthorized
            else Password Correct
                Service->>Service: Generate JWT token
                Service-->>API: Login successful with token
                API-->>Client: 200 OK {user_id, token, expiry}
            end
        end
    end
```

## Token Validation Flow

```mermaid
sequenceDiagram
    participant Client
    participant Middleware as Auth Middleware
    participant API as Protected API
    
    Client->>Middleware: Request with Authorization header
    Note over Middleware: Extract token from header
    
    alt No Token or Malformed
        Middleware-->>Client: 401 Unauthorized
    else Token Present
        Middleware->>Middleware: Validate JWT token
        
        alt Token Invalid or Expired
            Middleware-->>Client: 401 Unauthorized
        else Token Valid
            Middleware->>API: Forward request with user context
            API->>API: Process protected resource
            API-->>Client: 200 OK with requested resource
        end
    end
```

## Password Reset Flow

```mermaid
sequenceDiagram
    participant Client
    participant API as Auth API
    participant Service as Auth Service
    participant DB as Database
    participant Email as Email Service
    
    Client->>API: POST /forgot-password {email}
    API->>Service: RequestPasswordReset(email)
    Service->>DB: Get User by Email
    
    alt User Not Found
        DB-->>Service: User not found
        Service-->>API: Success (for security, don't reveal if email exists)
        API-->>Client: 200 OK
    else User Found
        DB-->>Service: User data
        Service->>Service: Generate reset token
        Service->>DB: Store reset token with expiry
        Service->>Email: Send reset email with token
        Email-->>Service: Email sent
        Service-->>API: Success
        API-->>Client: 200 OK
    end
    
    Note over Client: User clicks reset link in email
    
    Client->>API: GET /reset-password?token=xyz
    API->>Service: ValidateResetToken(token)
    Service->>DB: Check token validity and expiry
    
    alt Token Invalid or Expired
        DB-->>Service: Invalid token
        Service-->>API: Error: Invalid token
        API-->>Client: 400 Bad Request
    else Token Valid
        DB-->>Service: Token valid
        Service-->>API: Token valid
        API-->>Client: 200 OK with reset form
        
        Client->>API: POST /reset-password {token, new_password}
        API->>Service: ResetPassword(token, new_password)
        Service->>Service: Hash new password
        Service->>DB: Update user password
        Service->>DB: Invalidate reset token
        DB-->>Service: Password updated
        Service-->>API: Password reset successful
        API-->>Client: 200 OK
    end
``` 