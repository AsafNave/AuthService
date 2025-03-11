#!/bin/bash

# Authentication Service Test Script
# This script simulates the registration and login flow using curl commands

# Configuration
API_URL="http://localhost:8080"
EMAIL="test@example.com"
PASSWORD="Password123!"
FIRST_NAME="Test"
LAST_NAME="User"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Authentication Service Test Script ===${NC}"
echo -e "${BLUE}This script will test the registration and login flow${NC}"
echo ""

# Function to check if the API is running
check_api() {
  echo -e "${BLUE}Checking if the API is running...${NC}"
  if curl -s --head --request GET "$API_URL/health" | grep "200 OK" > /dev/null; then 
    echo -e "${GREEN}API is running!${NC}"
    return 0
  else
    echo -e "${RED}API is not running. Please start the API first.${NC}"
    return 1
  fi
}

# Test registration
test_registration() {
  echo -e "${BLUE}Testing user registration...${NC}"
  
  RESPONSE=$(curl -s -X POST "$API_URL/register" \
    -H "Content-Type: application/json" \
    -d "{
      \"email\": \"$EMAIL\",
      \"password\": \"$PASSWORD\",
      \"first_name\": \"$FIRST_NAME\",
      \"last_name\": \"$LAST_NAME\"
    }")
  
  if echo "$RESPONSE" | grep -q "id"; then
    echo -e "${GREEN}Registration successful!${NC}"
    echo -e "Response: $RESPONSE"
    return 0
  else
    echo -e "${RED}Registration failed.${NC}"
    echo -e "Response: $RESPONSE"
    return 1
  fi
}

# Test login
test_login() {
  echo -e "${BLUE}Testing user login...${NC}"
  
  RESPONSE=$(curl -s -X POST "$API_URL/login" \
    -H "Content-Type: application/json" \
    -d "{
      \"email\": \"$EMAIL\",
      \"password\": \"$PASSWORD\"
    }")
  
  if echo "$RESPONSE" | grep -q "access_token"; then
    echo -e "${GREEN}Login successful!${NC}"
    echo -e "Response: $RESPONSE"
    
    # Extract tokens for further testing
    ACCESS_TOKEN=$(echo "$RESPONSE" | grep -o '"access_token":"[^"]*' | sed 's/"access_token":"//')
    REFRESH_TOKEN=$(echo "$RESPONSE" | grep -o '"refresh_token":"[^"]*' | sed 's/"refresh_token":"//')
    
    echo -e "${GREEN}Access Token: ${NC}$ACCESS_TOKEN"
    echo -e "${GREEN}Refresh Token: ${NC}$REFRESH_TOKEN"
    
    # Save tokens to environment variables for further testing
    export ACCESS_TOKEN
    export REFRESH_TOKEN
    
    return 0
  else
    echo -e "${RED}Login failed.${NC}"
    echo -e "Response: $RESPONSE"
    return 1
  fi
}

# Test accessing a protected resource
test_protected_resource() {
  if [ -z "$ACCESS_TOKEN" ]; then
    echo -e "${RED}No access token available. Please login first.${NC}"
    return 1
  fi
  
  echo -e "${BLUE}Testing access to protected resource...${NC}"
  
  RESPONSE=$(curl -s -X GET "$API_URL/users/me" \
    -H "Authorization: Bearer $ACCESS_TOKEN")
  
  if echo "$RESPONSE" | grep -q "id"; then
    echo -e "${GREEN}Access to protected resource successful!${NC}"
    echo -e "Response: $RESPONSE"
    return 0
  else
    echo -e "${RED}Access to protected resource failed.${NC}"
    echo -e "Response: $RESPONSE"
    return 1
  fi
}

# Test token refresh
test_token_refresh() {
  if [ -z "$REFRESH_TOKEN" ]; then
    echo -e "${RED}No refresh token available. Please login first.${NC}"
    return 1
  fi
  
  echo -e "${BLUE}Testing token refresh...${NC}"
  
  RESPONSE=$(curl -s -X POST "$API_URL/refresh" \
    -H "Content-Type: application/json" \
    -d "{
      \"refresh_token\": \"$REFRESH_TOKEN\"
    }")
  
  if echo "$RESPONSE" | grep -q "access_token"; then
    echo -e "${GREEN}Token refresh successful!${NC}"
    echo -e "Response: $RESPONSE"
    
    # Update access token
    ACCESS_TOKEN=$(echo "$RESPONSE" | grep -o '"access_token":"[^"]*' | sed 's/"access_token":"//')
    echo -e "${GREEN}New Access Token: ${NC}$ACCESS_TOKEN"
    export ACCESS_TOKEN
    
    return 0
  else
    echo -e "${RED}Token refresh failed.${NC}"
    echo -e "Response: $RESPONSE"
    return 1
  fi
}

# Main execution
main() {
  check_api || exit 1
  
  echo ""
  test_registration
  
  echo ""
  test_login
  
  echo ""
  test_protected_resource
  
  echo ""
  test_token_refresh
  
  echo ""
  echo -e "${GREEN}All tests completed!${NC}"
}

# Run the main function
main 