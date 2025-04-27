# C Authentication Service

A simple authentication microservice written in C using the Ulfius web framework, Jansson for JSON handling, libjwt for JWT management, and SQLite for data persistence. It provides basic user registration, login, token refresh, and profile management functionalities. The service is designed to be containerized using Docker and proxied via Nginx.

## Features

*   User Registration (Username, Email, Password)
*   User Login with JWT (Access + Refresh Tokens)
*   Access Token Refresh using Refresh Tokens
*   Password Hashing (SHA-512 crypt)
*   Secure Token Handling (JWT HS256)
*   Profile View & Update (Email)
*   Password Change (Requires current password)
*   Password Reset Request (Placeholder)
*   Logout (Server-side refresh token invalidation)
*   Basic Rate Limiting (IP-based)
*   SQLite Database Persistence
*   Dockerized Deployment with Nginx Proxy

## Technology Stack

*   **Language:** C (C11 standard recommended)
*   **Web Framework:** [Ulfius](https://github.com/babelouest/ulfius)
*   **JSON Library:** [Jansson](https://github.com/akheron/jansson)
*   **JWT Library:** [libjwt](https://github.com/benmcollins/libjwt)
*   **Database:** SQLite 3
*   **Build Tool:** GCC / Make (optional)
*   **Containerization:** Docker, Docker Compose
*   **Proxy:** Nginx

## Setup and Installation

### Prerequisites

**For Native Build (Without Docker):**

*   GCC compiler (supporting C11)
*   Make (optional, for using a Makefile)
*   Development libraries:
    *   `libulfius-dev`
    *   `libjansson-dev`
    *   `libjwt-dev`
    *   `libsqlite3-dev`
    *   `libgnutls28-dev` (or equivalent for TLS support in Ulfius)
    *   `liborcania-dev` (Ulfius dependency)
    *   `libyder-dev` (Ulfius dependency)
    *   `libcrypt-dev` (if not part of libc)
*   `pkg-config` (usually helps with finding libraries)

**For Docker Build:**

*   Docker Engine
*   Docker Compose

### Environment Variables

The service requires a JWT secret for signing tokens. Create a `.env` file in the project root directory (`d:\Python\Kafka_Implementation\demo_app\C_language_auth\.env`):

```env
# filepath: d:\Python\Kafka_Implementation\demo_app\C_language_auth\.env
JWT_SECRET=your_very_strong_and_secret_key_here
```

*   **Replace `your_very_strong_and_secret_key_here` with a strong, unique secret.**
*   **Do NOT commit this `.env` file to version control.** Add it to your `.gitignore`.
*   Other environment variables (`AUTH_PORT`, `AUTH_DB_PATH`, etc.) are set in the `Dockerfile` and `docker-compose.yml` but can be overridden if needed.

### Native Build (Example)

1.  **Install Prerequisites:** Use your system's package manager (e.g., `apt` on Debian/Ubuntu):
    ```bash
    sudo apt-get update
    sudo apt-get install build-essential pkg-config libulfius-dev libjansson-dev libjwt-dev libsqlite3-dev libgnutls28-dev liborcania-dev libyder-dev libcrypt-dev
    ```
2.  **Compile:** Navigate to the project directory and compile the source code. Link all necessary libraries.
    ```bash
    gcc -std=c11 -o auth-service auth_service.c \
        $(pkg-config --cflags --libs ulfius) \
        -ljansson -ljwt -lsqlite3 -lgnutls -lcrypt -pthread
    ```
    *(Note: `pkg-config` might simplify finding flags for Ulfius and its dependencies. Adjust flags if needed.)*
3.  **Set Environment Variable:**
    ```bash
    export JWT_SECRET="your_very_strong_and_secret_key_here"
    # Optionally set others like AUTH_PORT, AUTH_DB_PATH
    ```
4.  **Run:**
    ```bash
    ./auth-service
    ```

### Docker Build (Recommended)

1.  **Ensure Docker and Docker Compose are installed.**
2.  **Create the `.env` file** as described above.
3.  **Navigate to the project directory** (`d:\Python\Kafka_Implementation\demo_app\C_language_auth`).
4.  **Build and Run:**
    ```bash
    docker-compose up --build -d
    ```
    *   `--build`: Forces a rebuild of the service image.
    *   `-d`: Runs the containers in detached mode (in the background).
5.  **Access:** The service will be available through the Nginx proxy at `http://localhost` (or the configured port, default is 80).
6.  **View Logs:**
    ```bash
    docker-compose logs -f auth-service
    docker-compose logs -f nginx
    ```
7.  **Stop:**
    ```bash
    docker-compose down
    ```

## API Endpoints

The base URL when running via Docker Compose and Nginx is `http://localhost`.

---

**1. Health Check**

*   **Method:** `GET`
*   **Path:** `/health`
*   **Description:** Checks if the service is running.
*   **Request Body:** None
*   **Success Response (200 OK):**
    ```json
    {
      "status": "ok"
    }
    ```

---

**2. Register User**

*   **Method:** `POST`
*   **Path:** `/register`
*   **Description:** Creates a new user account.
*   **Request Body:**
    ```json
    {
      "username": "newuser",
      "email": "new@example.com",
      "password": "strongpassword123"
    }
    ```
*   **Success Response (201 Created):**
    ```json
    {
      "message": "User registered"
    }
    ```
*   **Error Responses:**
    *   `400 Bad Request`: Invalid JSON, missing fields, invalid email format, weak password, username/email already exists.
    ```json
    { "error": "Invalid JSON" }
    { "error": "Invalid or missing fields (password min 8 chars)" }
    { "error": "Invalid email format" }
    { "error": "Username or email already exists" }
    ```
    *   `500 Internal Server Error`: Database error, hashing error.
    ```json
    { "error": "Internal server error" }
    ```

---

**3. Login User**

*   **Method:** `POST`
*   **Path:** `/login`
*   **Description:** Authenticates a user and returns JWT tokens.
*   **Request Body:**
    ```json
    {
      "username": "newuser",
      "password": "strongpassword123"
    }
    ```
*   **Success Response (200 OK):**
    ```json
    {
      "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    }
    ```
*   **Error Responses:**
    *   `400 Bad Request`: Invalid JSON, missing credentials.
    ```json
    { "error": "Invalid JSON" }
    { "error": "Missing credentials" }
    ```
    *   `401 Unauthorized`: Invalid username or password.
    ```json
    { "error": "Invalid credentials" }
    ```
    *   `429 Too Many Requests`: Rate limit exceeded.
    ```json
    { "error": "Too many requests" }
    ```
    *   `500 Internal Server Error`: Database error, token generation error.
    ```json
    { "error": "Internal server error" }
    ```

---

**4. Refresh Access Token**

*   **Method:** `POST`
*   **Path:** `/refresh`
*   **Description:** Issues a new access token using a valid refresh token.
*   **Request Body:**
    ```json
    {
      "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    }
    ```
*   **Success Response (200 OK):**
    ```json
    {
      "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    }
    ```
*   **Error Responses:**
    *   `400 Bad Request`: Invalid JSON, missing refresh token.
    ```json
    { "error": "Invalid JSON" }
    { "error": "Missing refresh_token" }
    ```
    *   `401 Unauthorized`: Invalid or expired refresh token.
    ```json
    { "error": "Invalid or expired refresh token" }
    ```
    *   `500 Internal Server Error`: Token generation error.
    ```json
    { "error": "Internal server error generating access token" }
    ```

---

**5. Logout User**

*   **Method:** `POST`
*   **Path:** `/logout`
*   **Description:** Logs out the user (invalidates refresh tokens on the server). Requires a valid access token.
*   **Headers:** `Authorization: Bearer <your_access_token>`
*   **Request Body:** None (or optionally the refresh token if specific invalidation is implemented)
*   **Success Response (200 OK):**
    ```json
    {
      "message": "Logged out successfully"
    }
    ```
*   **Error Responses:**
    *   `401 Unauthorized`: Invalid or expired access token.
    ```json
    { "error": "Invalid or expired token" }
    ```

---

**6. View User Profile**

*   **Method:** `GET`
*   **Path:** `/profile`
*   **Description:** Retrieves the profile information of the authenticated user.
*   **Headers:** `Authorization: Bearer <your_access_token>`
*   **Request Body:** None
*   **Success Response (200 OK):**
    ```json
    {
      "username": "newuser",
      "email": "new@example.com",
      "created_at": 1678886400
    }
    ```
*   **Error Responses:**
    *   `401 Unauthorized`: Invalid or expired access token.
    ```json
    { "error": "Invalid or expired token" }
    ```
    *   `404 Not Found`: Profile not found (shouldn't happen if token is valid).
    ```json
    { "error": "Profile not found" }
    ```
    *   `500 Internal Server Error`: Database error.
    ```json
    { "error": "Internal server error" }
    ```

---

**7. Update User Profile**

*   **Method:** `PUT`
*   **Path:** `/profile`
*   **Description:** Updates the profile information (currently only email) of the authenticated user.
*   **Headers:** `Authorization: Bearer <your_access_token>`
*   **Request Body:** (Include fields to update)
    ```json
    {
      "email": "updated@example.com"
    }
    ```
*   **Success Response (200 OK):** (Returns the updated profile)
    ```json
    {
      "username": "newuser",
      "email": "updated@example.com",
      "created_at": 1678886400
    }
    ```
*   **Error Responses:**
    *   `400 Bad Request`: Invalid JSON, invalid email format, email already in use.
    ```json
    { "error": "Invalid JSON" }
    { "error": "Invalid email format" }
    { "error": "Email already in use by another account" }
    ```
    *   `401 Unauthorized`: Invalid or expired access token.
    ```json
    { "error": "Invalid or expired token" }
    ```
    *   `500 Internal Server Error`: Database error.
    ```json
    { "error": "Internal server error during profile update" }
    ```

---

**8. Change Password**

*   **Method:** `POST`
*   **Path:** `/change-password`
*   **Description:** Allows an authenticated user to change their password.
*   **Headers:** `Authorization: Bearer <your_access_token>`
*   **Request Body:**
    ```json
    {
      "current_password": "strongpassword123",
      "new_password": "evenstrongerpassword456"
    }
    ```
*   **Success Response (200 OK):**
    ```json
    {
      "message": "Password changed successfully"
    }
    ```
*   **Error Responses:**
    *   `400 Bad Request`: Invalid JSON, missing fields, weak new password.
    ```json
    { "error": "Invalid JSON" }
    { "error": "Invalid or missing passwords (new password min 8 chars)" }
    ```
    *   `401 Unauthorized`: Invalid or expired access token, incorrect current password.
    ```json
    { "error": "Invalid or expired token" }
    { "error": "Incorrect current password" }
    ```
    *   `500 Internal Server Error`: Database error, hashing error.
    ```json
    { "error": "Internal server error" }
    ```

---

**9. Forgot Password**

*   **Method:** `POST`
*   **Path:** `/forgot-password`
*   **Description:** Initiates the password reset process (currently a placeholder).
*   **Request Body:**
    ```json
    {
      "email": "user@example.com"
    }
    ```
*   **Success Response (200 OK):** (Generic message to prevent email enumeration)
    ```json
    {
      "message": "If an account with that email exists, a password reset link has been sent."
    }
    ```
*   **Error Responses:**
    *   `400 Bad Request`: Invalid JSON, invalid email format.
    ```json
    { "error": "Invalid JSON" }
    { "error": "Invalid email format" }
    ```
    *   `429 Too Many Requests`: Rate limit exceeded.
    ```json
    { "error": "Too many requests" }
    ```

---

## Usage Examples (`curl`)

*(Replace placeholders like `<your_access_token>` and `<your_refresh_token>`)*

```bash
# Health Check
curl -i http://localhost/health

# Register
curl -i -X POST http://localhost/register \
 -H "Content-Type: application/json" \
 -d '{"username": "testuser", "email": "test@example.com", "password": "password123"}'

# Login
# (Save the tokens from the response)
curl -i -X POST http://localhost/login \
 -H "Content-Type: application/json" \
 -d '{"username": "testuser", "password": "password123"}'

# Refresh Token
curl -i -X POST http://localhost/refresh \
 -H "Content-Type: application/json" \
 -d '{"refresh_token": "<your_refresh_token>"}'

# View Profile
curl -i -X GET http://localhost/profile \
 -H "Authorization: Bearer <your_access_token>"

# Update Profile
curl -i -X PUT http://localhost/profile \
 -H "Authorization: Bearer <your_access_token>" \
 -H "Content-Type: application/json" \
 -d '{"email": "new_test@example.com"}'

# Change Password
curl -i -X POST http://localhost/change-password \
 -H "Authorization: Bearer <your_access_token>" \
 -H "Content-Type: application/json" \
 -d '{"current_password": "password123", "new_password": "newpassword456"}'

# Forgot Password
curl -i -X POST http://localhost/forgot-password \
 -H "Content-Type: application/json" \
 -d '{"email": "test@example.com"}'

# Logout
curl -i -X POST http://localhost/logout \
 -H "Authorization: Bearer <your_access_token>"
```

## Security Considerations

*   **JWT Secret:** Keep your `JWT_SECRET` secure and do not expose it. Use a strong, randomly generated key.
*   **Password Hashing:** Passwords are hashed using `crypt` with SHA-512.
*   **HTTPS:** The provided `nginx.conf` includes commented-out HTTPS configuration. For production, **enable HTTPS** with valid certificates (e.g., using Let's Encrypt). Update the `docker-compose.yml` ports and volumes accordingly.
*   **Rate Limiting:** Basic IP-based rate limiting is implemented, but consider more robust solutions for production.
*   **Input Validation:** Input is validated, but ensure thorough validation against potential attacks (SQL injection, XSS - though less relevant for a pure API).
*   **Dependencies:** Keep dependencies (Ulfius, Jansson, libjwt, etc.) updated.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues.

## License

MIT License

Copyright (c) 2025 DeepStacker

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
