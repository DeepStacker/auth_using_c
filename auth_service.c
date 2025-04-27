#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ulfius.h>
#include <sqlite3.h>
#include <jansson.h>
#include <jwt.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <crypt.h>
#include <regex.h> // Needed for email validation

// Forward declarations / Prototypes
char *generate_jwt(const char *username, int is_refresh);
int callback_forgot_password(const struct _u_request *req, struct _u_response *res, void *user_data);
int callback_change_password(const struct _u_request *req, struct _u_response *res, void *user_data);

// Configuration structure
typedef struct
{
    int port;
    char db_path[256];
    char jwt_secret[256];
    int access_token_expiry;
    int refresh_token_expiry;
} config_t;

config_t config = {
    .port = 8080,
    .db_path = "auth.db",
    .jwt_secret = "",
    .access_token_expiry = 900,     // 15 minutes
    .refresh_token_expiry = 604800, // 7 days
};

sqlite3 *db;
volatile sig_atomic_t keep_running = 1;
pthread_t cleanup_thread;

// Simple logging
#define log_message(level, ...)      \
    fprintf(stderr, "[%s] ", level); \
    fprintf(stderr, __VA_ARGS__);    \
    fprintf(stderr, "\n")

// Load configuration from environment variables
void load_config()
{
    char *env_var;
    if ((env_var = getenv("AUTH_PORT")))
        config.port = atoi(env_var);
    if ((env_var = getenv("AUTH_DB_PATH")))
        strncpy(config.db_path, env_var, sizeof(config.db_path) - 1);
    if ((env_var = getenv("AUTH_JWT_SECRET")))
        strncpy(config.jwt_secret, env_var, sizeof(config.jwt_secret) - 1);
}

// Validate configuration
int validate_config()
{
    if (strlen(config.jwt_secret) == 0)
    {
        log_message("ERROR", "JWT secret is not set");
        return 0;
    }
    if (strlen(config.db_path) == 0)
    {
        log_message("ERROR", "Database path is not set");
        return 0;
    }
    if (config.port <= 0 || config.port > 65535)
    {
        log_message("ERROR", "Invalid port number: %d", config.port);
        return 0;
    }
    return 1;
}

// Initialize SQLite database
int init_db()
{
    if (sqlite3_config(SQLITE_CONFIG_SERIALIZED) != SQLITE_OK)
    {
        log_message("ERROR", "Failed to configure SQLite serialized mode");
        return 0;
    }
    if (sqlite3_open(config.db_path, &db) != SQLITE_OK)
    {
        log_message("ERROR", "Failed to open database: %s", sqlite3_errmsg(db));
        return 0;
    }
    sqlite3_exec(db, "PRAGMA foreign_keys = ON;", NULL, NULL, NULL);
    char *sql = "CREATE TABLE IF NOT EXISTS users ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "username TEXT UNIQUE NOT NULL,"
                "password TEXT NOT NULL,"
                "email TEXT UNIQUE NOT NULL,"
                "created_at INTEGER NOT NULL);"
                "CREATE TABLE IF NOT EXISTS refresh_tokens ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "username TEXT NOT NULL,"
                "refresh_token TEXT NOT NULL UNIQUE,"
                "expiry INTEGER NOT NULL,"
                "FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE);";
    if (sqlite3_exec(db, sql, NULL, NULL, NULL) != SQLITE_OK)
    {
        log_message("ERROR", "Failed to create tables: %s", sqlite3_errmsg(db));
        return 0;
    }
    log_message("INFO", "Database initialized");
    return 1;
}

// Cleanup expired refresh tokens
void cleanup_expired_tokens()
{
    time_t now = time(NULL);
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "DELETE FROM refresh_tokens WHERE expiry < ?;", -1, &stmt, NULL);
    sqlite3_bind_int64(stmt, 1, now);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    log_message("DEBUG", "Cleaned up expired refresh tokens");
}

void *cleanup_thread_function(void *arg)
{
    while (keep_running)
    {
        cleanup_expired_tokens();
        sleep(3600); // Run hourly
    }
    return NULL;
}

// Function to hash password using crypt_r
char *hash_password(const char *password)
{
    char salt[32];
    strcpy(salt, "$6$"); // SHA-512
    const char *saltchars = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    FILE *urandom = fopen("/dev/urandom", "r");
    if (!urandom)
    {
        perror("fopen /dev/urandom");
        return NULL;
    }
    for (int i = 0; i < 16; i++)
    {
        unsigned char byte;
        // Corrected fread call
        if (fread(&byte, 1, 1, urandom) != 1)
        {
            fprintf(stderr, "Error reading from /dev/urandom\n");
            fclose(urandom);
            return NULL; // Or handle error appropriately
        }
        salt[i] = saltchars[byte % strlen(saltchars)];
    }
    fclose(urandom);
    salt[16] = '\0';
    char *hashed = crypt(password, salt);
    if (!hashed)
    {
        log_message("ERROR", "crypt failed");
        return NULL;
    }
    return strdup(hashed);
}

// Basic email validation using regex
int is_valid_email(const char *email)
{
    if (!email || strlen(email) > 255)
        return 0; // Basic length check
    regex_t regex;
    int reti;
    // Simple regex: basic structure check, not fully RFC compliant
    reti = regcomp(&regex, "^[^@ ]+@[^@ ]+\\.[^@ ]+$", REG_EXTENDED | REG_NOSUB);
    if (reti)
    {
        log_message("ERROR", "Could not compile regex for email validation");
        return 0; // Treat regex compilation error as invalid
    }
    reti = regexec(&regex, email, 0, NULL, 0);
    regfree(&regex);
    return reti == 0; // 0 means match found (valid)
}

// Function to verify password using crypt_r
int verify_password(const char *password, const char *hash)
{
    if (!password || !hash)
        return 0;
    char *result = crypt(password, hash);
    if (!result)
    {
        log_message("ERROR", "crypt failed during verification");
        return 0;
    }
    return strcmp(result, hash) == 0;
}

// Function to generate only access token (wrapper for generate_jwt)
char *generate_access_token(int user_id)
{
    // Need to get username from user_id first
    sqlite3_stmt *stmt;
    char username[256] = {0}; // Assuming max username length
    int found = 0;

    if (sqlite3_prepare_v2(db, "SELECT username FROM users WHERE id = ?;", -1, &stmt, NULL) == SQLITE_OK)
    {
        sqlite3_bind_int(stmt, 1, user_id);
        if (sqlite3_step(stmt) == SQLITE_ROW)
        {
            strncpy(username, (const char *)sqlite3_column_text(stmt, 0), sizeof(username) - 1);
            found = 1;
        }
        sqlite3_finalize(stmt);
    }
    else
    {
        log_message("ERROR", "Failed to prepare statement to get username for token generation: %s", sqlite3_errmsg(db));
    }

    if (found && strlen(username) > 0)
    {
        return generate_jwt(username, 0); // 0 indicates access token
    }
    else
    {
        log_message("ERROR", "Could not find username for user_id %d to generate access token", user_id);
        return NULL;
    }
}

// Generate JWT
char *generate_jwt(const char *username, int is_refresh)
{
    jwt_t *jwt;
    char *token = NULL;
    time_t now = time(NULL);
    int exp = now + (is_refresh ? config.refresh_token_expiry : config.access_token_expiry);
    if (jwt_new(&jwt) == 0)
    {
        jwt_add_grant(jwt, "username", username);
        jwt_add_grant_int(jwt, "exp", exp);
        jwt_add_grant(jwt, "type", is_refresh ? "refresh" : "access");
        if (jwt_set_alg(jwt, JWT_ALG_HS256, (const unsigned char *)config.jwt_secret, strlen(config.jwt_secret)) == 0)
        {
            token = jwt_encode_str(jwt);
        }
        jwt_free(jwt);
    }
    return token;
}

// Save refresh token
void save_refresh_token(const char *username, const char *refresh_token)
{
    time_t now = time(NULL);
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "INSERT INTO refresh_tokens (username, refresh_token, expiry) VALUES (?, ?, ?);", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, refresh_token, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, now + config.refresh_token_expiry);
    if (sqlite3_step(stmt) != SQLITE_DONE)
    {
        log_message("ERROR", "Failed to save refresh token: %s", sqlite3_errmsg(db));
    }
    sqlite3_finalize(stmt);
}

// Validate refresh token
int validate_refresh_token(const char *refresh_token, char *username_out, size_t username_out_len)
{
    jwt_t *jwt;
    if (jwt_decode(&jwt, refresh_token, (const unsigned char *)config.jwt_secret, strlen(config.jwt_secret)) != 0)
    {
        return 0;
    }
    const char *token_type = jwt_get_grant(jwt, "type");
    if (!token_type || strcmp(token_type, "refresh") != 0)
    {
        jwt_free(jwt);
        return 0;
    }
    const char *username = jwt_get_grant(jwt, "username");
    if (!username)
    {
        jwt_free(jwt);
        return 0;
    }
    time_t exp = jwt_get_grant_int(jwt, "exp");
    time_t now = time(NULL);
    if (exp <= now)
    {
        jwt_free(jwt);
        return 0;
    }
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "SELECT 1 FROM refresh_tokens WHERE refresh_token = ? AND username = ? AND expiry > ?;", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, refresh_token, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, username, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, now);
    int valid = (sqlite3_step(stmt) == SQLITE_ROW);
    if (valid)
    {
        strncpy(username_out, username, username_out_len - 1);
        username_out[username_out_len - 1] = '\0';
    }
    sqlite3_finalize(stmt);
    jwt_free(jwt);
    return valid;
}

// Authenticate request
int authenticate_request(const struct _u_request *request, char *username_out, size_t out_len)
{
    const char *auth_header = u_map_get(request->map_header, "Authorization");
    if (!auth_header || strncmp(auth_header, "Bearer ", 7) != 0)
    {
        return -1;
    }
    const char *token = auth_header + 7;
    jwt_t *jwt;
    if (jwt_decode(&jwt, token, (const unsigned char *)config.jwt_secret, strlen(config.jwt_secret)) != 0)
    {
        return -1;
    }
    const char *username = jwt_get_grant(jwt, "username");
    const char *token_type = jwt_get_grant(jwt, "type");
    time_t exp = jwt_get_grant_int(jwt, "exp");
    time_t now = time(NULL);
    int valid = (username && (!token_type || strcmp(token_type, "access") == 0) && exp > now);
    if (valid)
    {
        strncpy(username_out, username, out_len - 1);
        username_out[out_len - 1] = '\0';
    }
    jwt_free(jwt);
    return valid ? 0 : -1;
}

// Basic rate limiting
#define RATE_LIMIT_WINDOW 60 // 1 minute
#define RATE_LIMIT_MAX 10    // 10 requests per minute
typedef struct
{
    char ip[46]; // Supports IPv6
    int count;
    time_t last_reset;
} rate_limit_t;
rate_limit_t rate_limits[100];
int rate_limit_count = 0;
pthread_mutex_t rate_limit_mutex = PTHREAD_MUTEX_INITIALIZER;

int check_rate_limit(const char *ip)
{
    pthread_mutex_lock(&rate_limit_mutex);
    time_t now = time(NULL);
    for (int i = 0; i < rate_limit_count; i++)
    {
        if (strcmp(rate_limits[i].ip, ip) == 0)
        {
            if (now - rate_limits[i].last_reset >= RATE_LIMIT_WINDOW)
            {
                rate_limits[i].count = 1;
                rate_limits[i].last_reset = now;
                pthread_mutex_unlock(&rate_limit_mutex);
                return 1;
            }
            if (rate_limits[i].count >= RATE_LIMIT_MAX)
            {
                pthread_mutex_unlock(&rate_limit_mutex);
                return 0;
            }
            rate_limits[i].count++;
            pthread_mutex_unlock(&rate_limit_mutex);
            return 1;
        }
    }
    if (rate_limit_count < 100)
    {
        strcpy(rate_limits[rate_limit_count].ip, ip);
        rate_limits[rate_limit_count].count = 1;
        rate_limits[rate_limit_count].last_reset = now;
        rate_limit_count++;
    }
    pthread_mutex_unlock(&rate_limit_mutex);
    return 1;
}

// Helper function to send JSON error response
static void send_json_error(struct _u_response *res, int status, const char *error_message)
{
    json_t *err_json = json_pack("{s:s}", "error", error_message);
    ulfius_set_json_body_response(res, status, err_json);
    json_decref(err_json);
}

// Helper function to send JSON success message response
static void send_json_message(struct _u_response *res, int status, const char *message)
{
    json_t *msg_json = json_pack("{s:s}", "message", message);
    ulfius_set_json_body_response(res, status, msg_json);
    json_decref(msg_json);
}

// Health check endpoint
int callback_health_check(const struct _u_request *req, struct _u_response *res, void *user_data)
{
    (void)req;       // Unused
    (void)user_data; // Unused
    json_t *resp_json = json_pack("{s:s}", "status", "ok");
    ulfius_set_json_body_response(res, 200, resp_json);
    json_decref(resp_json); // Decrement reference count
    return U_CALLBACK_CONTINUE;
}

/// Fix for the register function - correct parameter binding
int callback_register(const struct _u_request *req, struct _u_response *res, void *user_data)
{
    json_error_t error;
    json_t *j_body = ulfius_get_json_body_request(req, &error);
    if (!j_body)
    {
        y_log_message(Y_LOG_LEVEL_WARNING, "Register: Invalid JSON received");
        send_json_error(res, 400, "Invalid JSON");
        return U_CALLBACK_COMPLETE;
    }

    const char *username = json_string_value(json_object_get(j_body, "username"));
    const char *email = json_string_value(json_object_get(j_body, "email"));
    const char *password = json_string_value(json_object_get(j_body, "password"));

    if (!username || !email || !password || strlen(username) == 0 || strlen(email) == 0 || strlen(password) < 8)
    {
        y_log_message(Y_LOG_LEVEL_WARNING, "Register: Invalid or missing fields");
        send_json_error(res, 400, "Invalid or missing fields (password min 8 chars)");
        json_decref(j_body);
        return U_CALLBACK_COMPLETE;
    }

    if (!is_valid_email(email))
    {
        y_log_message(Y_LOG_LEVEL_WARNING, "Register: Invalid email format for %s", email);
        send_json_error(res, 400, "Invalid email format");
        json_decref(j_body);
        return U_CALLBACK_COMPLETE;
    }

    char *hashed_password = hash_password(password);
    if (!hashed_password)
    {
        y_log_message(Y_LOG_LEVEL_ERROR, "Register: Failed to hash password");
        send_json_error(res, 500, "Internal server error");
        json_decref(j_body);
        return U_CALLBACK_COMPLETE;
    }

    time_t now = time(NULL);
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "INSERT INTO users (username, password, email, created_at) VALUES (?, ?, ?, ?);", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, hashed_password, -1, SQLITE_TRANSIENT); // Fixed: password in position 2
    sqlite3_bind_text(stmt, 3, email, -1, SQLITE_STATIC);              // Fixed: email in position 3
    sqlite3_bind_int64(stmt, 4, now);
    int rc = sqlite3_step(stmt);

    free(hashed_password); // Free the allocated hash

    if (rc == SQLITE_DONE)
    {
        y_log_message(Y_LOG_LEVEL_INFO, "User %s registered successfully", username);
        send_json_message(res, 201, "User registered");
    }
    else if (rc == SQLITE_CONSTRAINT)
    {
        y_log_message(Y_LOG_LEVEL_WARNING, "Register: Username or email already exists for %s", username);
        send_json_error(res, 400, "Username or email already exists");
    }
    else
    {
        y_log_message(Y_LOG_LEVEL_ERROR, "Register: Failed to insert user %s: %s", username, sqlite3_errmsg(db));
        send_json_error(res, 500, "Internal server error");
    }

    sqlite3_finalize(stmt);
    json_decref(j_body);
    return U_CALLBACK_COMPLETE;
}

// Login endpoint
int callback_login(const struct _u_request *req, struct _u_response *res, void *user_data)
{
    // Corrected pointer type mismatch warning
    const char *forwarded_ip = u_map_get(req->map_header, "X-Forwarded-For");
    const char *ip = forwarded_ip ? forwarded_ip : (const char *)req->client_address; // Cast client_address

    if (!check_rate_limit(ip))
    {
        y_log_message(Y_LOG_LEVEL_WARNING, "Login: Rate limit exceeded for IP: %s", ip);
        send_json_error(res, 429, "Too many requests");
        return U_CALLBACK_COMPLETE;
    }

    json_error_t error;
    json_t *j_body = ulfius_get_json_body_request(req, &error);
    if (!j_body)
    {
        y_log_message(Y_LOG_LEVEL_WARNING, "Login: Invalid JSON received from IP: %s", ip);
        send_json_error(res, 400, "Invalid JSON");
        return U_CALLBACK_COMPLETE;
    }

    const char *username = json_string_value(json_object_get(j_body, "username"));
    const char *password = json_string_value(json_object_get(j_body, "password"));

    if (!username || !password)
    {
        y_log_message(Y_LOG_LEVEL_WARNING, "Login: Missing credentials from IP: %s", ip);
        send_json_error(res, 400, "Missing credentials");
        json_decref(j_body);
        return U_CALLBACK_COMPLETE;
    }

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "SELECT password,id FROM users WHERE username = ?;", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);

    if (rc == SQLITE_ROW)
    {
        const char *stored_hash = (const char *)sqlite3_column_text(stmt, 0);
        int user_id = sqlite3_column_int(stmt, 1); // Get user_id

        if (verify_password(password, stored_hash))
        {
            // Use username directly, no need to fetch again
            char *access_token = generate_jwt(username, 0);
            char *refresh_token = generate_jwt(username, 1);
            if (!access_token || !refresh_token)
            {
                y_log_message(Y_LOG_LEVEL_ERROR, "Login: Failed to generate tokens for user %s", username);
                send_json_error(res, 500, "Internal server error");
                // Free tokens if one succeeded but the other failed
                free(access_token);
                free(refresh_token);
            }
            else
            {
                save_refresh_token(username, refresh_token);
                json_t *resp_json = json_pack("{s:s, s:s}", "access_token", access_token, "refresh_token", refresh_token);
                ulfius_set_json_body_response(res, 200, resp_json);
                json_decref(resp_json);
                free(access_token);
                free(refresh_token);
                y_log_message(Y_LOG_LEVEL_INFO, "User %s logged in successfully from IP: %s", username, ip);
            }
        }
        else
        {
            y_log_message(Y_LOG_LEVEL_WARNING, "Login: Invalid credentials for user %s from IP: %s", username, ip);
            send_json_error(res, 401, "Invalid credentials");
        }
    }
    else
    {
        y_log_message(Y_LOG_LEVEL_WARNING, "Login: Invalid credentials (user not found) for %s from IP: %s", username, ip);
        send_json_error(res, 401, "Invalid credentials");
    }

    sqlite3_finalize(stmt);
    json_decref(j_body);
    return U_CALLBACK_COMPLETE;
}

// Refresh token endpoint
int callback_refresh_token(const struct _u_request *req, struct _u_response *res, void *user_data)
{
    json_error_t error;
    json_t *j_body = ulfius_get_json_body_request(req, &error);
    if (!j_body)
    {
        send_json_error(res, 400, "Invalid JSON");
        return U_CALLBACK_COMPLETE;
    }

    const char *refresh_token_str = json_string_value(json_object_get(j_body, "refresh_token"));
    if (!refresh_token_str)
    {
        send_json_error(res, 400, "Missing refresh_token");
        json_decref(j_body);
        return U_CALLBACK_COMPLETE;
    }

    // Corrected function call: validate_refresh_token instead of verify_refresh_token
    // Also, need to get username from validate_refresh_token to generate new access token
    char username_from_token[256]; // Buffer to store username
    if (!validate_refresh_token(refresh_token_str, username_from_token, sizeof(username_from_token)))
    {
        send_json_error(res, 401, "Invalid or expired refresh token");
        json_decref(j_body);
        return U_CALLBACK_COMPLETE;
    }

    // Generate new access token using the validated username
    char *new_access_token = generate_jwt(username_from_token, 0); // Use username from token
    if (!new_access_token)
    {
        send_json_error(res, 500, "Internal server error generating access token");
        json_decref(j_body);
        return U_CALLBACK_COMPLETE;
    }

    json_t *resp_json = json_pack("{s:s}", "access_token", new_access_token);
    ulfius_set_json_body_response(res, 200, resp_json);
    json_decref(resp_json);
    free(new_access_token);
    json_decref(j_body);

    return U_CALLBACK_COMPLETE;
}

// Logout endpoint - Corrected Implementation
int callback_logout(const struct _u_request *req, struct _u_response *res, void *user_data)
{
    char username[256];
    if (authenticate_request(req, username, sizeof(username)) != 0)
    {
        send_json_error(res, 401, "Invalid or expired token");
        return U_CALLBACK_COMPLETE;
    }

    // Optional: Invalidate refresh tokens associated with the user
    // This requires fetching the refresh token from the request body or headers
    // if the client sends it during logout, or invalidating all for the user.
    // For simplicity, we'll just invalidate all for the user here.
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, "DELETE FROM refresh_tokens WHERE username = ?;", -1, &stmt, NULL);
    if (rc == SQLITE_OK)
    {
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE)
        {
            y_log_message(Y_LOG_LEVEL_ERROR, "Logout: Failed to delete refresh tokens for user %s: %s", username, sqlite3_errmsg(db));
            // Don't necessarily fail the logout, just log the error
        }
        sqlite3_finalize(stmt);
    }
    else
    {
        y_log_message(Y_LOG_LEVEL_ERROR, "Logout: Failed to prepare statement to delete refresh tokens for user %s: %s", username, sqlite3_errmsg(db));
    }

    y_log_message(Y_LOG_LEVEL_INFO, "User %s logged out", username);
    send_json_message(res, 200, "Logged out successfully");
    return U_CALLBACK_COMPLETE;
}

// Forgot password endpoint - Definition Added
int callback_forgot_password(const struct _u_request *req, struct _u_response *res, void *user_data)
{
    // Implementation similar to the one previously in auth_service.c
    // (Rate limiting, get email from JSON, validate email,
    // find user, generate reset token, store token, send email - details omitted for brevity)

    // Placeholder implementation:
    json_error_t error;
    json_t *j_body = ulfius_get_json_body_request(req, &error);
    if (!j_body)
    {
        send_json_error(res, 400, "Invalid JSON");
        return U_CALLBACK_COMPLETE;
    }
    const char *email = json_string_value(json_object_get(j_body, "email"));
    if (!email || !is_valid_email(email))
    {
        send_json_error(res, 400, "Invalid email format");
        json_decref(j_body);
        return U_CALLBACK_COMPLETE;
    }

    // TODO: Add logic to generate and send reset link/token
    y_log_message(Y_LOG_LEVEL_INFO, "Password reset requested for email: %s", email);

    // Always return success to prevent email enumeration
    send_json_message(res, 200, "If an account with that email exists, a password reset link has been sent.");
    json_decref(j_body);
    return U_CALLBACK_COMPLETE;
}

// Change password endpoint - Definition Added (using code previously misplaced in logout)
int callback_change_password(const struct _u_request *req, struct _u_response *res, void *user_data)
{
    char username[256];
    if (authenticate_request(req, username, sizeof(username)) != 0)
    {
        send_json_error(res, 401, "Invalid or expired token");
        return U_CALLBACK_COMPLETE;
    }

    json_error_t json_error;
    json_t *json = ulfius_get_json_body_request(req, &json_error); // Use ulfius helper
    if (!json)
    {
        send_json_error(res, 400, "Invalid JSON");
        return U_CALLBACK_COMPLETE;
    }

    const char *current_password = json_string_value(json_object_get(json, "current_password"));
    const char *new_password = json_string_value(json_object_get(json, "new_password"));

    if (!current_password || !new_password || strlen(new_password) < 8)
    {
        send_json_error(res, 400, "Invalid or missing passwords (new password min 8 chars)");
        json_decref(json);
        return U_CALLBACK_COMPLETE;
    }

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, "SELECT password FROM users WHERE username = ?;", -1, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        y_log_message(Y_LOG_LEVEL_ERROR, "Change Password: Failed to prepare select statement for user %s: %s", username, sqlite3_errmsg(db));
        send_json_error(res, 500, "Internal server error");
        json_decref(json);
        return U_CALLBACK_COMPLETE;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);

    if (rc == SQLITE_ROW)
    {
        const char *stored_hash = (const char *)sqlite3_column_text(stmt, 0);
        if (!verify_password(current_password, stored_hash))
        {
            y_log_message(Y_LOG_LEVEL_WARNING, "Change Password: Incorrect current password for user %s", username);
            send_json_error(res, 401, "Incorrect current password");
            sqlite3_finalize(stmt);
            json_decref(json);
            return U_CALLBACK_COMPLETE;
        }
    }
    else
    {
        // Should not happen if token was valid, but handle defensively
        y_log_message(Y_LOG_LEVEL_ERROR, "Change Password: User %s not found after authentication", username);
        send_json_error(res, 500, "Internal server error");
        sqlite3_finalize(stmt);
        json_decref(json);
        return U_CALLBACK_COMPLETE;
    }
    sqlite3_finalize(stmt); // Finalize select statement

    // Hash new password
    char *hashed_password = hash_password(new_password);
    if (!hashed_password)
    {
        y_log_message(Y_LOG_LEVEL_ERROR, "Change Password: Failed to hash new password for user %s", username);
        send_json_error(res, 500, "Internal server error");
        json_decref(json);
        return U_CALLBACK_COMPLETE;
    }

    // Update password in DB
    rc = sqlite3_prepare_v2(db, "UPDATE users SET password = ? WHERE username = ?;", -1, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        y_log_message(Y_LOG_LEVEL_ERROR, "Change Password: Failed to prepare update statement for user %s: %s", username, sqlite3_errmsg(db));
        send_json_error(res, 500, "Internal server error");
        free(hashed_password);
        json_decref(json);
        return U_CALLBACK_COMPLETE;
    }

    sqlite3_bind_text(stmt, 1, hashed_password, -1, SQLITE_TRANSIENT); // Use TRANSIENT
    sqlite3_bind_text(stmt, 2, username, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);

    if (rc == SQLITE_DONE)
    {
        y_log_message(Y_LOG_LEVEL_INFO, "Password changed successfully for user %s", username);
        send_json_message(res, 200, "Password changed successfully");

        // Also invalidate all refresh tokens on password change
        sqlite3_stmt *revoke_stmt;
        if (sqlite3_prepare_v2(db, "DELETE FROM refresh_tokens WHERE username = ?;", -1, &revoke_stmt, NULL) == SQLITE_OK)
        {
            sqlite3_bind_text(revoke_stmt, 1, username, -1, SQLITE_STATIC);
            sqlite3_step(revoke_stmt); // Ignore result, best effort
            sqlite3_finalize(revoke_stmt);
        }
        else
        {
            y_log_message(Y_LOG_LEVEL_ERROR, "Change Password: Failed to prepare statement to delete refresh tokens for user %s", username);
        }
    }
    else
    {
        y_log_message(Y_LOG_LEVEL_ERROR, "Change Password: Failed to update password for user %s: %s", username, sqlite3_errmsg(db));
        send_json_error(res, 500, "Internal server error");
    }

    sqlite3_finalize(stmt);
    free(hashed_password);
    json_decref(json);
    return U_CALLBACK_COMPLETE;
}

// View profile endpoint - Corrected JSON responses
int callback_view_profile(const struct _u_request *req, struct _u_response *res, void *user_data)
{
    char username[256]; // Use consistent buffer size
    if (authenticate_request(req, username, sizeof(username)) != 0)
    {
        send_json_error(res, 401, "Invalid or expired token");
        return U_CALLBACK_COMPLETE;
    }

    sqlite3_stmt *stmt;
    // Assuming 'first_name', 'last_name' might exist, adjust query as needed
    int rc = sqlite3_prepare_v2(db, "SELECT username, email, created_at FROM users WHERE username = ?;", -1, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        y_log_message(Y_LOG_LEVEL_ERROR, "View Profile: Failed to prepare select statement for user %s: %s", username, sqlite3_errmsg(db));
        send_json_error(res, 500, "Internal server error");
        return U_CALLBACK_COMPLETE;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);

    if (rc == SQLITE_ROW)
    {
        json_t *resp = json_object();
        // Safely handle potential NULLs if columns are added later
        json_object_set_new(resp, "username", json_string((const char *)sqlite3_column_text(stmt, 0)));
        json_object_set_new(resp, "email", json_string((const char *)sqlite3_column_text(stmt, 1)));
        json_object_set_new(resp, "created_at", json_integer(sqlite3_column_int64(stmt, 2)));
        // Add other fields like first_name, last_name if they exist in the table

        ulfius_set_json_body_response(res, 200, resp); // Pass json_t* directly
        json_decref(resp);                             // Decref after passing to ulfius
    }
    else
    {
        y_log_message(Y_LOG_LEVEL_WARNING, "View Profile: Profile not found for user %s (token was valid)", username);
        send_json_error(res, 404, "Profile not found");
    }

    sqlite3_finalize(stmt);
    return U_CALLBACK_COMPLETE;
}

// Update profile endpoint - Corrected JSON responses and validation
int callback_update_profile(const struct _u_request *req, struct _u_response *res, void *user_data)
{
    char username[256];
    if (authenticate_request(req, username, sizeof(username)) != 0)
    {
        send_json_error(res, 401, "Invalid or expired token");
        return U_CALLBACK_COMPLETE;
    }

    json_error_t json_error;
    json_t *json = ulfius_get_json_body_request(req, &json_error);
    if (!json)
    {
        send_json_error(res, 400, "Invalid JSON");
        return U_CALLBACK_COMPLETE;
    }

    // Extract fields - handle optional fields (e.g., only update email if provided)
    const char *email = json_string_value(json_object_get(json, "email"));
    // Add other fields like first_name, last_name if needed

    // --- Validation ---
    if (email && strlen(email) > 0)
    { // Only validate if email is provided and not empty
        if (strlen(email) > 255)
        {
            send_json_error(res, 400, "Email too long");
            json_decref(json);
            return U_CALLBACK_COMPLETE;
        }
        if (!is_valid_email(email))
        { // Use the regex validation
            send_json_error(res, 400, "Invalid email format");
            json_decref(json);
            return U_CALLBACK_COMPLETE;
        }

        // Check if email already exists for *another* user
        sqlite3_stmt *stmt;
        int rc = sqlite3_prepare_v2(db, "SELECT 1 FROM users WHERE email = ? AND username != ?;", -1, &stmt, NULL);
        if (rc == SQLITE_OK)
        {
            sqlite3_bind_text(stmt, 1, email, -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, username, -1, SQLITE_STATIC);
            if (sqlite3_step(stmt) == SQLITE_ROW)
            {
                send_json_error(res, 400, "Email already in use by another account");
                sqlite3_finalize(stmt);
                json_decref(json);
                return U_CALLBACK_COMPLETE;
            }
            sqlite3_finalize(stmt);
        }
        else
        {
            y_log_message(Y_LOG_LEVEL_ERROR, "Update Profile: Failed to prepare email check statement for user %s: %s", username, sqlite3_errmsg(db));
            send_json_error(res, 500, "Internal server error");
            json_decref(json);
            return U_CALLBACK_COMPLETE;
        }
    }
    // Add validation for other fields if necessary

    // --- Update ---
    // Build update statement dynamically or use multiple statements if needed
    // Example: Only updating email if provided
    int update_rc = SQLITE_OK;
    if (email && strlen(email) > 0)
    {
        sqlite3_stmt *update_stmt;
        update_rc = sqlite3_prepare_v2(db, "UPDATE users SET email = ? WHERE username = ?;", -1, &update_stmt, NULL);
        if (update_rc == SQLITE_OK)
        {
            sqlite3_bind_text(update_stmt, 1, email, -1, SQLITE_STATIC);
            sqlite3_bind_text(update_stmt, 2, username, -1, SQLITE_STATIC);
            if (sqlite3_step(update_stmt) != SQLITE_DONE)
            {
                update_rc = SQLITE_ERROR; // Mark as error
                y_log_message(Y_LOG_LEVEL_ERROR, "Update Profile: Failed to update email for user %s: %s", username, sqlite3_errmsg(db));
            }
            sqlite3_finalize(update_stmt);
        }
        else
        {
            y_log_message(Y_LOG_LEVEL_ERROR, "Update Profile: Failed to prepare email update statement for user %s: %s", username, sqlite3_errmsg(db));
        }
    }
    // Add similar blocks for other fields (first_name, last_name)

    if (update_rc == SQLITE_OK)
    { // Check if *any* update succeeded or no update was needed
        // Fetch the updated profile to return
        sqlite3_stmt *fetch_stmt;
        int fetch_rc = sqlite3_prepare_v2(db, "SELECT username, email, created_at FROM users WHERE username = ?;", -1, &fetch_stmt, NULL);
        if (fetch_rc == SQLITE_OK)
        {
            sqlite3_bind_text(fetch_stmt, 1, username, -1, SQLITE_STATIC);
            if (sqlite3_step(fetch_stmt) == SQLITE_ROW)
            {
                json_t *resp = json_object();
                json_object_set_new(resp, "username", json_string((const char *)sqlite3_column_text(fetch_stmt, 0)));
                json_object_set_new(resp, "email", json_string((const char *)sqlite3_column_text(fetch_stmt, 1)));
                json_object_set_new(resp, "created_at", json_integer(sqlite3_column_int64(fetch_stmt, 2)));
                // Add other fields
                ulfius_set_json_body_response(res, 200, resp);
                json_decref(resp);
            }
            else
            {
                // Should not happen if user was authenticated
                send_json_error(res, 404, "Profile not found after update");
            }
            sqlite3_finalize(fetch_stmt);
        }
        else
        {
            y_log_message(Y_LOG_LEVEL_ERROR, "Update Profile: Failed to prepare statement to fetch updated profile for user %s: %s", username, sqlite3_errmsg(db));
            send_json_error(res, 500, "Internal server error");
        }
    }
    else
    {
        // An update failed
        send_json_error(res, 500, "Internal server error during profile update");
    }

    json_decref(json);
    return U_CALLBACK_COMPLETE;
}

void signal_handler(int sig)
{
    keep_running = 0;
}

void cleanup()
{
    keep_running = 0;
    pthread_join(cleanup_thread, NULL);
    if (db)
    {
        sqlite3_close(db);
        db = NULL;
    }
}

int main(int argc, char *argv[])
{
    struct _u_instance instance;
    load_config();
    if (!validate_config() || !init_db())
    {
        cleanup();
        return 1;
    }
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    if (pthread_create(&cleanup_thread, NULL, cleanup_thread_function, NULL) != 0)
    {
        log_message("ERROR", "Failed to start cleanup thread");
        cleanup();
        return 1;
    }
    if (ulfius_init_instance(&instance, config.port, NULL, NULL) != U_OK)
    {
        log_message("ERROR", "Failed to initialize Ulfius");
        cleanup();
        return 1;
    }

    // Ensure all callbacks used here are defined or have prototypes above
    ulfius_add_endpoint_by_val(&instance, "GET", "/health", NULL, 0, &callback_health_check, NULL);
    ulfius_add_endpoint_by_val(&instance, "POST", "/register", NULL, 0, &callback_register, NULL);
    ulfius_add_endpoint_by_val(&instance, "POST", "/login", NULL, 0, &callback_login, NULL);
    ulfius_add_endpoint_by_val(&instance, "POST", "/refresh", NULL, 0, &callback_refresh_token, NULL);
    ulfius_add_endpoint_by_val(&instance, "POST", "/logout", NULL, 0, &callback_logout, NULL);
    ulfius_add_endpoint_by_val(&instance, "POST", "/forgot-password", NULL, 0, &callback_forgot_password, NULL); // Now defined
    ulfius_add_endpoint_by_val(&instance, "POST", "/change-password", NULL, 0, &callback_change_password, NULL); // Now defined
    ulfius_add_endpoint_by_val(&instance, "GET", "/profile", NULL, 0, &callback_view_profile, NULL);
    ulfius_add_endpoint_by_val(&instance, "PUT", "/profile", NULL, 0, &callback_update_profile, NULL);

    if (ulfius_start_framework(&instance) == U_OK)
    {
        log_message("INFO", "Server started on port %d", config.port);
        while (keep_running)
        {
            sleep(1);
        }
    }
    else
    {
        log_message("ERROR", "Failed to start server");
    }
    ulfius_stop_framework(&instance);
    ulfius_clean_instance(&instance);
    cleanup();
    return 0;
}