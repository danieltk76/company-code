/*
 * SecureLogD - Enterprise Logging Daemon
 * High-performance network logging service for enterprise environments
 * 
 * Copyright (c) 2024 Enterprise Systems Inc.
 * Licensed under MIT License
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <stdarg.h>

#define MAX_CLIENTS 100
#define BUFFER_SIZE 4096
#define MAX_LOG_SIZE 1024 * 1024 * 100  // 100MB
#define LOG_DIR "/var/log/securelogd"
#define CONFIG_FILE "/etc/securelogd/securelogd.conf"
#define PID_FILE "/var/run/securelogd.pid"
#define DEFAULT_PORT 8514

/* Configuration structure */
typedef struct {
    int port;
    char log_directory[256];
    char user[64];
    char group[64];
    int max_connections;
    int log_rotation;
    int debug_mode;
    char allowed_hosts[10][64];
    int num_allowed_hosts;
} config_t;

/* Client connection structure */
typedef struct {
    int socket;
    struct sockaddr_in address;
    char hostname[256];
    time_t connected_at;
    int authenticated;
    char username[64];
} client_t;

/* Global variables */
static config_t config;
static int server_socket;
static client_t clients[MAX_CLIENTS];
static pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static int running = 1;
static FILE *current_log_file = NULL;

/* Function prototypes */
void init_config(void);
int load_config(const char *filename);
void daemonize(void);
int create_server_socket(int port);
void *client_handler(void *arg);
void *connection_acceptor(void *arg);
void handle_log_message(client_t *client, const char *message);
void rotate_log_file(void);
int authenticate_client(client_t *client, const char *auth_data);
void process_command(client_t *client, const char *command);
void cleanup_and_exit(int sig);
void drop_privileges(void);
int is_host_allowed(const char *ip);
void log_to_file(const char *level, const char *message, ...);

int main(int argc, char *argv[]) {
    int opt;
    char *config_file = CONFIG_FILE;
    
    /* Parse command line arguments */
    while ((opt = getopt(argc, argv, "c:dh")) != -1) {
        switch (opt) {
            case 'c':
                config_file = optarg;
                break;
            case 'd':
                config.debug_mode = 1;
                break;
            case 'h':
                printf("Usage: %s [-c config_file] [-d] [-h]\n", argv[0]);
                printf("  -c: Configuration file path\n");
                printf("  -d: Debug mode (don't daemonize)\n");
                printf("  -h: Show this help\n");
                exit(EXIT_SUCCESS);
            default:
                fprintf(stderr, "Invalid option. Use -h for help.\n");
                exit(EXIT_FAILURE);
        }
    }
    
    /* Initialize configuration */
    init_config();
    
    /* Load configuration file */
    if (load_config(config_file) != 0) {
        fprintf(stderr, "Failed to load configuration from %s\n", config_file);
        exit(EXIT_FAILURE);
    }
    
    /* Create log directory if it doesn't exist */
    if (mkdir(config.log_directory, 0755) != 0 && errno != EEXIST) {
        perror("mkdir");
        exit(EXIT_FAILURE);
    }
    
    /* Setup signal handlers */
    signal(SIGTERM, cleanup_and_exit);
    signal(SIGINT, cleanup_and_exit);
    signal(SIGPIPE, SIG_IGN);
    
    /* Create server socket */
    server_socket = create_server_socket(config.port);
    if (server_socket < 0) {
        fprintf(stderr, "Failed to create server socket\n");
        exit(EXIT_FAILURE);
    }
    
    printf("SecureLogD starting on port %d\n", config.port);
    printf("Log directory: %s\n", config.log_directory);
    
    /* Daemonize if not in debug mode */
    if (!config.debug_mode) {
        daemonize();
    }
    
    /* Drop privileges after binding to socket */
    drop_privileges();
    
    /* Initialize client array */
    memset(clients, 0, sizeof(clients));
    
    /* Start connection acceptor thread */
    pthread_t acceptor_thread;
    if (pthread_create(&acceptor_thread, NULL, connection_acceptor, NULL) != 0) {
        perror("pthread_create");
        exit(EXIT_FAILURE);
    }
    
    /* Main daemon loop */
    log_to_file("INFO", "SecureLogD daemon started successfully");
    
    while (running) {
        sleep(1);
        
        /* Check for log rotation */
        if (config.log_rotation) {
            struct stat st;
            if (current_log_file && fstat(fileno(current_log_file), &st) == 0) {
                if (st.st_size > MAX_LOG_SIZE) {
                    rotate_log_file();
                }
            }
        }
    }
    
    /* Cleanup */
    log_to_file("INFO", "SecureLogD daemon shutting down");
    pthread_join(acceptor_thread, NULL);
    close(server_socket);
    
    if (current_log_file) {
        fclose(current_log_file);
    }
    
    return EXIT_SUCCESS;
}

void init_config(void) {
    config.port = DEFAULT_PORT;
    strcpy(config.log_directory, LOG_DIR);
    strcpy(config.user, "nobody");
    strcpy(config.group, "nobody");
    config.max_connections = MAX_CLIENTS;
    config.log_rotation = 1;
    config.debug_mode = 0;
    config.num_allowed_hosts = 0;
}

int load_config(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        /* Use defaults if config file doesn't exist */
        return 0;
    }
    
    char line[512];
    while (fgets(line, sizeof(line), file)) {
        /* Remove newline */
        line[strcspn(line, "\n")] = 0;
        
        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\0') {
            continue;
        }
        
        char key[128], value[256];
        if (sscanf(line, "%127s = %255s", key, value) == 2) {
            if (strcmp(key, "port") == 0) {
                config.port = atoi(value);
            } else if (strcmp(key, "log_directory") == 0) {
                strncpy(config.log_directory, value, sizeof(config.log_directory) - 1);
            } else if (strcmp(key, "user") == 0) {
                strncpy(config.user, value, sizeof(config.user) - 1);
            } else if (strcmp(key, "group") == 0) {
                strncpy(config.group, value, sizeof(config.group) - 1);
            } else if (strcmp(key, "max_connections") == 0) {
                config.max_connections = atoi(value);
            } else if (strcmp(key, "log_rotation") == 0) {
                config.log_rotation = atoi(value);
            } else if (strcmp(key, "allowed_host") == 0 && config.num_allowed_hosts < 10) {
                strncpy(config.allowed_hosts[config.num_allowed_hosts], value, 
                       sizeof(config.allowed_hosts[0]) - 1);
                config.num_allowed_hosts++;
            }
        }
    }
    
    fclose(file);
    return 0;
}

void daemonize(void) {
    pid_t pid, sid;
    
    /* Fork off the parent process */
    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);  /* Parent exits */
    }
    
    /* Create a new SID for the child process */
    sid = setsid();
    if (sid < 0) {
        exit(EXIT_FAILURE);
    }
    
    /* Change working directory to root */
    if ((chdir("/")) < 0) {
        exit(EXIT_FAILURE);
    }
    
    /* Close standard file descriptors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    /* Write PID file */
    FILE *pid_file = fopen(PID_FILE, "w");
    if (pid_file) {
        fprintf(pid_file, "%d\n", getpid());
        fclose(pid_file);
    }
}

int create_server_socket(int port) {
    int sockfd;
    struct sockaddr_in server_addr;
    int opt = 1;
    
    /* Create socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }
    
    /* Set socket options */
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(sockfd);
        return -1;
    }
    
    /* Bind socket */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    
    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(sockfd);
        return -1;
    }
    
    /* Listen for connections */
    if (listen(sockfd, config.max_connections) < 0) {
        perror("listen");
        close(sockfd);
        return -1;
    }
    
    return sockfd;
}

void *connection_acceptor(void *arg) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    while (running) {
        int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket < 0) {
            if (running) {
                perror("accept");
            }
            continue;
        }
        
        /* Check if host is allowed */
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        
        if (!is_host_allowed(client_ip)) {
            log_to_file("WARN", "Connection from unauthorized host: %s", client_ip);
            close(client_socket);
            continue;
        }
        
        /* Find available client slot */
        pthread_mutex_lock(&clients_mutex);
        int slot = -1;
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].socket == 0) {
                slot = i;
                break;
            }
        }
        
        if (slot >= 0) {
            clients[slot].socket = client_socket;
            clients[slot].address = client_addr;
            strcpy(clients[slot].hostname, client_ip);
            clients[slot].connected_at = time(NULL);
            clients[slot].authenticated = 0;
            
            /* Create thread to handle client */
            pthread_t client_thread;
            if (pthread_create(&client_thread, NULL, client_handler, &clients[slot]) != 0) {
                perror("pthread_create");
                close(client_socket);
                clients[slot].socket = 0;
            } else {
                pthread_detach(client_thread);
            }
        } else {
            /* No available slots */
            close(client_socket);
        }
        pthread_mutex_unlock(&clients_mutex);
    }
    
    return NULL;
}

void *client_handler(void *arg) {
    client_t *client = (client_t*)arg;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_received;
    
    log_to_file("INFO", "Client connected from %s", client->hostname);
    
    /* Send welcome message */
    const char *welcome = "SecureLogD v1.0 - Please authenticate\n";
    send(client->socket, welcome, strlen(welcome), 0);
    
    while (running) {
        bytes_received = recv(client->socket, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received <= 0) {
            break;  /* Connection closed or error */
        }
        
        buffer[bytes_received] = '\0';
        
        /* Remove trailing newline */
        if (buffer[bytes_received - 1] == '\n') {
            buffer[bytes_received - 1] = '\0';
        }
        
        /* Handle authentication */
        if (!client->authenticated) {
            if (strncmp(buffer, "AUTH ", 5) == 0) {
                if (authenticate_client(client, buffer + 5)) {
                    client->authenticated = 1;
                    const char *auth_ok = "Authentication successful\n";
                    send(client->socket, auth_ok, strlen(auth_ok), 0);
                    log_to_file("INFO", "Client %s authenticated successfully", client->hostname);
                } else {
                    const char *auth_fail = "Authentication failed\n";
                    send(client->socket, auth_fail, strlen(auth_fail), 0);
                    break;
                }
            } else {
                const char *need_auth = "Authentication required\n";
                send(client->socket, need_auth, strlen(need_auth), 0);
            }
            continue;
        }
        
        /* Handle commands */
        if (strncmp(buffer, "CMD ", 4) == 0) {
            process_command(client, buffer + 4);
        } else {
            /* Regular log message */
            handle_log_message(client, buffer);
        }
    }
    
    /* Cleanup client connection */
    log_to_file("INFO", "Client %s disconnected", client->hostname);
    close(client->socket);
    
    pthread_mutex_lock(&clients_mutex);
    memset(client, 0, sizeof(client_t));
    pthread_mutex_unlock(&clients_mutex);
    
    return NULL;
}

void handle_log_message(client_t *client, const char *message) {
    time_t now;
    struct tm *tm_info;
    char timestamp[64];
    char log_entry[BUFFER_SIZE + 256];
    
    time(&now);
    tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    /* Format log entry */
    snprintf(log_entry, sizeof(log_entry), "[%s] %s: %s\n", 
             timestamp, client->hostname, message);
    
    /* Write to log file */
    pthread_mutex_lock(&log_mutex);
    
    if (!current_log_file) {
        char log_filename[512];
        snprintf(log_filename, sizeof(log_filename), "%s/securelogd.log", config.log_directory);
        current_log_file = fopen(log_filename, "a");
        if (!current_log_file) {
            perror("fopen");
            pthread_mutex_unlock(&log_mutex);
            return;
        }
    }
    
    fputs(log_entry, current_log_file);
    fflush(current_log_file);
    
    pthread_mutex_unlock(&log_mutex);
    
    /* Send acknowledgment */
    const char *ack = "OK\n";
    send(client->socket, ack, strlen(ack), 0);
}

void rotate_log_file(void) {
    char old_filename[512], new_filename[512];
    time_t now;
    struct tm *tm_info;
    char timestamp[64];
    
    time(&now);
    tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", tm_info);
    
    pthread_mutex_lock(&log_mutex);
    
    if (current_log_file) {
        fclose(current_log_file);
        current_log_file = NULL;
    }
    
    snprintf(old_filename, sizeof(old_filename), "%s/securelogd.log", config.log_directory);
    snprintf(new_filename, sizeof(new_filename), "%s/securelogd_%s.log", 
             config.log_directory, timestamp);
    
    rename(old_filename, new_filename);
    
    pthread_mutex_unlock(&log_mutex);
    
    log_to_file("INFO", "Log file rotated to %s", new_filename);
}

int authenticate_client(client_t *client, const char *auth_data) {
    char username[64], password[64];
    
    /* Parse authentication data */
    if (sscanf(auth_data, "%63s %63s", username, password) != 2) {
        return 0;
    }
    
    /* Simple authentication - in production this would use proper auth */
    if (strcmp(username, "admin") == 0 && strcmp(password, "securelogd123") == 0) {
        strcpy(client->username, username);
        return 1;
    }
    
    /* Check system users (simplified) */
    struct passwd *pwd = getpwnam(username);
    if (pwd != NULL) {
        /* In a real implementation, you'd verify the password properly */
        strcpy(client->username, username);
        return 1;
    }
    
    return 0;
}

void process_command(client_t *client, const char *command) {
    char response[1024];
    
    if (strcmp(command, "STATUS") == 0) {
        int active_clients = 0;
        pthread_mutex_lock(&clients_mutex);
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].socket != 0) {
                active_clients++;
            }
        }
        pthread_mutex_unlock(&clients_mutex);
        
        snprintf(response, sizeof(response), "Active clients: %d\n", active_clients);
        send(client->socket, response, strlen(response), 0);
        
    } else if (strcmp(command, "ROTATE") == 0) {
        rotate_log_file();
        const char *msg = "Log rotation initiated\n";
        send(client->socket, msg, strlen(msg), 0);
        
    } else if (strncmp(command, "CONFIG ", 7) == 0) {
        /* Handle configuration commands */
        char key[64], value[256];
        if (sscanf(command + 7, "%63s %255s", key, value) == 2) {
            /* This is dangerous - allows runtime config changes */
            if (strcmp(key, "log_directory") == 0) {
                strcpy(config.log_directory, value);
                snprintf(response, sizeof(response), "Log directory changed to: %s\n", value);
            } else if (strcmp(key, "max_connections") == 0) {
                config.max_connections = atoi(value);
                snprintf(response, sizeof(response), "Max connections set to: %d\n", config.max_connections);
            } else {
                strcpy(response, "Unknown configuration key\n");
            }
        } else {
            strcpy(response, "Invalid CONFIG command format\n");
        }
        send(client->socket, response, strlen(response), 0);
        
    } else {
        const char *unknown = "Unknown command\n";
        send(client->socket, unknown, strlen(unknown), 0);
    }
}

void cleanup_and_exit(int sig) {
    running = 0;
    
    /* Close all client connections */
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].socket != 0) {
            close(clients[i].socket);
        }
    }
    pthread_mutex_unlock(&clients_mutex);
    
    /* Remove PID file */
    unlink(PID_FILE);
    
    exit(EXIT_SUCCESS);
}

void drop_privileges(void) {
    struct passwd *pwd;
    struct group *grp;
    
    /* Get user and group information */
    pwd = getpwnam(config.user);
    if (!pwd) {
        fprintf(stderr, "Warning: Could not find user %s\n", config.user);
        return;
    }
    
    grp = getgrnam(config.group);
    if (!grp) {
        fprintf(stderr, "Warning: Could not find group %s\n", config.group);
        return;
    }
    
    /* Drop privileges */
    if (setgid(grp->gr_gid) != 0) {
        perror("setgid");
        exit(EXIT_FAILURE);
    }
    
    if (setuid(pwd->pw_uid) != 0) {
        perror("setuid");
        exit(EXIT_FAILURE);
    }
}

int is_host_allowed(const char *ip) {
    /* If no allowed hosts configured, allow all */
    if (config.num_allowed_hosts == 0) {
        return 1;
    }
    
    for (int i = 0; i < config.num_allowed_hosts; i++) {
        if (strcmp(config.allowed_hosts[i], ip) == 0) {
            return 1;
        }
        /* Simple wildcard matching */
        if (strncmp(config.allowed_hosts[i], ip, strlen(config.allowed_hosts[i]) - 1) == 0 &&
            config.allowed_hosts[i][strlen(config.allowed_hosts[i]) - 1] == '*') {
            return 1;
        }
    }
    
    return 0;
}

void log_to_file(const char *level, const char *message, ...) {
    va_list args;
    char log_message[1024];
    char full_log[1200];
    time_t now;
    struct tm *tm_info;
    char timestamp[64];
    
    va_start(args, message);
    vsnprintf(log_message, sizeof(log_message), message, args);
    va_end(args);
    
    time(&now);
    tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    snprintf(full_log, sizeof(full_log), "[%s] [%s] %s\n", timestamp, level, log_message);
    
    /* Write to current log file or stderr */
    if (current_log_file) {
        pthread_mutex_lock(&log_mutex);
        fputs(full_log, current_log_file);
        fflush(current_log_file);
        pthread_mutex_unlock(&log_mutex);
    } else {
        fputs(full_log, stderr);
    }
} 