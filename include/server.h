/**
 * @file server.h
 * @brief detail of each function of server.c
 */
#pragma once
#ifndef SERVER_H

/**
 *  @brief ifndef identifier
 */
#define SERVER_H

#include "AlertInvasion.h"
#include "EmergencyNotification.h"
#include "SuppliesData.h"
#include <arpa/inet.h>
#include <cJSON.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

/**
 *  @brief Buffer size for various operations.
 */
#define BUF_SIZE 1024

/**
 *  @brief Boolean value for TRUE.
 */
#define TRUE 1

/**
 *  @brief Maximum number of clients.
 */
#define NUM_CLI 100

/**
 *  @brief Length of arguments.
 */
#define ARG_LENG 2

/**
 *  @brief Minimum port number.
 */
#define MIN_PORT 1024

/**
 *  @brief Maximum port number.
 */
#define MAX_PORT 65535

/**
 *  @brief Username for authentication.
 */
#define UBUNTU "UBUNTU"

/**
 *  @brief Maximum number of pending connections for the server socket.
 */
#define MAX_PENDING_CONNECTIONS 10

/**
 *  @brief Size of the log buffer.
 */
#define LOG_BUF_SIZE 48

/**
 *  @brief Maximum number of clients.
 */
#define MAX_CLIENTS 100

/**
 *  @brief Maximum size of a buffer.
 */
#define MAX_BUFFER 2048

/**
 *  @brief Size of the shared memory object.
 */
#define SMO_SIZE 4096

/**
 *  @brief Name of the shared memory object for the state summary.
 */
#define SMO_SUMMARY_NAME "/state_summary"

/**
 *  @brief Name of the shared memory object for the users summary.
 */
#define SMO_USERS_NAME "/users_summary"

/**
 *  @brief Path for the alert pipe.
 */
#define ALERT_PIPE_PATH "/tmp/alert_pipe"

/**
 *  @brief Path for the emergency pipe.
 */
#define EMERGENCY_PIPE_PATH "/tmp/emergency_pipe"

/**
 *  @brief Path for the server configuration file.
 */
#define TXT_PATH_SERVER "../startproject/configuration.txt"

/**
 *  @brief Name of the state summary JSON file.
 */
#define ST_SUM_JSON "state_summary.json"

/**
 *  @brief Path for the log file.
 */
#define LOG_PATH "../var/log/refuge.log"

/**
 *  @brief Size of a message.
 */
#define MSG_SIZE 1024

/**
 *  @brief Value for authorized status.
 */
#define AUTHORIZED 1

/**
 *  @brief Value for unauthorized status.
 */
#define NOTAUTHORIZED 0

/**
 *  @brief Key for the semaphore for suppliers.
 */
#define SEM_KEY_SUPP 2345

/**
 *  @brief Key for the semaphore for users.
 */
#define SEM_KEY_USERS 6789

/** @var cJSON* state_summary
 *  @brief Pointer to a cJSON object representing the state summary.
 */
cJSON* state_summary = NULL;

/** @var char* json_string
 *  @brief Pointer to a string representing the JSON string.
 */
char* json_string = NULL;

/** @typedef struct sockaddr_in6 sockaddr_in6
 *  @brief Typedef for the sockaddr_in6 structure.
 */
typedef struct sockaddr_in6 sockaddr_in6;

/** @typedef struct sockaddr sockaddr
 *  @brief Typedef for the sockaddr structure.
 */
typedef struct sockaddr sockaddr;

/** @var void* ptr_supp
 *  @brief Pointer to the shared memory object for suppliers.
 */
void* ptr_supp;

/** @var void* ptr_users
 *  @brief Pointer to the shared memory object for users.
 */
void* ptr_users;

/** @struct ClientInfo
 *  @brief Structure representing a client.
 *  @var ClientInfo::socket
 *  Member 'socket' represents the client's socket.
 *  @var ClientInfo::role
 *  Member 'role' represents the client's role.
 *  @var ClientInfo::end
 *  Member 'end' represents whether the client's session has ended.
 */
typedef struct
{
    int socket;
    int role;
    int end;
} ClientInfo;

/** @var ClientInfo connected_clients[MAX_CLIENTS]
 *  @brief Array of connected clients.
 */
ClientInfo connected_clients[MAX_CLIENTS];

/** @struct msgbuf
 *  @brief Structure for a message buffer.
 *  @var msgbuf::mtype
 *  Member 'mtype' represents the message type.
 *  @var msgbuf::mtext
 *  Member 'mtext' represents the message text.
 */
struct msgbuf
{
    long mtype;
    char mtext[MSG_SIZE];
};

/** @var int alert_pipe_fd
 *  @brief File descriptor for the alert pipe.
 */
/** @var int emergency_pipe_fd
 *  @brief File descriptor for the emergency pipe.
 */
/** @var int socket_fd_tcp
 *  @brief File descriptor for the TCP socket.
 */
/** @var int socket_fd_udp
 *  @brief File descriptor for the UDP socket.
 */
int alert_pipe_fd, emergency_pipe_fd, socket_fd_tcp, socket_fd_udp;

/** @var int sem_id_supp
 *  @brief ID for the semaphore for suppliers.
 */
/** @var int sem_id_users
 *  @brief ID for the semaphore for users.
 */
int sem_id_supp, sem_id_users;

/** @var pid_t alert_pid
 *  @brief PID for the alert process.
 */
/** @var pid_t emergency_pid
 *  @brief PID for the emergency process.
 */
pid_t alert_pid, emergency_pid;

/**
 * @brief Handles the SIGINT signal.
 *
 * This function is called when the program receives a SIGINT signal (e.g., when the user presses `Ctrl+C`).
 * It closes the socket and then exits the program.
 *
 * @param sig The signal number.
 */
void handle_sigint(int sig);

/**
 * @brief Locks a semaphore.
 *
 * This function locks a semaphore by performing a 'P' operation (decrementing the semaphore value).
 * If the semaphore is already 0, the function will block until the semaphore becomes greater than 0.
 *
 * @param sem_id The ID of the semaphore to lock.
 */
void sem_lock(int sem_id);

/**
 * @brief Unlocks a semaphore.
 *
 * This function unlocks a semaphore by performing a 'V' operation (incrementing the semaphore value).
 * If there are other processes waiting on the semaphore, one of them will be unblocked.
 *
 * @param sem_id The ID of the semaphore to unlock.
 */
void sem_unlock(int sem_id);

/**
 * @brief Initializes the semaphores.
 *
 * This function initializes two semaphores: `sem_id_supp` and `sem_id_users`.
 * It uses `semget` to create the semaphores and `semctl` to set their initial values to 1.
 * If `semget` fails, it prints an error message and exits the program.
 */
void initialize_semaphores();

/**
 * @brief Handles a TCP connection with a client.
 *
 * This function manages a TCP connection with a client. It continuously reads messages from the client.
 * If the message is "modify", it sends back the updated supplies. If the message is "state", it sends back the state
 * summary. If the message is "end", it prepares to end the process and sends a message to the message queue to delete
 * the client. For any other message, it sends back "wrong message". The function handles errors for socket read/write
 * operations. After processing each message, it returns.
 *
 * @param new_socket_fd_tcp The socket file descriptor for the TCP connection.
 * @param msq_id_tcp The message queue ID for TCP connections.
 * @param buf_tcp A pointer to the message buffer for TCP connections.
 * @param msq_id_delete The message queue ID for deleting clients.
 * @param buf_delete A pointer to the message buffer for deleting clients.
 */
void handle_tcp(int new_socket_fd_tcp, int msq_id_tcp, struct msgbuf* buf_tcp, int msq_id_delete,
                struct msgbuf* buf_delete);

/**
 * @brief Handles a UDP connection with a client.
 *
 * This function manages a UDP connection with a client. It continuously reads messages from the client.
 * If the message is "state", it sends back the state summary. For any other message, it sends back "you entered the
 * wrong message". The function handles errors for socket read/write operations. After processing each message, it
 * returns.
 *
 * @param socket_fd_udp The socket file descriptor for the UDP connection.
 * @param serv_addr The server address for the UDP connection.
 * @param msq_id_delete The message queue ID for deleting clients.
 * @param buf_delete A pointer to the message buffer for deleting clients.
 *
 * @return The client port if the communication is successful, -1 otherwise.
 */
int handle_udp(int socket_fd_udp, struct sockaddr_in6 serv_addr, int msq_id_delete, struct msgbuf* buf_delete);

/**
 * @brief Sets up a shared memory object for supplies.
 *
 * This function sets up a shared memory object. It opens a shared memory object with the name `SMO_NAME`, sets its size
 * to `SMO_SIZE`, and maps it into the process's address space. If the mapping fails, it prints an error message and
 * exits. After setting up the shared memory, it calls `create_state_summary`.
 */
void setup_shared_memory_supplies();

/**
 * @brief Sets up a shared memory object for users.
 *
 * This function creates a shared memory segment with the name `SMO_USERS_NAME` and size `SMO_SIZE`.
 * Then it maps this segment into the process's address space. If the mapping fails, the program terminates.
 * Finally, it calls `create_users_summary` to initialize the summary of the users in the shared memory.
 */
void setup_shared_memory_users();

/**
 * This function accepts a new connection from a client.
 *
 * @param server_socket The server socket that is listening for incoming connections.
 * @param msq_id_create The message queue ID for creating new clients.
 * @param buf_create A pointer to the message buffer for creating new clients.
 *
 * @return The client socket if the connection and authentication are successful, -1 otherwise.
 */
int accept_new_connection(int server_socket, int msq_id_create, struct msgbuf* buf_create);

/**
 * @brief Authenticates a client connected to a server.
 *
 * This function authenticates a client connected to a server. It reads the client's credentials from the socket.
 * If the credentials match "Username: UBUNTU, Password: UBUNTU", it sends back "authorized client" and sets `auto_user`
 * to 1. Otherwise, it sends back "unauthorized client". If any socket operation fails, it prints an error message and
 * exits. The function returns 0 if the client is authorized, and -1 otherwise.
 *
 * @param client_socket The client's socket to authenticate.
 * @return int 0 if the client is authorized, -1 otherwise.
 */
int auth_client(int client_socket);

/**
 * @brief Retrieves the address of a client connected to a given socket.
 *
 * This function retrieves the address of a client connected to a given socket. It uses the `getpeername` function to
 * get the client's address, and then formats it into a string in the form "IP:Port". This string is stored in the
 * `client_address` buffer. If `getpeername` fails, it prints an error message and exits the program.
 *
 * @param client_socket The client's socket to get the address from.
 * @param client_address The buffer to store the client's address.
 * @param buffer_size The size of the buffer.
 */
void get_client_address(int client_socket, char* client_address, size_t buffer_size);

/**
 * @brief Logs a given activity to a file.
 *
 * This function logs a given activity to a file. It first gets the current time and formats it into a human-readable
 * string. Then, it opens a log file in append mode, writes the timestamp and activity to the file, and finally closes
 * the file. If any step fails, it doesn't handle the error and the program may crash or behave unexpectedly.
 *
 * @param activity The activity to log.
 */
void log_activity(const char* activity);

/**
 * @brief Handles alerts.
 *
 * This function reads alerts from a pipe, modifies them, logs them, and sends them to connected clients.
 * If the pipe is closed, it prints an alert message. It continues this process as long as there are alerts to read.
 * The function uses a buffer to store and manipulate the alerts. It ensures that the buffer is cleared after each alert
 * is processed. The function also handles the case where the alert pipe is closed. It prints a message to indicate this
 * event.
 */
void handle_alerts();

/**
 * @brief Handles emergencies.
 *
 * This function reads an emergency alert from a pipe, logs it, prints it, and sends it to all connected clients.
 * If there's an error while sending, it prints an error message. After handling the emergency, it disconnects all
 * clients. If there's no alert to read, the function returns immediately. The function uses a buffer to store and
 * manipulate the alerts.
 *
 * @param msq_id_em The message queue ID for emergencies.
 * @param buf_em The message buffer for emergencies.
 */
void handle_emergencies(int msq_id_em, struct msgbuf* buf_em);

/**
 * @brief Creates a JSON object to store a summary of the state of a system.
 *
 * This function creates a JSON object to store a summary of the state of a system. This object includes information
 * about alerts, supplies, and emergency events. Alerts are represented as entries from different directions (north,
 * east, west, south). Supplies are divided into food (meat, vegetables, fruits, water) and medicines (antibiotics, pain
 * relievers, bandages). The last emergency event is also recorded. If the JSON object creation fails, the program
 * terminates. In the end, `save_state_summary_to_file` is called to save this summary to a file.
 */
void create_state_summary();

/**
 * @brief Saves the state summary to a file.
 *
 * This function takes the JSON object created in `create_state_summary` and converts it to a text string.
 * If the conversion fails, the function returns. Then, it tries to open a file called “state_summary.json” for writing.
 * If the file open fails, it frees the memory allocated for the JSON string and returns. If successful, it writes the
 * JSON string to the file, copies the JSON string to `ptr_supp`, closes the file, and frees the memory allocated for
 * the JSON string. If `ptr_supp` is a pointer to shared memory, this effectively saves the state summary in shared
 * memory.
 */
void save_state_summary_to_file();

/**
 * @brief Modifies supplies.
 *
 * This function takes a message containing a supply name and a value. It searches for the supply in the state summary
 * (a JSON object) and updates its value. Supplies can be food (meat, vegetables, fruits, water) or medicine
 * (antibiotics, analgesics, bandages). If the supply is found and successfully updated, the state summary is saved to a
 * file.
 *
 * @param message The message containing the supply name and value.
 */
void modify_supplies(const char* message);

/**
 * @brief Modifies alerts.
 *
 * This function takes an alert message containing an area name and a temperature. It searches for the corresponding
 * alert entry for the area in the state summary and increments its value by one. This is used to track the number of
 * possible infection alerts in different areas. If the alert entry is found and successfully updated, the state summary
 * is saved to a file.
 *
 * @param alert_message The alert message containing the area name and temperature.
 */
void modify_alerts(const char* alert_message);

/**
 * @brief Modifies emergency.
 *
 * @param alert_message The alert message containing the emergency.
 */
void modify_emergency(const char* alert_message);

/**
 * @brief Checks if a port is within a valid range.
 *
 * This function checks if the given port is within the range of valid port numbers.
 * The valid range is defined by the constants MIN_PORT and MAX_PORT.
 *
 * @param port The port number to check.
 * @return Returns 1 if the port is within the valid range, otherwise returns 0.
 */
int is_port_in_range(int port);

/**
 * @brief Reads the port number from a file.
 *
 * This function opens a file named "puerto.txt" in read mode and reads the port number
 * from the second line of the file. The port number is then converted to an integer and returned.
 *
 * @return int The port number read from the file. If the file could not be opened, or if the port
 * number could not be read, the function returns -1.
 */
int read_port_from_file();

/**
 * @brief The main function of the server program.
 *
 * This function sets up the server to handle TCP and UDP connections. It reads the port number from a file,
 * initializes semaphores, sets up shared memory, and creates pipes for alerts and emergencies. It then enters a loop
 * where it continuously accepts new connections, handles TCP and UDP requests, and reads from the alert and emergency
 * pipes. It also checks for messages in the message queues and handles them accordingly.
 *
 * @param argc The number of command-line arguments.
 * @param argv The command-line arguments.
 * @return 0 if the program finishes successfully, 1 otherwise.
 */
int main(int argc, char const* argv[]);

#endif