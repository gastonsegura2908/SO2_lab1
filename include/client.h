/**
 * @file client.h
 * @brief  detail of each function of client.c
 */
#pragma once
#ifndef CLIENT_H

/**
 *  @brief ifndef identifier
 */
#define CLIENT_H

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

/**
 *  @brief Path to the client configuration file.
 */
#define TXTPATHCLIENT "../startproject/configuration.txt"

/**
 *  @brief Buffer size for various operations.
 */
#define BUF_SIZE 2048

/**
 *  @brief Boolean value for TRUE.
 */
#define TRUE 1

/**
 *  @brief Minimum port number.
 */
#define MIN_PORT 1024

/**
 *  @brief Maximum port number.
 */
#define MAX_PORT 65535

/**
 *  @brief Length of arguments.
 */
#define ARG_LENG 3

/**
 *  @brief Length of login credentials.
 */
#define LOGIN_LENG 20

/**
 *  @brief Socket file descriptor.
 *
 *  This variable represents the socket file descriptor used for network communication.
 */
int sock_fd;

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
 * @brief Gets the server address.
 *
 * This function takes a hostname as input and returns a `sockaddr_in` structure. It uses the `inet_pton` function
 * to convert the hostname (an IPv4 address in text form) into a network byte order binary form, which is stored
 * in `serv_addr.sin_addr`. If `inet_pton` returns 0, it means the input is not a valid IPv4 address. If it returns -1,
 * it means there was a system error. In either case, an error message is printed and the program exits.
 *
 * @param hostname The hostname to convert.
 * @param port The port number.
 * @return A `sockaddr_in` structure representing the server address.
 */
struct addrinfo* get_server_address(char* hostname, char* port);

/**
 * @brief Gets the user's credentials.
 *
 * This function prompts the user to enter their username and password. It reads the input from the standard input
 * (`stdin`), removes the newline character from the end of each input string, and stores the inputs in the `username`
 * and `password` variables. If the input exceeds the size of the variables, it will only store the characters that fit,
 * ensuring that no buffer overflow occurs.
 *
 * @param username The variable to store the username.
 * @param password The variable to store the password.
 */
void get_credentials(char* username, char* password);

/**
 * @brief Handles a TCP connection.
 *
 * This function creates a TCP socket, connects to a server, and then enters a loop where it sends and receives messages
 * from the server. The server's address information is provided by the 'res' parameter. The function sends the username
 * and password to the server and then waits for a response. If the server responds with 'unauthorized client', the
 * function closes the socket, prints a message, and then handles a UDP connection. If the server responds with anything
 * else, the function enters a loop where it prompts the user to enter a command, sends this command to the server, and
 * then waits for a response. The loop continues until the user enters 'end' or the server responds with 'ending
 * process' or 'end of process due to emergency'. When the loop ends, the function closes the socket and returns.
 *
 * @param res A pointer to a struct addrinfo that contains the server's address information.
 * @param username A pointer to a string that contains the username.
 * @param password A pointer to a string that contains the password.
 */
void handle_tcp_connection(struct addrinfo* res, char* username, char* password);

/**
 * @brief Handles a UDP connection.
 *
 * This function creates a UDP socket and enters a loop where it sends and receives messages from a server.
 * The server's address information is provided by the 'res' parameter.
 * The function prompts the user to enter 'state' or 'end', sends this message to the server, and then waits for a
 * response. If the user enters 'end' or if the server responds with 'end of process due to emergency', the function
 * closes the socket and returns.
 *
 * @param res A pointer to a struct addrinfo that contains the server's address information.
 */
void handle_udp_connection(struct addrinfo* res);

/**
 * @brief Reads the IP address and port number from a configuration file.
 *
 * This function opens a file named "config.txt" in read mode and reads the IP address and port number from the file.
 * The IP address is expected to be on the first line of the file and the port number on the second line.
 * The read IP address and port number are stored in the provided variables.
 *
 * If the file cannot be opened, or if the IP address or port number cannot be read, the function prints an error
 * message and terminates the program.
 *
 * @param hostname hostname
 * @param port A pointer to an integer where the read port number will be stored.
 */
void read_config(char* hostname, int* port);

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
 * @brief The main function of the client program.
 *
 * This function sets up a signal handler for SIGINT, reads the server's hostname and port number from a configuration
 * file, gets the server's address, prompts the user for their username and password, and then handles the TCP
 * connection to the server. It also frees the memory allocated for the server's address information before exiting.
 */
int main(int argc, char const* argv[]);

#endif