/**
 * @file client.c
 * @brief program on client in the client-servel model
 */

#include "client.h"

void handle_sigint(int sig)
{
    if (close(sock_fd) < 0)
    {
        perror("Close sock_fd");
    }
    exit(0);
}

struct addrinfo* get_server_address(char* hostname, char* port)
{
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(hostname, port, &hints, &res);
    if (status != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        exit(1);
    }
    return res;
}

void get_credentials(char* username, char* password)
{
    printf("Enter username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0;
    fflush(stdout);
    printf("Enter password: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = 0;
}

void handle_tcp_connection(struct addrinfo* res, char* username, char* password)
{
    printf("[TCP connection]\n");
    if ((sock_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0)
    {
        printf("\n Socket creation error.\n");
        exit(EXIT_FAILURE);
    }
    int opt_set_s = 1;
    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt_set_s, sizeof(opt_set_s)))
    {
        perror("Setsockopt");
        exit(EXIT_FAILURE);
    }
    if ((connect(sock_fd, res->ai_addr, res->ai_addrlen)) < 0)
    {
        perror("Connection");
        if (close(sock_fd) < 0)
        {
            perror("Close");
        }
        exit(EXIT_FAILURE);
    }
    char buffer[BUF_SIZE];
    int num_bytes, finish = 0;

    sprintf(buffer, "Username: %s, Password: %s", username, password);
    num_bytes = write(sock_fd, buffer, strlen(buffer));
    if (num_bytes < 0)
    {
        perror("Write to socket");
        if (close(sock_fd) < 0)
        {
            perror("Close");
        }
        exit(EXIT_FAILURE);
    }

    memset(buffer, '\0', BUF_SIZE);
    num_bytes = read(sock_fd, buffer, BUF_SIZE);
    if (num_bytes < 0)
    {
        perror("Read from socket");
        if (close(sock_fd) < 0)
        {
            perror("Close");
        }
        exit(EXIT_FAILURE);
    }
    printf("Answer from server: %s.\n", buffer);
    fflush(stdout);

    if (strcmp("unauthorized client", buffer) == 0)
    {
        printf("Unprivileged user.\n");
        if (close(sock_fd) < 0)
        {
            perror("Close");
        }
        printf("changing to udp connection...\n");
        handle_udp_connection(res);
        return;
    }
    else
    {
        printf("privileged user.\n");

        while (TRUE)
        {
            printf("you can manage:meat,vegetables,fruits,water,antibiotics,analgesics,bandages\n");
            printf("1° option --> Enter 'modify' field to change(e.g:'meat') amount('15')\n");
            printf("2° option --> Enter 'state' or 'end':");
            fflush(stdout);
            memset(buffer, '\0', BUF_SIZE);
            fgets(buffer, BUF_SIZE - 1, stdin);
            num_bytes = write(sock_fd, buffer, strlen(buffer));
            if (num_bytes < 0)
            {
                perror("Write to socket");
                if (close(sock_fd) < 0)
                {
                    perror("Close");
                }
                exit(EXIT_FAILURE);
            }

            buffer[strlen(buffer) - 1] = '\0';
            if (!strcmp("end", buffer))
            {
                finish = 1;
            }

            memset(buffer, '\0', BUF_SIZE);
            num_bytes = read(sock_fd, buffer, BUF_SIZE);
            printf("Answer from server: %s.\n", buffer);
            fflush(stdout);
            if (num_bytes < 0)
            {
                perror("Read from socket");
                if (close(sock_fd) < 0)
                {
                    perror("Close");
                }
                exit(EXIT_FAILURE);
            }
            if ((strcmp("ending process", buffer) == 0) || (strcmp("end of process due to emergency", buffer) == 0))
            {
                finish = 1;
            }

            if (finish)
            {
                printf("Finishing execution of the tcp connection.\n");
                if (close(sock_fd) < 0)
                {
                    perror("Close");
                }
                return;
            }
        }
    }
}

void handle_udp_connection(struct addrinfo* res)
{
    printf("[UDP connection]\n");
    if ((sock_fd = socket(res->ai_family, SOCK_DGRAM, 0)) < 0)
    {
        printf("\n Socket creation error.\n");
        exit(EXIT_FAILURE);
    }
    int opt_set_s = 1;
    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt_set_s, sizeof(opt_set_s)))
    {
        perror("Setsockopt");
        exit(EXIT_FAILURE);
    }
    char buffer[BUF_SIZE];
    memset(buffer, 0, BUF_SIZE);
    int num_bytes = 0, finish = 0;
    ;

    while (TRUE)
    {
        printf("Enter 'state' or 'end':");
        memset(buffer, 0, BUF_SIZE);
        fgets(buffer, BUF_SIZE, stdin);
        int addr_len = res->ai_addrlen;

        int num_bytes = sendto(sock_fd, (void*)buffer, BUF_SIZE, 0, res->ai_addr, addr_len);
        if (num_bytes < 0)
        {
            perror("Sendto");
            if (close(sock_fd) < 0)
            {
                perror("Close");
            }
            exit(EXIT_FAILURE);
        }

        buffer[strlen(buffer) - 1] = '\0';
        if (!strcmp("end", buffer))
        {
            finish = 1;
        }

        memset(buffer, 0, sizeof(buffer));
        num_bytes = recvfrom(sock_fd, (void*)buffer, BUF_SIZE, 0, res->ai_addr, &addr_len);
        if (num_bytes < 0)
        {
            perror("Recvfrom");
            if (close(sock_fd) < 0)
            {
                perror("Close");
            }
            exit(EXIT_FAILURE);
        }

        printf("Answer from server:%s.\n", buffer);
        fflush(stdout);

        if (strcmp("end of process due to emergency", buffer) == 0)
        {
            finish = 1;
        }

        if (finish)
        {
            printf("Finishing execution of the udp connection.\n");
            if (close(sock_fd) < 0)
            {
                perror("Close");
                exit(EXIT_FAILURE);
            }
            return;
        }
    }
}
int is_port_in_range(int port)
{
    return port >= MIN_PORT && port <= MAX_PORT;
}

void read_config(char* hostname, int* port)
{
    FILE* file = fopen(TXTPATHCLIENT, "r");
    if (file == NULL)
    {
        printf("Could not open file config.txt\n");
        exit(1);
    }

    if (fgets(hostname, 50, file) == NULL)
    {
        printf("Could not read the IP address of the file\n");
        fclose(file);
        exit(1);
    }

    size_t len = strlen(hostname);
    if (len > 0 && hostname[len - 1] == '\n')
    {
        hostname[len - 1] = '\0';
    }

    if (fscanf(file, "%d", port) != 1)
    {
        printf("Could not read file port\n");
        fclose(file);
        exit(1);
    }
    if (!is_port_in_range(*port))
    {
        printf("Port %d is not in the range 1024-65535\n", *port);
        fclose(file);
        exit(1);
    }
    fclose(file);
}

int main(int argc, char const* argv[])
{
    signal(SIGINT, handle_sigint);
    char hostname[50];
    int port;

    read_config(hostname, &port);

    char port_str[6];
    sprintf(port_str, "%d", port);

    struct addrinfo* res = get_server_address(hostname, port_str);

    char username[LOGIN_LENG];
    char password[LOGIN_LENG];
    get_credentials(username, password);
    handle_tcp_connection(res, username, password);
    freeaddrinfo(res);
    return 0;
}
