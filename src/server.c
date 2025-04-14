
/**
 * @file server.c
 * @brief program on server in the client-servel model
 */

#include "server.h"

void handle_sigint(int sig)
{
    if (access(ALERT_PIPE_PATH, F_OK) != -1)
    {
        unlink(ALERT_PIPE_PATH);
    }
    if (access(EMERGENCY_PIPE_PATH, F_OK) != -1)
    {
        unlink(EMERGENCY_PIPE_PATH);
    }

    close(alert_pipe_fd);
    close(emergency_pipe_fd);
    close(socket_fd_tcp);
    close(socket_fd_udp);

    if (kill(alert_pid, 0) != -1 || errno != ESRCH)
    {
        kill(alert_pid, SIGTERM);
    }
    if (kill(emergency_pid, 0) != -1 || errno != ESRCH)
    {
        kill(emergency_pid, SIGTERM);
    }

    exit(EXIT_SUCCESS);
}

void sem_lock(int sem_id)
{
    struct sembuf sb = {0, -1, 0};
    semop(sem_id, &sb, 1);
}

void sem_unlock(int sem_id)
{
    struct sembuf sb = {0, 1, 0};
    semop(sem_id, &sb, 1);
}

void initialize_semaphores()
{
    sem_id_supp = semget(SEM_KEY_SUPP, 1, IPC_CREAT | 0666);
    if (sem_id_supp == -1)
    {
        perror("semget");
        exit(EXIT_FAILURE);
    }
    semctl(sem_id_supp, 0, SETVAL, 1);

    sem_id_users = semget(SEM_KEY_USERS, 1, IPC_CREAT | 0666);
    if (sem_id_users == -1)
    {
        perror("semget");
        exit(EXIT_FAILURE);
    }
    semctl(sem_id_users, 0, SETVAL, 1);
}

void handle_tcp(int new_socket_fd_tcp, int msq_id_tcp, struct msgbuf* buf_tcp, int msq_id_delete,
                struct msgbuf* buf_delete)
{
    char client_address[INET6_ADDRSTRLEN];
    char log_buffer[MAX_BUFFER];
    char buffer[BUF_SIZE];
    int num_bytes;
    int first_time = 1;

    while (TRUE)
    {
        memset(buffer, 0, BUF_SIZE);
        num_bytes = read(new_socket_fd_tcp, buffer, BUF_SIZE - 1);
        if (num_bytes < 0)
        {
            perror("Socket read");
            exit(EXIT_FAILURE);
        }
        buffer[num_bytes - 1] = '\0';
        printf("Received from client:%s\n", buffer);
        fflush(stdout);
        char command[MAX_BUFFER];
        sscanf(buffer, "%s", command);
        if ((strcmp(command, "modify") == 0))
        {
            get_client_address(new_socket_fd_tcp, client_address, sizeof(client_address));
            printf("[SERVER] Updated of supplies from client %s\n", client_address);
            sprintf(log_buffer, "Updated of supplies from client %s", client_address);
            log_activity(log_buffer);

            sprintf(buf_tcp->mtext, buffer + strlen(command) + 1);
            int result = msgsnd(msq_id_tcp, buf_tcp, strlen(buf_tcp->mtext) + 1, 0); // -- type 1
            if (result == -1)
            {
                perror("Error in msgsnd");
            }

            sprintf(buffer, "updating supplies");
        }
        else
        {
            if (strcmp(buffer, "state") == 0)
            {
                strcpy(buffer, (char*)ptr_supp);
                get_client_address(new_socket_fd_tcp, client_address, sizeof(client_address));
                printf("[SERVER] Request of state from client %s\n", client_address);
                sprintf(log_buffer, "Request of state from client %s", client_address);
                log_activity(log_buffer);
            }
            else
            {
                if (strcmp(buffer, "end") == 0)
                {
                    sprintf(buffer, "ending process");

                    sprintf(buf_delete->mtext, "%d", new_socket_fd_tcp);
                    int result = msgsnd(msq_id_delete, buf_delete, strlen(buf_delete->mtext) + 1, 0); // -- type 4
                    if (result == -1)
                    {
                        perror("Error in msgsnd");
                    }
                }
                else
                {
                    sprintf(buffer, "wrong message");
                }
            }
        }

        num_bytes = write(new_socket_fd_tcp, buffer, strlen(buffer));
        if (num_bytes < 0)
        {
            perror("Writing to socket");
            exit(EXIT_FAILURE);
        }

        if (strcmp("ending process", buffer) == 0)
        {
            sprintf(log_buffer, "ending process %s", client_address);
            log_activity(log_buffer);
            close(new_socket_fd_tcp);
            exit(0);
        }
    }
}

int handle_udp(int socket_fd_udp, struct sockaddr_in6 serv_addr, int msq_id_delete, struct msgbuf* buf_delete)
{
    int addr_len = sizeof(struct sockaddr_in6);
    char buffer[BUF_SIZE];
    int num_bytes = 0;
    struct sockaddr_in6 client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    while (TRUE)
    {
        memset(buffer, 0, BUF_SIZE);

        num_bytes = recvfrom(socket_fd_udp, buffer, BUF_SIZE - 1, 0, (struct sockaddr*)&client_addr, &client_addr_len);
        if (num_bytes < 0)
        {
            perror("receive to socket");
            exit(EXIT_FAILURE);
        }

        int client_port = ntohs(client_addr.sin6_port);

        printf("Received from client:%s\n", buffer);
        fflush(stdout);
        buffer[strlen(buffer) - 1] = '\0';
        if (strcmp(buffer, "state") == 0)
        {
            sprintf(buffer, strdup((char*)ptr_supp));
        }
        else if (strcmp(buffer, "end") == 0)
        {
            sprintf(buffer, "ending process");
            sprintf(buf_delete->mtext, "%d", client_port);
            int result = msgsnd(msq_id_delete, buf_delete, strlen(buf_delete->mtext) + 1, 0); // -- type 4
            if (result == -1)
            {
                perror("Error in msgsnd");
            }
        }
        else
        {
            sprintf(buffer, "you entered the wrong message");
        }

        num_bytes = sendto(socket_fd_udp, buffer, strlen(buffer), 0, (struct sockaddr*)&client_addr, client_addr_len);
        if (num_bytes < 0)
        {
            perror("sending to socket");
            exit(1);
        }
        return client_port;
    }
}

void setup_shared_memory_supplies()
{
    int fd;

    fd = shm_open(SMO_SUMMARY_NAME, O_CREAT | O_RDWR, 0666);
    ftruncate(fd, SMO_SIZE);

    ptr_supp = mmap(0, SMO_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr_supp == MAP_FAILED)
    {
        perror("mmap");
        exit(EXIT_FAILURE);
    }

    create_state_summary();
}

void setup_shared_memory_users()
{
    int fd;

    fd = shm_open(SMO_USERS_NAME, O_CREAT | O_RDWR, 0666);
    ftruncate(fd, SMO_SIZE);

    ptr_users = mmap(0, SMO_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr_users == MAP_FAILED)
    {
        perror("mmap");
        exit(EXIT_FAILURE);
    }

    create_users_summary(ptr_users);
}

int accept_new_connection(int server_socket, int msq_id_create, struct msgbuf* buf_create)
{
    int add_size = sizeof(sockaddr_in6);
    int client_socket;
    int client_role;
    char log_buffer[MAX_BUFFER + LOG_BUF_SIZE];
    char client_address[MAX_BUFFER];
    sockaddr_in6 client_addr;

    client_socket = accept(server_socket, (sockaddr*)&client_addr, (socklen_t*)&add_size);
    if (client_socket == -1)
    {
        perror("Error accepting connection from client");
        return -1;
    }

    client_role = auth_client(client_socket);
    if (client_role == -1)
    {
        close(client_socket);

        printf("The client was not authorized\n");
        return -1;
    }
    sprintf(buf_create->mtext, "%d", client_socket);
    int result = msgsnd(msq_id_create, buf_create, strlen(buf_create->mtext) + 1, 0); // -- type 3
    if (result == -1)
    {
        perror("Error in msgsnd");
    }

    char ipstr[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(client_addr.sin6_addr), ipstr, sizeof ipstr);
    printf("[SERVER] New connection at %s:%d\n", ipstr, ntohs(client_addr.sin6_port));
    get_client_address(client_socket, client_address, sizeof(client_address));
    sprintf(log_buffer, "Connection from new client %s", client_address);
    log_activity(log_buffer);
    memset(log_buffer, 0, MAX_BUFFER);

    return client_socket;
}

int auth_client(int client_socket)
{
    ssize_t valread;
    char buffer[MAX_BUFFER];
    int num_bytes = 0;
    int auto_user = 0;

    memset(buffer, 0, MAX_BUFFER);
    if ((valread = read(client_socket, buffer, MAX_BUFFER - 1)) <= 0)
    {
        if (close(client_socket) < 0)
        {
            perror("Close client_socket");
        }
        perror("Socket read");
        exit(1);
    }

    if (strcmp(buffer, "Username: UBUNTU, Password: UBUNTU") == 0)
    {
        sprintf(buffer, "authorized client");
        auto_user = 1;
    }
    else
    {
        sprintf(buffer, "unauthorized client");
    }

    num_bytes = write(client_socket, buffer, strlen(buffer));
    if (num_bytes < 0)
    {
        perror("Writing to socket");
        exit(1);
    }

    if (auto_user)
    {
        return 0;
    }
    else
    {
        return -1;
    }
}

void get_client_address(int client_socket, char* client_address, size_t buffer_size)
{
    struct sockaddr_in6 addr;
    socklen_t addr_len = sizeof(addr);
    char ipstr[INET6_ADDRSTRLEN];

    if (getpeername(client_socket, (struct sockaddr*)&addr, &addr_len) == 0)
    {
        inet_ntop(AF_INET6, &(addr.sin6_addr), ipstr, sizeof ipstr);
        snprintf(client_address, buffer_size, "%s:%d", ipstr, ntohs(addr.sin6_port));
    }
    else
    {
        perror("Error getting client address");
        exit(EXIT_FAILURE);
    }
}

void log_activity(const char* activity)
{
    time_t current_time;
    struct tm* local_time;
    char timestamp[80];

    current_time = time(NULL);
    local_time = localtime(&current_time);
    strftime(timestamp, sizeof(timestamp), "%a %b %d %T %Y", local_time);

    FILE* log_file = fopen(LOG_PATH, "a");

    fprintf(log_file, "%s, %s\n", timestamp, activity);

    fclose(log_file);
}

void handle_alerts()
{
    char buffer[MAX_BUFFER];
    ssize_t bytes_read;

    while ((bytes_read = read(alert_pipe_fd, buffer, MAX_BUFFER)) > 0)
    {
        buffer[bytes_read - 1] = '\0';

        modify_alerts(buffer);

        printf("[ALERT] %s\n", buffer);
        log_activity(buffer);
        strcat(buffer, "\n");

        memset(buffer, 0, MAX_BUFFER);
    }

    if (bytes_read == 0)
    {
        printf("[ALERT] Alert pipe closed\n");
    }
}

void handle_emergencies(int msq_id_em, struct msgbuf* buf_em)
{
    char buffer[MAX_BUFFER];
    ssize_t bytes_read;

    bytes_read = read(emergency_pipe_fd, buffer, MAX_BUFFER);
    if (bytes_read <= 0)
        return;

    buffer[bytes_read - 1] = '\0';

    printf("[EMERGENCY] %s\n", buffer);
    log_activity(buffer);

    sprintf(buf_em->mtext, buffer);
    int result = msgsnd(msq_id_em, buf_em, strlen(buf_em), 0); // -- type 2
    if (result == -1)
    {
        perror("error in msgsnd handle_emergencies");
    }
}

void create_state_summary()
{
    state_summary = cJSON_CreateObject();

    if (state_summary == NULL)
    {
        printf("Error creating JSON object\n");
        exit(1);
    }

    cJSON* alerts = cJSON_CreateObject();
    cJSON_AddItemToObject(state_summary, "alerts", alerts);

    cJSON_AddNumberToObject(alerts, "north_entry", 0);
    cJSON_AddNumberToObject(alerts, "east_entry", 0);
    cJSON_AddNumberToObject(alerts, "west_entry", 0);
    cJSON_AddNumberToObject(alerts, "south_entry", 0);

    cJSON* supplies = cJSON_CreateObject();
    cJSON_AddItemToObject(state_summary, "supplies", supplies);

    cJSON* food = cJSON_CreateObject();
    cJSON_AddItemToObject(supplies, "food", food);

    cJSON_AddNumberToObject(food, "meat", 100);
    cJSON_AddNumberToObject(food, "vegetables", 200);
    cJSON_AddNumberToObject(food, "fruits", 150);
    cJSON_AddNumberToObject(food, "water", 1000);

    cJSON* medicine = cJSON_CreateObject();
    cJSON_AddItemToObject(supplies, "medicine", medicine);

    cJSON_AddNumberToObject(medicine, "antibiotics", 50);
    cJSON_AddNumberToObject(medicine, "analgesics", 100);
    cJSON_AddNumberToObject(medicine, "bandages", 100);

    cJSON* emergency = cJSON_CreateObject();
    cJSON_AddItemToObject(state_summary, "emergency", emergency);
    cJSON_AddStringToObject(emergency, "last_event", "NULL");

    save_state_summary_to_file();
}

void save_state_summary_to_file()
{
    char* json_string = cJSON_Print(state_summary);
    if (json_string == NULL)
    {
        printf("Error printing JSON object\n");
        return;
    }

    FILE* file = fopen(ST_SUM_JSON, "w");
    if (file == NULL)
    {
        printf("Error opening file\n");
        free(json_string);
        return;
    }

    fprintf(file, "%s", json_string);
    strcpy((char*)ptr_supp, json_string);
    fclose(file);
    free(json_string);
}

void modify_supplies(const char* message)
{
    char field[MAX_BUFFER];
    int value;
    if (sscanf(message, "%s %d", field, &value) != 2)
    {
        printf("Invalid message format\n");
        return;
    }

    cJSON* element = NULL;
    cJSON* supplies = cJSON_GetObjectItem(state_summary, "supplies");

    if (strcmp(field, "meat") == 0 || strcmp(field, "vegetables") == 0 || strcmp(field, "fruits") == 0 ||
        strcmp(field, "water") == 0)
    {
        cJSON* food = cJSON_GetObjectItem(supplies, "food");
        element = cJSON_GetObjectItem(food, field);
    }
    else if (strcmp(field, "antibiotics") == 0 || strcmp(field, "analgesics") == 0 || strcmp(field, "bandages") == 0)
    {
        cJSON* medicine = cJSON_GetObjectItem(supplies, "medicine");
        element = cJSON_GetObjectItem(medicine, field);
    }
    else
    {
        printf("Unknown field: %s\n", field);
        return;
    }

    if (element != NULL)
    {
        cJSON_SetNumberValue(element, value);
        save_state_summary_to_file();
    }
    else
    {
        printf("Field not found: %s\n", field);
    }
}

void modify_alerts(const char* alert_message)
{
    char area[MAX_BUFFER];
    float temperature;

    if (sscanf(alert_message, "Alert of possible infection in %[^,], %f", area, &temperature) != 2)
    {
        printf("Invalid alert message format\n");
        return;
    }

    cJSON* alerts = cJSON_GetObjectItem(state_summary, "alerts");
    if (alerts == NULL)
    {
        printf("Error accessing alerts object\n");
        return;
    }

    cJSON* alert_entry = cJSON_GetObjectItem(alerts, area);
    if (alert_entry == NULL)
    {
        printf("Alert entry not found for area: %s\n", area);
        return;
    }

    int current_value = cJSON_GetNumberValue(alert_entry);
    cJSON_SetNumberValue(alert_entry, current_value + 1);

    save_state_summary_to_file();
}

void modify_emergency(const char* alert_message)
{
    cJSON* emergency = cJSON_GetObjectItem(state_summary, "emergency");
    if (emergency == NULL)
    {
        printf("Error accessing emergency object\n");
        return;
    }

    cJSON* em_entry = cJSON_GetObjectItem(emergency, "last_event");
    if (em_entry == NULL)
    {
        printf("emergency entry not found");
        return;
    }

    time_t t = time(NULL);
    struct tm* tm_info = localtime(&t);
    char time_str[100];
    strftime(time_str, 100, " %Y-%m-%d %H:%M:%S", tm_info);

    char new_alert_message[200];
    sprintf(new_alert_message, "%s %s", alert_message, time_str);

    cJSON* new_last_event = cJSON_CreateString(new_alert_message);
    cJSON_ReplaceItemInObject(emergency, "last_event", new_last_event);

    save_state_summary_to_file();
}

int is_port_in_range(int port)
{
    return port >= MIN_PORT && port <= MAX_PORT;
}

int read_port_from_file()
{
    FILE* file = fopen(TXT_PATH_SERVER, "r");
    if (file == NULL)
    {
        printf("Could not open file port\n");
        return -1;
    }

    char* line = NULL;
    size_t len = 0;
    ssize_t read;

    int line_number = 0;
    int port = 0;

    while ((read = getline(&line, &len, file)) != -1)
    {
        line_number++;
        if (line_number == 2)
        {
            port = atoi(line);
            break;
        }
    }

    free(line);
    fclose(file);

    if (port == 0)
    {
        printf("Could not read file port\n");
        return -1;
    }

    if (!is_port_in_range(port))
    {
        printf("Port %d is not in the range 1024-65535\n", port);
        return -1;
    }

    return port;
}

int main(int argc, char const* argv[])
{
    signal(SIGINT, handle_sigint);
    int port = read_port_from_file();
    if (port == -1)
    {
        return 1;
    }
    initialize_semaphores();
    char buffer[MAX_BUFFER];
    char log_buffer[MAX_BUFFER + LOG_BUF_SIZE];
    char client_address[MAX_BUFFER];

    struct msgbuf buf_tcp;
    int msq_id_tcp = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
    if (msq_id_tcp == -1)
    {
        perror("msgget");
        return 1;
    }
    buf_tcp.mtype = 1;

    struct msgbuf buf_em;
    int msq_id_em = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
    if (msq_id_em == -1)
    {
        perror("msgget");
        return 1;
    }
    buf_em.mtype = 2;

    struct msgbuf buf_create;
    int msq_id_create = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
    if (msq_id_create == -1)
    {
        perror("msgget");
        return 1;
    }
    buf_create.mtype = 3;

    struct msgbuf buf_delete;
    int msq_id_delete = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
    if (msq_id_delete == -1)
    {
        perror("msgget");
        return 1;
    }
    buf_delete.mtype = 4;

    int new_socket_fd_tcp, cli_len, pid, opt_set_s = 1, addr_len, client_socket;
    fd_set read_fds;
    struct sockaddr_in6 serv_addr, cli_addr;
    int num_bytes;

    socket_fd_tcp = socket(AF_INET6, SOCK_STREAM, 0);
    socket_fd_udp = socket(AF_INET6, SOCK_DGRAM, 0);

    if (setsockopt(socket_fd_tcp, SOL_SOCKET, SO_REUSEADDR, &opt_set_s, sizeof(opt_set_s)))
    {
        perror("Setsockopt");
        exit(EXIT_FAILURE);
    }
    if (setsockopt(socket_fd_udp, SOL_SOCKET, SO_REUSEADDR, &opt_set_s, sizeof(opt_set_s)))
    {
        perror("Setsockopt");
        exit(EXIT_FAILURE);
    }
    char port_str[6];
    sprintf(port_str, "%d", port);

    memset((char*)&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin6_family = AF_INET6;
    serv_addr.sin6_addr = in6addr_any;
    serv_addr.sin6_port = htons(port);

    if (bind(socket_fd_tcp, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("Bind tcp failed");
        exit(EXIT_FAILURE);
    }
    if (bind(socket_fd_udp, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("Bind udp failed");
        exit(EXIT_FAILURE);
    }
    printf("Process: %d - available socket: %d.\n", getpid(), ntohs(serv_addr.sin6_port));
    if (listen(socket_fd_tcp, NUM_CLI) < 0)
    {
        perror("Listen");
        exit(EXIT_FAILURE);
    }

    setup_shared_memory_supplies();
    setup_shared_memory_users();

    mkfifo(ALERT_PIPE_PATH, 0666);

    alert_pipe_fd = open(ALERT_PIPE_PATH, O_RDONLY | O_NONBLOCK);
    if (alert_pipe_fd == -1)
    {
        perror("Error opening alert pipe");
    }

    alert_pid = fork();
    if (alert_pid == -1)
    {
        perror("Error creating alert process");
    }
    else if (alert_pid == 0)
    {
        temp_alert();
        exit(EXIT_SUCCESS);
    }

    mkfifo(EMERGENCY_PIPE_PATH, 0666);

    emergency_pipe_fd = open(EMERGENCY_PIPE_PATH, O_RDONLY | O_NONBLOCK);
    if (emergency_pipe_fd == -1)
    {
        perror("Error opening emergency pipe");
    }

    emergency_pid = fork();
    if (emergency_pid == -1)
    {
        perror("Error creating emergency process");
    }
    else if (emergency_pid == 0)
    {
        emerg_notif();
        exit(EXIT_SUCCESS);
    }

    cli_len = sizeof(cli_addr);
    addr_len = sizeof(struct sockaddr);

    while (TRUE)
    {
        FD_ZERO(&read_fds);
        FD_SET(socket_fd_tcp, &read_fds);
        FD_SET(socket_fd_udp, &read_fds);
        FD_SET(alert_pipe_fd, &read_fds);
        FD_SET(emergency_pipe_fd, &read_fds);

        int max_fd = (socket_fd_tcp > socket_fd_udp) ? socket_fd_tcp : socket_fd_udp;
        max_fd = (max_fd > alert_pipe_fd) ? max_fd : alert_pipe_fd;
        max_fd = (max_fd > emergency_pipe_fd) ? max_fd : emergency_pipe_fd;

        if (select(max_fd + 1, &read_fds, NULL, NULL, NULL) == -1)
        {
            perror("Select");
            exit(1);
        }

        if (FD_ISSET(socket_fd_tcp, &read_fds))
        {
            client_socket = accept_new_connection(socket_fd_tcp, msq_id_create, &buf_create);
            if (client_socket == -1) // udp
            {
                continue;
            }

            pid = fork();
            if (pid < 0)
            {
                perror("Fork ERROR");
                exit(1);
            }

            if (pid == 0)
            {
                close(socket_fd_tcp);
                handle_tcp(client_socket, msq_id_tcp, &buf_tcp, msq_id_delete, &buf_delete);
                close(client_socket);
                exit(0);
            }
        }

        if (FD_ISSET(socket_fd_udp, &read_fds))
        {
            int client_port = handle_udp(socket_fd_udp, serv_addr, msq_id_delete, &buf_delete);
            if (get_protocol(client_port, sem_id_users) < 0)
            {
                create_new_client(ptr_users, client_port, 0, NOTAUTHORIZED, sem_id_users);
            }
        }

        if (FD_ISSET(alert_pipe_fd, &read_fds))
        {
            handle_alerts();
        }

        if (FD_ISSET(emergency_pipe_fd, &read_fds))
        {
            handle_emergencies(msq_id_em, &buf_em);
        }

        if (msgrcv(msq_id_tcp, &buf_tcp, sizeof(buf_tcp.mtext), 1, IPC_NOWAIT) == -1)
        { // -- by tcp
            if (!(errno == ENOMSG))
            {
                perror("msgrcv");
            }
        }
        else
        {
            sem_lock(sem_id_supp);
            modify_supplies(buf_tcp.mtext);
            sem_unlock(sem_id_supp);
        }

        if (msgrcv(msq_id_em, &buf_em, sizeof(buf_em.mtext), 2, IPC_NOWAIT) == -1)
        { // -- by emergencies
            if (!(errno == ENOMSG))
            {
                perror("msgrcv");
            }
        }
        else
        {
            modify_emergency(buf_em.mtext);
        }

        if (msgrcv(msq_id_create, &buf_create, sizeof(buf_create.mtext), 3, IPC_NOWAIT) == -1)
        { // -- by tcp connection new
            if (!(errno == ENOMSG))
            {
                perror("msgrcv");
            }
        }
        else
        {
            if (get_protocol(atoi(buf_create.mtext), sem_id_users) < 0)
            {
                create_new_client(ptr_users, atoi(buf_create.mtext), 0, AUTHORIZED, sem_id_users);
            }
        }

        if (msgrcv(msq_id_delete, &buf_delete, sizeof(buf_delete.mtext), 4, IPC_NOWAIT) == -1)
        { // -- by delete udp or tcp connection
            if (!(errno == ENOMSG))
            {
                perror("msgrcv");
            }
        }
        else
        {
            delete_client(ptr_users, atoi(buf_delete.mtext), sem_id_users);
        }
    }
    return 0;
}
