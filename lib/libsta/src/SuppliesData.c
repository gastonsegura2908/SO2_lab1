/**
 * @file SuppliesData.c
 * @brief supply management module
 */

#include "SuppliesData.h"

cJSON* state_users = NULL;
char* json_string_user = NULL;

void sem_lock_sd(int sem_id)
{
    struct sembuf sb = {0, -1, 0};
    semop(sem_id, &sb, 1);
}

void sem_unlock_sd(int sem_id)
{
    struct sembuf sb = {0, 1, 0};
    semop(sem_id, &sb, 1);
}

void create_users_summary(void* ptr)
{
    state_users = cJSON_CreateObject();
    if (state_users == NULL)
    {
        printf("Error creating JSON object\n");
        exit(1);
    }

    cJSON* tcp_clients = cJSON_CreateArray();
    cJSON_AddItemToObject(state_users, "tcp_clients", tcp_clients);

    cJSON* udp_clients = cJSON_CreateArray();
    cJSON_AddItemToObject(state_users, "udp_clients", udp_clients);

    save_users_summary_to_file(ptr);
}

void create_new_client(void* ptr, int value, int end, int is_tcp, int sem_id)
{
    sem_lock_sd(sem_id);
    cJSON* clients = cJSON_GetObjectItem(state_users, is_tcp ? "tcp_clients" : "udp_clients");
    if (clients == NULL)
    {
        clients = cJSON_CreateArray();
        cJSON_AddItemToObject(state_users, is_tcp ? "tcp_clients" : "udp_clients", clients);
    }

    cJSON* newClientInfo = cJSON_CreateObject();
    if (is_tcp)
    {
        cJSON_AddNumberToObject(newClientInfo, "socket", value);
    }
    else
    {
        cJSON_AddNumberToObject(newClientInfo, "port", value);
    }
    cJSON_AddNumberToObject(newClientInfo, "end", end);
    cJSON_AddItemToArray(clients, newClientInfo);

    save_users_summary_to_file(ptr);
    sem_unlock_sd(sem_id);
}

void delete_client(void* ptr, int value, int sem_id)
{
    sem_lock_sd(sem_id);
    cJSON* tcp_clients = cJSON_GetObjectItem(state_users, "tcp_clients");
    cJSON* udp_clients = cJSON_GetObjectItem(state_users, "udp_clients");

    cJSON* clients[] = {tcp_clients, udp_clients};
    const char* keys[] = {"socket", "port"};
    int i;
    for (i = 0; i < 2; i++)
    {
        cJSON* client_list = clients[i];
        if (client_list == NULL)
        {
            continue;
        }

        cJSON* client = NULL;
        int index = 0;
        cJSON_ArrayForEach(client, client_list)
        {
            if (cJSON_GetObjectItem(client, keys[i])->valueint == value)
            {
                cJSON_DeleteItemFromArray(client_list, index);
                break;
            }
            index++;
        }
    }

    save_users_summary_to_file(ptr);
    sem_unlock_sd(sem_id);
}

void save_users_summary_to_file(void* ptr)
{
    json_string_user = cJSON_Print(state_users);
    if (json_string_user == NULL)
    {
        printf("Error printing JSON object\n");
        return;
    }

    FILE* file = fopen(US_SUM_JSON, "w");
    if (file == NULL)
    {
        printf("Error opening file\n");
        free(json_string_user);
        return;
    }

    fprintf(file, "%s", json_string_user);
    strcpy((char*)ptr, json_string_user);
    fclose(file);
    free(json_string_user);
}

int get_protocol(int value, int sem_id)
{
    cJSON* tcp_clients = cJSON_GetObjectItem(state_users, "tcp_clients");
    if (tcp_clients != NULL)
    {
        cJSON* client = NULL;
        cJSON_ArrayForEach(client, tcp_clients)
        {
            if (cJSON_GetObjectItem(client, "socket")->valueint == value)
            {
                return 1; // TCP
            }
        }
    }

    cJSON* udp_clients = cJSON_GetObjectItem(state_users, "udp_clients");
    if (udp_clients != NULL)
    {
        cJSON* client = NULL;
        cJSON_ArrayForEach(client, udp_clients)
        {
            if (cJSON_GetObjectItem(client, "port")->valueint == value)
            {
                return 0; // UDP
            }
        }
    }

    return -1; // unknown
}
