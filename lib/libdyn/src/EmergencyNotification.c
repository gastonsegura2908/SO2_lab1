/**
 * @file EmergencyNotification.c
 * @brief external emergency module
 */

#include "EmergencyNotification.h"

void emerg_notif()
{
    int emergency_pipe_fd = open(EMERGENCY_PIPE_PATH, O_WRONLY);
    if (emergency_pipe_fd == -1)
    {
        perror("Failed to open emergency pipe");
        exit(EXIT_FAILURE);
    }
    char emergency_message[SIZE];

    while (TRUE)
    {
        sleep((rand() % 6) + 25); // ~ between 25 y 30 seconds

        srand(time(NULL));
        int random_message = rand() % 3;
        switch (random_message)
        {
        case 0:
            sprintf(emergency_message, "Server failure");
            break;
        case 1:
            sprintf(emergency_message, "Power outage");
            break;
        case 2:
            sprintf(emergency_message, "Earthquake");
            break;
        }

        ssize_t write_ret = write(emergency_pipe_fd, emergency_message, strlen(emergency_message));
        if (write_ret == -1)
        {
            perror("Failed to write to emergency pipe");
            exit(EXIT_FAILURE);
        }
        memset(emergency_message, 0, sizeof(emergency_message));

        fflush(stdout);
    }

    if (close(emergency_pipe_fd) == -1)
    {
        perror("Failed to close emergency pipe");
        exit(EXIT_FAILURE);
    }
}
