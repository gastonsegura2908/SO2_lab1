/**
 * @file AlertInvasion.c
 * @brief temperature alert module
 */

#include "AlertInvasion.h"

void temp_alert()
{

    int alert_pipe_fd = open(ALERT_PIPE_PATH, O_WRONLY);
    if (alert_pipe_fd == -1)
    {
        perror("Failed alert pipe fd");
        exit(EXIT_FAILURE);
    }

    char full_alert[SIZE];
    char alert_message[SIZE];

    const char* entries[] = {"north_entry", "east_entry", "west_entry", "south_entry"};

    srand(time(NULL));
    while (TRUE)
    {
        sleep((rand() % 4) + 5); //~ between 5 and 8 seconds

        float temperature = ((float)rand() / RAND_MAX) * (MAX_TEMP - MIN_TEMP) + MIN_TEMP;
        int entry_index = rand() % 4;
        time_t t = time(NULL);
        struct tm tm = *localtime(&t);
        char timestamp[SIZE_TS];
        if (strftime(timestamp, sizeof(timestamp), "%c", &tm) == 0)
        {
            fprintf(stderr, "strftime returned 0");
            exit(EXIT_FAILURE);
        }

        sprintf(full_alert, "%s, %s, %.1f", timestamp, entries[entry_index], temperature);

        if (temperature >= TEMP)
        {
            sprintf(alert_message, "Alert of possible infection in %s, %.1f\n", entries[entry_index], temperature);
            ssize_t write_ret = write(alert_pipe_fd, alert_message, strlen(alert_message));
            if (write_ret == -1)
            {
                perror("Failed to write to alert pipe");
                exit(EXIT_FAILURE);
            }
        }
        memset(alert_message, 0, sizeof(alert_message));
        memset(full_alert, 0, sizeof(full_alert));
    }

    if (close(alert_pipe_fd) == -1)
    {
        perror("Failed to close alert pipe");
        exit(EXIT_FAILURE);
    }
}
