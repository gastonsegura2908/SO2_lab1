/**
 * @file EmergencyNotification.h
 * @brief EmergencyNotification.c header file
 */

#ifndef EMERGENCYNOTIFICATION_H
#define EMERGENCYNOTIFICATION_H

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/** @def EMERGENCY_PIPE_PATH "/tmp/emergency_pipe"
 *  @brief Path for the emergency pipe.
 */
#define EMERGENCY_PIPE_PATH "/tmp/emergency_pipe"

/** @def TRUE 1
 *  @brief Boolean value for TRUE.
 */
#define TRUE 1

/** @def SIZE 60
 *  @brief General size used in the system.
 */
#define SIZE 60

/**
 * @brief Generates random emergency notifications.
 *
 * This function continuously generates random emergency notifications ("Server failure", "Power outage", "Earthquake")
 * at intervals of 25 to 30 seconds. These messages are sent to a pipe. The function handles errors related to
 * opening/closing the pipe and writing to it. If any step fails, it prints an error message and exits.
 */
void emerg_notif();

#endif
