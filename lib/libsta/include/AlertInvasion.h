/**
 * @file AlertInvasion.h
 * @brief AlertInvasion.c header file
 */
#pragma once
#ifndef ALERTINVASION_H
#define ALERTINVASION_H

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/** @def TRUE 1
 *  @brief Boolean value for TRUE.
 */
#define TRUE 1

/** @def SIZE 60
 *  @brief General size used in the system.
 */
#define SIZE 60

/** @def TIME 3
 *  @brief Time interval used in the system.
 */
#define TIME 3

/** @def TEMP 38
 *  @brief Reference temperature.
 */
#define TEMP 38

/** @def MAX_AMOUNT 10
 *  @brief Maximum amount for a certain operation in the system.
 */
#define MAX_AMOUNT 10

/** @def MIN_TEMP 35
 *  @brief Minimum allowed temperature.
 */
#define MIN_TEMP 35

/** @def MAX_TEMP 42
 *  @brief Maximum allowed temperature.
 */

#define MAX_TEMP 42

/** @def SIZE_TS 64
 *  @brief Size of a timestamp.
 */
#define SIZE_TS 64

/** @def ALERT_PIPE_PATH "/tmp/alert_pipe"
 *  @brief Path for the alert pipe.
 */
#define ALERT_PIPE_PATH "/tmp/alert_pipe"

/**
 * @brief Generates random temperature alerts.
 *
 * This function continuously generates random temperature alerts for different areas (north, east, west, south).
 * If the temperature exceeds a certain threshold (38°), it sends an alert message indicating a possible infection in
 * the area to a pipe. The function sleeps for a random interval between 5 and 8 seconds before generating the next
 * alert. It also handles errors related to opening/closing the pipe and formatting the timestamp.
 */
void temp_alert();

#endif
