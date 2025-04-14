/**
 * @file SuppliesData.h
 * @brief SuppliesData.c header file
 */
#pragma once
#ifndef SUPPLIESDATA_H
#define SUPPLIESDATA_H

#include <cJSON.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

/** @def US_SUM_JSON "users_summary.json"
 *  @brief Name of the users summary JSON file.
 */
#define US_SUM_JSON "users_summary.json"

/** @def SEM_KEY_SUPP_SD 1234
 *  @brief Key for the semaphore for supplier data.
 */
#define SEM_KEY_SUPP_SD 1234

/** @def SEM_KEY_USERS_SD 5678
 *  @brief Key for the semaphore for user data.
 */
#define SEM_KEY_USERS_SD 5678

/** @var extern cJSON* state_users
 *  @brief Pointer to a cJSON object representing the state of the users.
 *
 *  This variable is defined in another file and is used to store the state of the users in the system.
 */
extern cJSON* state_users;

/** @var extern char* json_string_user
 *  @brief Pointer to a string representing the JSON string for the users.
 *
 *  This variable is defined in another file and is used to store the JSON string that represents the state of the
 * users.
 */
extern char* json_string_user;

/**
 * @brief Locks a semaphore.
 *
 * This function locks a semaphore by performing a 'P' operation (decrementing the semaphore value).
 * If the semaphore is already 0, the function will block until the semaphore becomes greater than 0.
 *
 * @param sem_id The ID of the semaphore to lock.
 */
void sem_lock_sd(int sem_id);

/**
 * @brief Unlocks a semaphore.
 *
 * This function unlocks a semaphore by performing a 'V' operation (incrementing the semaphore value).
 * If there are other processes waiting on the semaphore, one of them will be unblocked.
 *
 * @param sem_id The ID of the semaphore to unlock.
 */
void sem_unlock_sd(int sem_id);

/**
 * @brief Initializes the JSON object to store the clients' information.
 *
 * This function creates a JSON object and two JSON arrays to store the information of TCP and UDP clients respectively.
 * It then saves the JSON object to a file.
 *
 * @param ptr A pointer to a buffer where the JSON string will be stored.
 */
void create_users_summary(void* ptr);

/**
 * @brief Adds a new client to the JSON object.
 *
 * This function adds a new client to the appropriate list in the JSON object (either TCP or UDP).
 * It then saves the updated JSON object to a file.
 *
 * @param ptr A pointer to a buffer where the JSON string will be stored.
 * @param value The socket descriptor or port number of the new client.
 * @param end The end status of the new client.
 * @param is_tcp A flag indicating whether the new client is a TCP client (1) or a UDP client (0).
 * @param sem_id value of semaphore
 */
void create_new_client(void* ptr, int value, int end, int is_tcp, int sem_id);

/**
 * @brief Removes a client from the JSON object.
 *
 * This function removes a client from the appropriate list in the JSON object (either TCP or UDP).
 * It then saves the updated JSON object to a file.
 *
 * @param ptr A pointer to a buffer where the JSON string will be stored.
 * @param value The socket descriptor or port number of the client to be removed.
 * @param sem_id value of semaphore
 */
void delete_client(void* ptr, int value, int sem_id);

/**
 * @brief Saves the JSON object to a file.
 *
 * This function converts the JSON object to a string and saves it to a file.
 * It also stores the JSON string in a buffer.
 *
 * @param ptr A pointer to a buffer where the JSON string will be stored.
 */
void save_users_summary_to_file(void* ptr);

/**
 * @brief Determines the protocol of a client.
 *
 * This function checks whether a given socket descriptor or port number belongs to a TCP client or a UDP client.
 *
 * @param value The socket descriptor or port number of the client.
 * @param sem_id value of semaphore
 * @return Returns 1 if the client is a TCP client, 0 if the client is a UDP client, and -1 if the client is unknown.
 */
int get_protocol(int value, int sem_id);

#endif
