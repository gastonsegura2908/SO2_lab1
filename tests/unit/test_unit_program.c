#include "AlertInvasion.h"
#include "EmergencyNotification.h"
#include "SuppliesData.h"
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <unity.h>
#define SMO_USERS_NAME "/users_summary"
#define SMO_SIZE 4096
#define ALERT_PIPE_PATH "/tmp/alert_pipe"
#define EMERGENCY_PIPE_PATH "/tmp/emergency_pipe"
#define SEM_KEY_SUPP 2345
#define SEM_KEY_USERS 6789
void *ptr_users;
int sem_id_supp, sem_id_users;

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

void test_logic_create_delete_client(void)
{
    initialize_semaphores();
    int fd;
    fd = shm_open(SMO_USERS_NAME, O_CREAT | O_RDWR, 0666);
    ftruncate(fd, SMO_SIZE);
    void *ptr_users = mmap(0, SMO_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    create_users_summary(ptr_users);
    create_new_client(ptr_users, 4, 0, 1, sem_id_users);
    create_new_client(ptr_users, 2345, 0, 0, sem_id_users);
    TEST_ASSERT_EQUAL(1, get_protocol(4, sem_id_users));
    TEST_ASSERT_EQUAL(0, get_protocol(2345, sem_id_users));
    TEST_ASSERT_EQUAL(-1, get_protocol(3, sem_id_users));
    delete_client(ptr_users, 4, sem_id_users);
    delete_client(ptr_users, 2345, sem_id_users);
    TEST_ASSERT_EQUAL(-1, get_protocol(4, sem_id_users));
    TEST_ASSERT_EQUAL(-1, get_protocol(2345, sem_id_users));

    if (munmap(ptr_users, SMO_SIZE) == -1)
    {
        perror("munmap");
        exit(EXIT_FAILURE);
    }
    if (close(fd) == -1)
    {
        perror("close");
        exit(EXIT_FAILURE);
    }
    if (shm_unlink(SMO_USERS_NAME) == -1)
    {
        perror("shm_unlink");
        exit(EXIT_FAILURE);
    }
}

// void test_logic_emerg_notif(void)
// {
//     int emergency_pipe_fd;
//     pid_t emergency_pid;

//     mkfifo(EMERGENCY_PIPE_PATH, 0666);

//     emergency_pipe_fd = open(EMERGENCY_PIPE_PATH, O_RDONLY | O_NONBLOCK);
//     if (emergency_pipe_fd == -1)
//     {
//         perror("Error opening emergency pipe");
//     }

//     emergency_pid = fork();
//     if (emergency_pid == -1)
//     {
//         perror("Error creating emergency process");
//     }
//     else if (emergency_pid == 0)
//     {
//         emerg_notif();
//         exit(EXIT_SUCCESS);
//     }else{
//         sleep(30);

//         if (kill(emergency_pid, SIGTERM) == -1) {
//             perror("kill");
//             exit(EXIT_FAILURE);
//         }

//         if (waitpid(emergency_pid, NULL, 0) == -1) {
//             perror("waitpid");
//             exit(EXIT_FAILURE);
//         }

//         char buffer[SIZE];
//         ssize_t num_bytes = read(emergency_pipe_fd, buffer, SIZE - 1);
//         if (num_bytes == -1) {
//             perror("read");
//             exit(EXIT_FAILURE);
//         }
//         buffer[num_bytes] = '\0';
//         if (strstr(buffer, "Server failure") != NULL ||
//             strstr(buffer, "Power outage") != NULL ||
//             strstr(buffer, "Earthquake") != NULL) {
//             printf("Emergency message received: %s\n", buffer);
//             TEST_ASSERT_EQUAL(strlen(buffer), num_bytes);
//         }

//         if (close(emergency_pipe_fd) == -1) {
//             perror("close");
//             exit(EXIT_FAILURE);
//         }
//         if (unlink(EMERGENCY_PIPE_PATH) == -1) {
//             perror("unlink");
//             exit(EXIT_FAILURE);
//         }
//     }
// }

void setUp(void)
{
}

void tearDown(void)
{
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_logic_create_delete_client);

    // RUN_TEST(test_logic_emerg_notif);

    return UNITY_END();
}
