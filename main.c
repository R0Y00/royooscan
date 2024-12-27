#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <stdbool.h>

#pragma comment(lib, "ws2_32.lib") // Winsock 库链接

#define MAX_PORT 65535       // 最大端口号
#define TIMEOUT 20           // 超时时间（毫秒）
#define BATCH_SIZE 500       // 每个线程扫描的端口数量

typedef struct {
    long *data;      // 动态数组存储队列数据
    int front;       // 队列头索引
    int rear;        // 队列尾索引
    int capacity;    // 队列容量
    int size;        // 当前队列大小
} Queue;

// 队列函数实现
Queue* create_queue(int capacity) {
    Queue *queue = (Queue *)malloc(sizeof(Queue));
    queue->data = (long *)malloc(capacity * sizeof(long));
    queue->front = 0;
    queue->rear = -1;
    queue->capacity = capacity;
    queue->size = 0;
    return queue;
}

int is_empty(Queue *queue) {
    return queue->size == 0;
}

int is_full(Queue *queue) {
    return queue->size == queue->capacity;
}

void enqueue(Queue *queue, long value) {
    if (is_full(queue)) return;
    queue->rear = (queue->rear + 1) % queue->capacity;
    queue->data[queue->rear] = value;
    queue->size++;
}

long dequeue(Queue *queue) {
    if (is_empty(queue)) return -1;
    long value = queue->data[queue->front];
    queue->front = (queue->front + 1) % queue->capacity;
    queue->size--;
    return value;
}

void free_queue(Queue *queue) {
    free(queue->data);
    free(queue);
}

// 全局变量和锁
volatile long current_port = 1;  // 当前扫描的端口号
char target_ip[16];              // 目标 IP 地址
int open_ports[MAX_PORT] = {0};  // 0 表示关闭，1 表示开放
CRITICAL_SECTION queue_lock;     // 队列锁
CRITICAL_SECTION open_ports_lock; // 用于保护 open_ports 的锁

Queue *port_queue; // 队列存储需要扫描的端口

// 扫描 TCP 端口
void scan_tcp(long port) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) return;

    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);

    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    target.sin_addr.s_addr = inet_addr(target_ip);

    connect(sock, (struct sockaddr*)&target, sizeof(target));

    fd_set write_fds;
    struct timeval timeout;
    FD_ZERO(&write_fds);
    FD_SET(sock, &write_fds);
    timeout.tv_sec = 0;
    timeout.tv_usec = TIMEOUT * 1000;

    if (select(0, NULL, &write_fds, NULL, &timeout) > 0) {
        EnterCriticalSection(&open_ports_lock);
        open_ports[port] = 1;
        LeaveCriticalSection(&open_ports_lock);
    }

    closesocket(sock);
}

// 扫描 UDP 端口
void scan_udp(long port) {
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == INVALID_SOCKET) return;

    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    target.sin_addr.s_addr = inet_addr(target_ip);

    char send_data[] = "Hello"; // 任意 UDP 数据
    sendto(sock, send_data, sizeof(send_data), 0, (struct sockaddr*)&target, sizeof(target));

    fd_set read_fds;
    struct timeval timeout;
    FD_ZERO(&read_fds);
    FD_SET(sock, &read_fds);
    timeout.tv_sec = 0;
    timeout.tv_usec = TIMEOUT * 1000;

    if (select(0, &read_fds, NULL, NULL, &timeout) > 0) {
        EnterCriticalSection(&open_ports_lock);
        open_ports[port] = 1;
        LeaveCriticalSection(&open_ports_lock);
    }

    closesocket(sock);
}

DWORD WINAPI scan_port_pool(LPVOID arg) {
    bool is_udp = *((bool*)arg);

    while (true) {
        long port;

        // 从队列中获取一个端口
        EnterCriticalSection(&queue_lock);
        if (is_empty(port_queue)) {
            LeaveCriticalSection(&queue_lock);
            break;
        }
        port = dequeue(port_queue);
        LeaveCriticalSection(&queue_lock);

        // 根据扫描类型选择 TCP 或 UDP
        if (is_udp) {
            scan_udp(port);
        } else {
            scan_tcp(port);
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Usage: %s <IP> <threads> <tcp|udp>\n", argv[0]);
        return 1;
    }

    // 获取目标 IP 和线程数
    strncpy(target_ip, argv[1], 16);
    int thread_count = atoi(argv[2]);
    bool is_udp = strcmp(argv[3], "udp") == 0;

    if (thread_count < 1 || thread_count > 1000) {
        printf("Thread count must be between 1 and 1000.\n");
        return 1;
    }

    // 初始化 Winsock
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("Failed to initialize Winsock: %d\n", WSAGetLastError());
        return 1;
    }

    // 初始化锁
    InitializeCriticalSection(&queue_lock);
    InitializeCriticalSection(&open_ports_lock);

    // 初始化任务队列
    port_queue = create_queue(MAX_PORT);
    for (long port = 1; port <= MAX_PORT; port++) {
        enqueue(port_queue, port);
    }

    // 创建线程池
    HANDLE *threads = (HANDLE *)malloc(thread_count * sizeof(HANDLE));
    for (int i = 0; i < thread_count; i++) {
        threads[i] = CreateThread(NULL, 0, scan_port_pool, &is_udp, 0, NULL);
        if (threads[i] == NULL) {
            printf("Failed to create thread %d, error code: %lu\n", i, GetLastError());
        }
    }

    // 等待所有线程完成
    WaitForMultipleObjects(thread_count, threads, TRUE, INFINITE);

    // 打印开放端口
    printf("Scan complete. Open ports:\n");
    int open_count = 0;
    for (int i = 1; i <= MAX_PORT; i++) {
        if (open_ports[i]) {
            open_count++;
            printf("Port %d is open\n", i);
        }
    }
    printf("Total open ports: %d\n", open_count);

    // 释放资源
    for (int i = 0; i < thread_count; i++) {
        CloseHandle(threads[i]);
    }
    free(threads);
    free_queue(port_queue);
    DeleteCriticalSection(&queue_lock);
    DeleteCriticalSection(&open_ports_lock);
    WSACleanup();

    return 0;
}
