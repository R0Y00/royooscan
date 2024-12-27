#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <pthread.h>

#pragma comment(lib, "ws2_32.lib")

#define MAX_THREADS 1000  // 最大线程数
#define TIMEOUT 100       // 超时时间（毫秒）

typedef struct {
    char ip[16];
    int port;
    int protocol; // 0 = TCP, 1 = UDP
} ScanTask;

typedef struct {
    int total_ports;
    int open_ports;
} ScanResult;

pthread_mutex_t result_mutex;  // 结果统计的互斥锁
ScanResult scan_result = {0, 0};

// 扫描 TCP 端口
void *scan_tcp_port(void *arg) {
    ScanTask *task = (ScanTask *)arg;
    SOCKET sock;
    struct sockaddr_in server;
    int result;

    // 创建 TCP 套接字
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "TCP socket creation failed.\n");
        pthread_exit(NULL);
    }

    // 设置非阻塞模式
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);

    server.sin_family = AF_INET;
    server.sin_port = htons(task->port);
    server.sin_addr.s_addr = inet_addr(task->ip);

    // 尝试连接
    connect(sock, (struct sockaddr *)&server, sizeof(server));

    // 使用 select 检查连接状态
    fd_set writefds;
    struct timeval tv;
    FD_ZERO(&writefds);
    FD_SET(sock, &writefds);

    tv.tv_sec = 0;
    tv.tv_usec = TIMEOUT * 1000;

    result = select(0, NULL, &writefds, NULL, &tv);

    pthread_mutex_lock(&result_mutex);
    scan_result.total_ports++;
    if (result > 0 && FD_ISSET(sock, &writefds)) {
        printf("[TCP] %s:%d is open.\n", task->ip, task->port);
        scan_result.open_ports++;
    }
    pthread_mutex_unlock(&result_mutex);

    closesocket(sock);
    free(task);
    pthread_exit(NULL);
}

// 扫描 UDP 端口
void *scan_udp_port(void *arg) {
    ScanTask *task = (ScanTask *)arg;
    SOCKET sock;
    struct sockaddr_in server;
    int result;
    char buffer[1024] = {0};
    char test_message[] = "UDP Test"; // 用于测试的消息

    // 创建 UDP 套接字
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "UDP socket creation failed.\n");
        pthread_exit(NULL);
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(task->port);
    server.sin_addr.s_addr = inet_addr(task->ip);

    // 发送测试消息
    sendto(sock, test_message, sizeof(test_message), 0, (struct sockaddr *)&server, sizeof(server));

    // 设置非阻塞模式
    fd_set readfds;
    struct timeval tv;
    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);

    tv.tv_sec = 0;
    tv.tv_usec = TIMEOUT * 1000;

    result = select(0, &readfds, NULL, NULL, &tv);

    pthread_mutex_lock(&result_mutex);
    scan_result.total_ports++;
    if (result > 0 && FD_ISSET(sock, &readfds)) {
        printf("[UDP] %s:%d is open.\n", task->ip, task->port);
        scan_result.open_ports++;
    }
    pthread_mutex_unlock(&result_mutex);

    closesocket(sock);
    free(task);
    pthread_exit(NULL);
}

void start_scan(const char *ip, int start_port, int end_port, int protocol) {
    pthread_t threads[MAX_THREADS];
    int thread_count = 0;

    for (int port = start_port; port <= end_port; ++port) {
        ScanTask *task = (ScanTask *)malloc(sizeof(ScanTask));
        if (!task) {
            fprintf(stderr, "Memory allocation failed.\n");
            break;
        }

        strncpy(task->ip, ip, 15);
        task->ip[15] = '\0';
        task->port = port;
        task->protocol = protocol;

        if (protocol == 0) { // TCP
            if (pthread_create(&threads[thread_count], NULL, scan_tcp_port, task) != 0) {
                fprintf(stderr, "TCP thread creation failed for port %d.\n", port);
                free(task);
                continue;
            }
        } else { // UDP
            if (pthread_create(&threads[thread_count], NULL, scan_udp_port, task) != 0) {
                fprintf(stderr, "UDP thread creation failed for port %d.\n", port);
                free(task);
                continue;
            }
        }

        thread_count++;

        // 限制线程数量
        if (thread_count >= MAX_THREADS) {
            for (int i = 0; i < thread_count; ++i) {
                pthread_join(threads[i], NULL);
            }
            thread_count = 0;
        }
    }

    // 等待所有线程结束
    for (int i = 0; i < thread_count; ++i) {
        pthread_join(threads[i], NULL);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        printf("Usage: %s <IP> <start_port> <end_port> <protocol (tcp/udp)>\n", argv[0]);
        return 1;
    }

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed.\n");
        return 1;
    }

    const char *ip = argv[1];
    int start_port = atoi(argv[2]);
    int end_port = atoi(argv[3]);
    const char *protocol = argv[4];

    if (start_port <= 0 || end_port <= 0 || start_port > end_port) {
        fprintf(stderr, "Invalid port range.\n");
        return 1;
    }

    if (strcmp(protocol, "tcp") == 0) {
        printf("Starting TCP scan on %s from port %d to %d...\n", ip, start_port, end_port);
        start_scan(ip, start_port, end_port, 0);
    } else if (strcmp(protocol, "udp") == 0) {
        printf("Starting UDP scan on %s from port %d to %d...\n", ip, start_port, end_port);
        start_scan(ip, start_port, end_port, 1);
    } else {
        fprintf(stderr, "Invalid protocol. Use 'tcp' or 'udp'.\n");
        return 1;
    }

    printf("\nScan completed.\n");
    printf("Scanned %d ports.\n", scan_result.total_ports);
    printf("%d ports are open.\n", scan_result.open_ports);

    WSACleanup();
    return 0;
}
