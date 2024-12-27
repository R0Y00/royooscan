#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <pthread.h>
#include <stdint.h>

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

// 解析 CIDR 表达式为 IP 范围
void parse_cidr(const char *cidr, char **ips, int *ip_count) {
    unsigned int ip, mask, start, end;
    sscanf(cidr, "%d.%d.%d.%d/%d",
           (int *)&((uint8_t *)&ip)[0],
           (int *)&((uint8_t *)&ip)[1],
           (int *)&((uint8_t *)&ip)[2],
           (int *)&((uint8_t *)&ip)[3],
           (int *)&mask);

    ip = ntohl(ip); // 转换为主机字节序
    mask = (1 << (32 - mask)) - 1;
    start = ip & ~mask;
    end = ip | mask;

    *ip_count = 0;
    for (unsigned int addr = start; addr <= end; addr++) {
        struct in_addr in;
        in.s_addr = htonl(addr);
        strncpy(ips[*ip_count], inet_ntoa(in), 15);
        ips[*ip_count][15] = '\0';
        (*ip_count)++;
    }
}

// 解析范围 IP 表达式
void parse_ip_range(const char *ip_range, char **ips, int *ip_count) {
    char start_ip[16], end_ip[16];
    unsigned int start[4], end[4];
    *ip_count = 0;

    if (strchr(ip_range, '-') != NULL) {
        sscanf(ip_range, "%15[^-]-%15s", start_ip, end_ip);
        sscanf(start_ip, "%u.%u.%u.%u", &start[0], &start[1], &start[2], &start[3]);
        sscanf(end_ip, "%u.%u.%u.%u", &end[0], &end[1], &end[2], &end[3]);

        for (unsigned int a = start[0]; a <= end[0]; a++) {
            for (unsigned int b = start[1]; b <= end[1]; b++) {
                for (unsigned int c = start[2]; c <= end[2]; c++) {
                    for (unsigned int d = start[3]; d <= end[3]; d++) {
                        sprintf(ips[*ip_count], "%u.%u.%u.%u", a, b, c, d);
                        (*ip_count)++;
                    }
                }
            }
        }
    } else if (strchr(ip_range, '/') != NULL) {
        parse_cidr(ip_range, ips, ip_count);
    } else {
        strncpy(ips[*ip_count], ip_range, 15);
        ips[*ip_count][15] = '\0';
        (*ip_count)++;
    }
}

// 扫描 TCP 端口
void *scan_tcp_port(void *arg) {
    ScanTask *task = (ScanTask *)arg;
    SOCKET sock;
    struct sockaddr_in server;
    int result;

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        pthread_exit(NULL);
    }

    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);

    server.sin_family = AF_INET;
    server.sin_port = htons(task->port);
    server.sin_addr.s_addr = inet_addr(task->ip);

    connect(sock, (struct sockaddr *)&server, sizeof(server));

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
    char test_message[] = "UDP Test";

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        pthread_exit(NULL);
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(task->port);
    server.sin_addr.s_addr = inet_addr(task->ip);

    sendto(sock, test_message, sizeof(test_message), 0, (struct sockaddr *)&server, sizeof(server));

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
            break;
        }

        strncpy(task->ip, ip, 15);
        task->ip[15] = '\0';
        task->port = port;
        task->protocol = protocol;

        if (protocol == 0) {
            pthread_create(&threads[thread_count], NULL, scan_tcp_port, task);
        } else {
            pthread_create(&threads[thread_count], NULL, scan_udp_port, task);
        }

        thread_count++;
        if (thread_count >= MAX_THREADS) {
            for (int i = 0; i < thread_count; ++i) {
                pthread_join(threads[i], NULL);
            }
            thread_count = 0;
        }
    }

    for (int i = 0; i < thread_count; ++i) {
        pthread_join(threads[i], NULL);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        printf("Usage: %s <IP or range> <start_port> <end_port> <protocol (tcp/udp)>\n", argv[0]);
        return 1;
    }

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return 1;
    }

    const char *ip_range = argv[1];
    int start_port = atoi(argv[2]);
    int end_port = atoi(argv[3]);
    const char *protocol = argv[4];

    char *ips[65536];
    for (int i = 0; i < 65536; i++) {
        ips[i] = (char *)malloc(16);
    }
    int ip_count = 0;
    parse_ip_range(ip_range, ips, &ip_count);

    int protocol_flag = strcmp(protocol, "udp") == 0 ? 1 : 0;
    for (int i = 0; i < ip_count; i++) {
        start_scan(ips[i], start_port, end_port, protocol_flag);
    }

    for (int i = 0; i < 65536; i++) {
        free(ips[i]);
    }

    WSACleanup();
    return 0;
}
