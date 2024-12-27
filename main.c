#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <pthread.h>
#include <time.h>
#include <stdint.h>
#include <math.h>

#pragma comment(lib, "ws2_32.lib")

#define MAX_THREADS 1000  // 最大线程数
#define TIMEOUT 100       // 连接超时时间（毫秒）

typedef struct {
    char ip[16];
    int port;
} ScanTask;

typedef struct {
    int total_ports;
    int open_ports;
} ScanResult;

pthread_mutex_t result_mutex;  // 结果统计的互斥锁
ScanResult scan_result = {0, 0};

void *scan_port(void *arg) {
    ScanTask *task = (ScanTask *)arg;
    SOCKET sock;
    struct sockaddr_in server;
    int result;

    // 创建套接字
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "Socket creation failed.\n");
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
        printf("[+] %s:%d is open.\n", task->ip, task->port);
        scan_result.open_ports++;
    }
    pthread_mutex_unlock(&result_mutex);

    closesocket(sock);
    free(task);
    pthread_exit(NULL);
}

void start_scan(const char *ip, int start_port, int end_port) {
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

        if (pthread_create(&threads[thread_count], NULL, scan_port, task) != 0) {
            fprintf(stderr, "Thread creation failed for port %d.\n", port);
            free(task);
            continue;
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

void parse_ip_range(const char *ip_range, char **ips, int *ip_count) {
    char start_ip[16], end_ip[16];
    unsigned int start[4], end[4];
    *ip_count = 0;

    if (strchr(ip_range, '-') != NULL) {
        // IP 范围（如 192.168.1.1-192.168.1.10）
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
        // CIDR 表达式
        parse_cidr(ip_range, ips, ip_count);
    } else {
        // 单个 IP
        strncpy(ips[*ip_count], ip_range, 15);
        ips[*ip_count][15] = '\0';
        (*ip_count)++;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Usage: %s <IP or range> <start_port> <end_port>\n", argv[0]);
        return 1;
    }

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed.\n");
        return 1;
    }

    const char *ip_range = argv[1];
    int start_port = atoi(argv[2]);
    int end_port = atoi(argv[3]);

    if (start_port <= 0 || end_port <= 0 || start_port > end_port) {
        fprintf(stderr, "Invalid port range.\n");
        return 1;
    }

    // 解析 IP 范围
    char *ips[65536];
    for (int i = 0; i < 65536; i++) {
        ips[i] = (char *)malloc(16 * sizeof(char));
    }
    int ip_count = 0;
    parse_ip_range(ip_range, ips, &ip_count);

    // 开始计时
    clock_t start_time = clock();

    // 扫描每个 IP
    for (int i = 0; i < ip_count; i++) {
        start_scan(ips[i], start_port, end_port);
    }

    // 结束计时
    clock_t end_time = clock();
    double total_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;

    printf("\nScan completed.\n");
    printf("Scanned %d ports across %d IPs in %.2f seconds.\n", scan_result.total_ports, ip_count, total_time);
    printf("%d ports are open.\n", scan_result.open_ports);

    for (int i = 0; i < 65536; i++) {
        free(ips[i]);
    }

    WSACleanup();
    return 0;
}
