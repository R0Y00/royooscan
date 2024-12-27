### README

---

## 中文版

### 项目简介

本项目是一个高性能的端口扫描器，使用 **C语言** 编写，支持多种 IP 表达式，包括单个 IP、IP 范围和 CIDR 表达式（如 `192.168.1.0/24`）。该工具利用多线程和非阻塞套接字技术实现了高效、快速的端口扫描。适用于需要快速检测目标主机开放端口的场景。

### 功能特点
1. **多种 IP 表达式支持**：
    - 单个 IP（如 `192.168.1.1`）。
    - IP 范围（如 `192.168.1.1-192.168.1.10`）。
    - CIDR 表达式（如 `192.168.1.0/24`）。
2. **高性能**：
    - 使用多线程加速扫描，支持高并发。
    - 非阻塞 I/O，减少连接超时时间。
3. **扫描统计**：
    - 输出总端口数、开放端口数、扫描耗时及 IP 数量。
4. **跨平台支持**：
    - 基于 Windows 系统的 Winsock API。

### 使用说明

#### 1. 编译
在 Windows 系统上，使用支持 `pthread` 的 GCC 工具链（如 MinGW-w64）编译代码：
```bash
gcc -o royooscan.exe fast_scanner.c -lws2_32 -lpthread
```

#### 2. 运行
运行程序时，输入 IP 表达式、起始端口和结束端口。例如：
```bash
royooscan.exe <IP或范围> <起始端口> <结束端口>
```

**示例**：
```bash
royooscan.exe 192.168.1.0/24 1 100
```

#### 3. 输出示例
```plaintext
Starting scan on 192.168.1.0/24 from port 1 to 100...
[+] 192.168.1.1:22 is open.
[+] 192.168.1.2:80 is open.

Scan completed.
Scanned 25600 ports across 256 IPs in 5.25 seconds.
2 ports are open.
```

#### 4. 参数说明
- `<IP或范围>`：支持以下格式：
    - 单个 IP（如 `192.168.1.1`）。
    - IP 范围（如 `192.168.1.1-192.168.1.10`）。
    - CIDR 表达式（如 `192.168.1.0/24`）。
- `<起始端口>`：扫描起始端口（1-65535）。
- `<结束端口>`：扫描结束端口（1-65535）。


---

## English Version

### Project Overview

This project is a high-performance port scanner written in **C language**. It supports multiple IP address formats, including single IPs, IP ranges, and CIDR expressions (e.g., `192.168.1.0/24`). The scanner leverages multi-threading and non-blocking socket techniques to achieve efficient and fast port scanning. It is suitable for scenarios requiring quick detection of open ports on target hosts.

### Features
1. **Support for Multiple IP Formats**:
    - Single IP (e.g., `192.168.1.1`).
    - IP range (e.g., `192.168.1.1-192.168.1.10`).
    - CIDR expression (e.g., `192.168.1.0/24`).
2. **High Performance**:
    - Accelerated scanning with multi-threading and high concurrency.
    - Non-blocking I/O to reduce connection timeout delays.
3. **Scan Statistics**:
    - Outputs the total number of ports, open ports, scan duration, and IP count.
4. **Cross-Platform Support**:
    - Designed for Windows systems using Winsock API.

### Usage Instructions

#### 1. Compilation
On Windows, use a GCC toolchain that supports `pthread` (e.g., MinGW-w64) to compile the code:
```bash
gcc -o royooscan.exe fast_scanner.c -lws2_32 -lpthread
```

#### 2. Execution
Run the program with the IP expression, starting port, and ending port as arguments. For example:
```bash
royooscan.exe <IP or range> <start_port> <end_port>
```

**Example**:
```bash
royooscan.exe 192.168.1.0/24 1 100
```

#### 3. Output Example
```plaintext
Starting scan on 192.168.1.0/24 from port 1 to 100...
[+] 192.168.1.1:22 is open.
[+] 192.168.1.2:80 is open.

Scan completed.
Scanned 25600 ports across 256 IPs in 5.25 seconds.
2 ports are open.
```

#### 4. Parameter Details
- `<IP or range>`: Supports the following formats:
    - Single IP (e.g., `192.168.1.1`).
    - IP range (e.g., `192.168.1.1-192.168.1.10`).
    - CIDR expression (e.g., `192.168.1.0/24`).
- `<start_port>`: Starting port to scan (1-65535).
- `<end_port>`: Ending port to scan (1-65535).


---

### License
This project is released under the **MIT License**. You are free to use, modify, and distribute this software. Ensure compliance with applicable laws when using this tool.
