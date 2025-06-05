#ifndef VARIABLES_H  // 如果VARIABLES_H沒有被定義過
#define VARIABLES_H  // 定義VARIABLES_H

// 定義顏色字串常數
#define CYAN "\x1b[0;36m"
#define GREEN "\x1b[0;32m"
#define LIGHTGREEN "\x1b[1;32m"
#define WHITE "\x1b[0;37m"
#define RED "\x1b[0;31m"
#define YELLOW "\x1b[0;33m"
#define BLUE "\x1b[0;34m"
#define PURPLE "\x1b[0;35m"
#define ORANGE "\x1b[38;5;166m"
#define RESET "\x1b[0m"

// 定義最多規則數量常數
#define MAX_RULES 100

// 定義全域變數
extern char *ipBlocklist[MAX_RULES];  // 封鎖的 IP 名單
extern int tcpPortBlocklist[MAX_RULES];  // 封鎖的 TCP port 名單
extern int udpPortBlocklist[MAX_RULES];  // 封鎖的 UDP port 名單
extern int ipNumber;  // 封鎖的 IP 數量
extern int tcpPortNumber;  // 封鎖的 TCP port 數量
extern int udpPortNumber;  // 封鎖的 UDP port 數量

#endif