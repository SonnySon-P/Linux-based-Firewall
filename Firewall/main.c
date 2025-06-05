#include <stdio.h>  // 標準輸入輸出函式庫
#include <stdlib.h>  // 標準通用工具函式庫
#include <string.h>  // 字串操作函式庫
#include "variables.h"  // 定義變數
#include "sharedFunctions.h"  // 共用函式
#include "manageBlocklist.h" // 管理封鎖名單
#include "executeFirewall.h" // 執行防火牆
#include "viewLogs.h" // 查詢日誌

// 變數宣告
char *ipBlocklist[MAX_RULES];  // 封鎖的ip名單
int tcpPortBlocklist[MAX_RULES];  // 封鎖的tcp port名單
int udpPortBlocklist[MAX_RULES];  // 封鎖的udp port名單
int ipNumber = 0;  // 封鎖的ip數量
int tcpPortNumber = 0;  // 封鎖的tcp port數量
int udpPortNumber = 0;  // 封鎖的udp port數量


// 顯示主選單
void showMainMenu() {
    int subChoice;

    while (1) {
        system("clear");  // 清除終端機顯示內容
        printf(RED);
        printf("              ______ _       __          __   _ _  \n");
        printf("             |  ____(_)      \\ \\        / /  | | | \n");
        printf("             | |__   _ _ __ __\\ \\  /\\  / /_ _| | | \n");
        printf("             |  __| | | '__/ _ \\ \\/  \\/ / _` | | | \n");
        printf("             | |    | | | |  __/\\  /\\  / (_| | | | \n");
        printf("             |_|    |_|_|  \\___| \\/  \\/ \\__,_|_|_| \n");
        printf("\n");
        printf(GREEN);
        printf("                                     ~ By SonnySon \n");
        printf(RESET);
        printf("\n");
        printf("\n");
        printf("============================================================\n");
        printf("                  FIREWALL MANAGEMENT SYSTEM                \n");
        printf("------------------------------------------------------------\n");
        printf(" Welcome to the Firewall Management System.                 \n");
        printf(" Please choose a category to feature:                       \n");
        printf("------------------------------------------------------------\n");
        printf(YELLOW " [1] " RESET "Manage Blocklist\n");
        printf(YELLOW " [2] " RESET "Execute Firewall Rules\n");
        printf(YELLOW " [3] " RESET "View Logs\n");
        printf(YELLOW " [4] " RESET "Exit Program\n");
        printf("============================================================\n");
        printf(ORANGE "Enter your choice: " RESET);
        scanf("%d", &subChoice);

        switch (subChoice) {
            case 1:
                manageBlocklistMenu();
                break;
            case 2:
                executeFirewallMenu();
                break;
            case 3:
                viewLogs();
                break;
            case 4:
                printf(BLUE "Exiting program. Goodbye!\n" RESET);
                exit(0);
            default:
                printf(BLUE "Invalid option. Please try again.\n" RESET);
                halt();
        }
    }
}

// 載入封鎖名單
void loadBlocklist() {
    // 開啟檔案
    FILE *file = fopen("blocklist.conf", "r");
    if (!file) {
        printf(BLUE "Could not open blocklist.conf.\n" RESET);
        return;
    }

    char line[128];  // 常用來儲存一行文字，讀取最多127個字元，保留一個給"\0"
    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = 0;  // 去除換行字元
        if (strncmp(line, "IP:", 3) == 0) {
            ipBlocklist[ipNumber++] = strdup(line + 3);  // 將line字串中從第3個字元開始，轉換為對應的字串（分配一塊新的記憶體，然後將參數字串複製進去，並傳回這個新記憶體的指標）
        } else if (strncmp(line, "TCPPORT:", 8) == 0) {
            tcpPortBlocklist[tcpPortNumber++] = atoi(line + 8);  // 將line字串中從第8個字元開始，轉換為對應的整數
        } else if (strncmp(line, "UDPPORT:", 8) == 0) {
            udpPortBlocklist[udpPortNumber++] = atoi(line + 8);
        }
    }

    // 關閉開啟的檔案
    fclose(file);
}

// 主程式
int main() {
    loadBlocklist();  // 載入封鎖名單
    showMainMenu();  // 顯示主選單
    return 0;
}