#include <stdio.h>  // 標準輸入輸出函式庫
#include <stdlib.h>  // 標準通用工具函式庫
#include <string.h>  // 字串操作函式庫
#include "variables.h"  // 定義變數
#include "sharedFunctions.h"  // 共用函式

// 按時間篩選載入日誌
void loadLogsByTime(const char *startTime, const char *endTime) {
    // 開啟檔案
    FILE *file = fopen("firewall.log", "r");
    if (!file) {
        printf(BLUE "Could not open firewall.log.\n" RESET);
        return;
    }

    char line[256];  // 常用來儲存一行文字，讀取最多255個字元，保留一個給"\0"
    while (fgets(line, sizeof(line), file)) {
        char logTime[20];
        sscanf(line, "%19s", logTime);

        // 確保搜尋結果介於指定的開始時間和結束時間之間
        if (strcmp(logTime, startTime) >= 0 && strcmp(logTime, endTime) <= 0) {
            printf("%s", line);
        }
    }

    // 關閉開啟的檔案
    fclose(file);
}

// 按時間篩選載入日誌
void loadLogsByRule(const char *ruleType) {
    FILE *file = fopen("firewall.log", "r");
    if (!file) {
        perror("Failed to open file");
        return;
    }

    char line[256];  // 常用來儲存一行文字，讀取最多255個字元，保留一個給"\0"
    while (fgets(line, sizeof(line), file)) {
        // 確保搜尋結果符合違反規則類型
        if (strcasestr(line, ruleType)) {  // 比對不區分大小寫
            printf("%s", line);
        }
    }

    // 關閉開啟的檔案
    fclose(file);
}

// 顯示查詢日誌選單
void viewLogsMenu() {
    int choice;
    char startTime[20], endTime[20], ruleType[20];

    while (1) {
        system("clear");
        printf("============================================================\n");
        printf("                         VIEWLOGS                           \n");
        printf("============================================================\n");
        printf(" You are now Firewall Log.                                  \n");
        printf(" Please choose a category to feature:                       \n");
        printf("------------------------------------------------------------\n");
        printf(YELLOW " [1] " RESET "Filter by Time Range\n");
        printf(YELLOW " [2] " RESET "Filter by Violate Rule Type\n");
        printf(YELLOW " [3] " RESET "Return to Main Menu\n");
        printf("============================================================\n");
        printf(ORANGE "Enter your choice: " RESET);
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                printf(ORANGE "Enter start time (YYYY-MM-DD HH:MM:SS): " RESET);
                scanf("%s", startTime);
                while (getchar() != '\n');  // 清除輸入緩衝區
                printf(ORANGE "Enter end time (YYYY-MM-DD HH:MM:SS): " RESET);
                scanf("%s", endTime);
                loadLogsByTime(startTime, endTime);
                printf("\n");
                halt();
                break;
            case 2:
                printf(ORANGE "Enter Violate Rule type (IP / TCPPORT / UDPPORT): " RESET);
                scanf("%s", ruleType);
                loadLogsByRule(ruleType);
                printf("\n");
                halt();
                break;
            case 3:
                return;
            default:
                printf(BLUE "Invalid option. Please try again.\n" RESET);
                halt();
        }
    }
}

// 查詢日誌
void viewLogs() {
    viewLogsMenu();
}