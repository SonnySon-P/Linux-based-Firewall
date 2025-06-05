#include <stdio.h>  // 標準輸入輸出函式庫
#include <stdlib.h>  // 標準通用工具函式庫
#include <string.h>  // 字串操作函式庫
#include "variables.h"  // 定義變數
#include "sharedFunctions.h"  // 共用函式
#include "manageBlocklist.h" // 管理封鎖名單

// 儲存封鎖列表
void saveBlocklist() {
    // 開啟檔案
    FILE *file = fopen("blocklist.conf", "w");
    if (file == NULL) {
        printf(BLUE "Could not open blocklist.conf.\n" RESET);
        return;
    }

    // 寫入ip封鎖名單
    for (int i = 0; i < ipNumber; i++) {
        if (ipBlocklist[i] != NULL) {
            fprintf(file, "IP:%s\n", ipBlocklist[i]);
        }
    }

    // 寫入tcp port封鎖名單
    for (int i = 0; i < tcpPortNumber; i++) {
        fprintf(file, "TCPPORT:%d\n", tcpPortBlocklist[i]);
    }

    // 寫入udp port封鎖名單
    for (int i = 0; i < udpPortNumber; i++) {
        fprintf(file, "UDPPORT:%d\n", udpPortBlocklist[i]);
    }

    // 關閉開啟的檔案
    fclose(file);
}

// 檢查udp port是否已經在ipBlocklist
int isUDPPortInBlocklist(int port) {
    for (int i = 0; i < udpPortNumber; i++) {
        if (udpPortBlocklist[i] == port) {
            return 1;  // udp port已經存在
        }
    }
    return 0;  // udp port不存在
}

// 檢查tcp port是否已經在ipBlocklist
int isTCPPortInBlocklist(int port) {
    for (int i = 0; i < tcpPortNumber; i++) {
        if (tcpPortBlocklist[i] == port) {
            return 1;  // tcp port已經存在
        }
    }
    return 0;  // tcp port不存在
}

// 檢查i[是否已經在ipBlocklist
int isIPInBlocklist(char* ip) {
    for (int i = 0; i < ipNumber; i++) {
        if (strcmp(ipBlocklist[i], ip) == 0) {
            return 1;  // ip已經存在
        }
    }
    return 0;  // ip不存在
}

// 檢查ip是否有效
int isIP(char *ip) {
    int number = 0;
    int dots = 0;
    char *ipSegment;
    
    if (ip == NULL) {
        printf("0\n");
        return 0;
    }

    // 以.分割字串，並檢查每個分段
    ipSegment = strtok(ip, ".");
    while (ipSegment) {
        // 檢查每個分段是否為數字
        if (sscanf(ipSegment, "%d", &number) != 1) {
            return 0;  // 不是數字
        }
        
        // 檢查數字是否在有效範圍0~255
        if (number < 0 || number > 255) {
            return 0;  // 不在範圍內
        }
        
        // 檢查第一個分段是否以0開頭並且數字不為0
        if (dots == 0 && number == 0) {
            return 0;  // 不符合規則
        }

        // 檢查是否以零開頭的數字
        if (number == 0 && strlen(ipSegment) > 1) {
            return 0;  // 不符合規則
        }
        
        // 計算.數量
        dots++;
        
        // 繼續分割字串
        ipSegment = strtok(NULL, ".");
    }

    // 是否有4個.
    if (dots != 4) {
        return 0;
    }
    
    return 1;  // 符合規則的IP
}

// 查看udp port封鎖列表
void viewUDPPortBlocklist() {
    system("clear");
    printf("============================================================\n");
    printf("                   VIEW UDPPORT BLOCKLIST                   \n");
    printf("============================================================\n");

    if (udpPortNumber == 0) {
        printf(BLUE "No UDP Ports are currently blocked.\n" RESET);
    } else {
        for (int i = 0; i < udpPortNumber; i++) {
            printf(" " YELLOW "[%d]" RESET " %d\n", i + 1, udpPortBlocklist[i]);
        }
    }

    printf("============================================================\n");
}

// 查看tcp port封鎖列表
void viewTCPPortBlocklist() {
    system("clear");
    printf("============================================================\n");
    printf("                   VIEW TCPPORT BLOCKLIST                   \n");
    printf("============================================================\n");

    if (tcpPortNumber == 0) {
        printf(BLUE "No TCP Ports are currently blocked.\n" RESET);
    } else {
        for (int i = 0; i < tcpPortNumber; i++) {
            printf(" " YELLOW "[%d]" RESET " %d\n", i + 1, tcpPortBlocklist[i]);
        }
    }

    printf("============================================================\n");
}

// 查看ip封鎖列表
void viewIPBlocklist() {
    system("clear");
    printf("============================================================\n");
    printf("                     VIEW IP BLOCKLIST                      \n");
    printf("============================================================\n");

    if (ipNumber == 0) {
        printf(BLUE "No IPs are currently blocked.\n" RESET);
    } else {
        for (int i = 0; i < ipNumber; i++) {
            printf(" " YELLOW "[%d]" RESET " %s\n", i + 1, ipBlocklist[i]);
        }
    }

    printf("============================================================\n");
}

// 從封鎖清單刪除udp port
void removeUDPPortFromBlocklist() {
    if (udpPortNumber == 0) {
        printf(BLUE "UDP Port Blocklist is empty. Nothing to remove.\n" RESET);
        halt();
        return;
    }

    viewUDPPortBlocklist();
    
    int index;
    printf(ORANGE "Enter the number of the UDP Port to remove: " RESET);
    scanf("%d", &index);

    if (index < 1 || index > udpPortNumber) {
        printf(BLUE "Invalid selection.\n" RESET);
    } else {
        for (int i = index - 1; i < udpPortNumber - 1; i++) {
            udpPortBlocklist[i] = udpPortBlocklist[i + 1];
        }
        udpPortNumber--;
        printf(BLUE "UDP Port removed from blocklist.\n" RESET);
    }

    saveBlocklist();

    halt();
}

// 從封鎖清單刪除tcp port
void removeTCPPortFromBlocklist() {
    if (tcpPortNumber == 0) {
        printf(BLUE "TCP Port Blocklist is empty. Nothing to remove.\n" RESET);
        halt();
        return;
    }

    viewTCPPortBlocklist();
    
    int index;
    printf(ORANGE "Enter the number of the TCP Port to remove: " RESET);
    scanf("%d", &index);

    if (index < 1 || index > tcpPortNumber) {
        printf(BLUE "Invalid selection.\n" RESET);
    } else {
        for (int i = index - 1; i < tcpPortNumber - 1; i++) {
            tcpPortBlocklist[i] = tcpPortBlocklist[i + 1];
        }
        tcpPortNumber--;
        printf(BLUE "TCP Port removed from blocklist.\n" RESET);
    }

    saveBlocklist();

    halt();
}

// 從封鎖清單刪除ip
void removeIPFromBlocklist() {
    if (ipNumber == 0) {
        printf(BLUE "IP Blocklist is empty. Nothing to remove.\n" RESET);
        halt();
        return;
    }

    viewIPBlocklist();
    
    int index;
    printf(ORANGE "Enter the number of the IP to remove: " RESET);
    scanf("%d", &index);

    if (index < 1 || index > ipNumber) {
        printf(BLUE "Invalid selection.\n" RESET);
    } else {
        for (int i = index - 1; i < ipNumber - 1; i++) {
            strcpy(ipBlocklist[i], ipBlocklist[i + 1]);
        }
        ipNumber--;
        printf(BLUE "IP removed from blocklist.\n" RESET);
    }

    saveBlocklist();

    halt();
}

// 新增udp port至封鎖列表
void addUDPPortToBlocklist() {
    if (udpPortNumber >= MAX_RULES) {
        printf(BLUE "Blocklist is full. Cannot add more UDP Ports.\n" RESET);
        halt();
        return;
    }

    // 輸入port
    int port;
    printf(ORANGE "Enter UDP Port to block (range: 0~65535): " RESET);
    scanf("%d", &port);

    // 檢查port是否在有效範圍內
    if (port < 0 || port > 65535) {
        printf(BLUE "Invalid UDP Port number! It must be between 0 and 65535.\n" RESET);
        halt();
        return;
    }

    // 檢查port是否已經在udpPortBlocklist
    if (isUDPPortInBlocklist(port)) {
        printf(BLUE "This UDP Port is already in the blocklist.\n" RESET);
        halt();
        return;
    }

    // 將port加入到udpPortBlocklist
    udpPortBlocklist[udpPortNumber] = port;
    udpPortNumber++;

    // 儲存更新過的blocklist
    saveBlocklist();

    // 提示訊息
    printf(BLUE "UDP Port added to blocklist.\n" RESET);
    halt();
}

// 新增tcp port至封鎖列表
void addTCPPortToBlocklist() {
    if (tcpPortNumber >= MAX_RULES) {
        printf(BLUE "Blocklist is full. Cannot add more TCP Ports.\n" RESET);
        halt();
        return;
    }

    // 輸入port
    int port;
    printf(ORANGE "Enter TCP Port to block (range: 0~65535): " RESET);
    scanf("%d", &port);

    // 檢查port是否在有效範圍內
    if (port < 0 || port > 65535) {
        printf(BLUE "Invalid TCP Port number! It must be between 0 and 65535.\n" RESET);
        halt();
        return;
    }

    // 檢查port是否已經在tcpPortBlocklist
    if (isTCPPortInBlocklist(port)) {
        printf(BLUE "This TCP Port is already in the blocklist.\n" RESET);
        halt();
        return;
    }

    // 將port加入到tcpPortBlocklist
    tcpPortBlocklist[tcpPortNumber] = port;
    tcpPortNumber++;

    // 儲存更新過的blocklist
    saveBlocklist();

    // 提示訊息
    printf(BLUE "TCP Port added to blocklist.\n" RESET);
    halt();
}

// 新增ip至封鎖列表
void addIPToBlocklist() {
    if (ipNumber >= MAX_RULES) {
        printf(BLUE "Blocklist is full. Cannot add more IPs.\n" RESET);
        halt();
        return;
    }

    // 輸入ip
    char ip[16];
    printf(ORANGE "Enter IP to block (format: xxx.xxx.xxx.xxx): " RESET);
    scanf("%15s", ip);

    // 檢查ip是否有效
    if (!isIP(strdup(ip))) {
        printf(BLUE "Invalid IP address.\n" RESET);
        halt();
        return;
    }

    // 檢查ip是否已經在ipBlocklist
    if (isIPInBlocklist(ip)) {
        printf(BLUE "This IP is already in the blocklist.\n" RESET);
        halt();
        return;
    }

    // 將ip加入到ipBlocklist
    ipBlocklist[ipNumber] = malloc(16);  // 分配16bytes給這個IP
    strcpy(ipBlocklist[ipNumber], ip);  // 儲存IP
    ipNumber++;

    // 儲存更新過的blocklist
    saveBlocklist();

    // 提示訊息
    printf(BLUE "IP added to blocklist.\n" RESET);
    halt();
}

// 管理udp port封鎖名單
void manageUDPPortBlocklistMenu() {
    int choice;

    while (1) {
        system("clear");
        printf("============================================================\n");
        printf("                 MANAGE UDPPORT BLOCKLIST                   \n");
        printf("============================================================\n");
        printf(" You are now managing the UDP Port Blocklist.               \n");
        printf(" Please choose a category to feature:                       \n");
        printf("------------------------------------------------------------\n");
        printf(YELLOW " [1] " RESET "View UDP Port Blocklist\n");
        printf(YELLOW " [2] " RESET "Add UDP Port to Blocklist\n");
        printf(YELLOW " [3] " RESET "Remove UDP Port from Blocklist\n");
        printf(YELLOW " [4] " RESET "Return to Blocklist Management Menu\n");
        printf("============================================================\n");
        printf(ORANGE "Enter your choice: " RESET);
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                viewUDPPortBlocklist();
                halt();
                break;
            case 2:
                addUDPPortToBlocklist();
                break;
            case 3:
                removeUDPPortFromBlocklist();
                break;
            case 4:
                return;
            default:
                printf("\nInvalid option. Please try again.\n");
                halt();
        }
    }
}

// 管理tcp port封鎖名單
void manageTCPPortBlocklistMenu() {
    int choice;

    while (1) {
        system("clear");
        printf("============================================================\n");
        printf("                 MANAGE TCPPORT BLOCKLIST                   \n");
        printf("============================================================\n");
        printf(" You are now managing the TCP Port Blocklist.               \n");
        printf(" Please choose a category to feature:                       \n");
        printf("------------------------------------------------------------\n");
        printf(YELLOW " [1] " RESET "View TCP Port Blocklist\n");
        printf(YELLOW " [2] " RESET "Add TCP Port to Blocklist\n");
        printf(YELLOW " [3] " RESET "Remove TCP Port from Blocklist\n");
        printf(YELLOW " [4] " RESET "Return to Blocklist Management Menu\n");
        printf("============================================================\n");
        printf(ORANGE "Enter your choice: " RESET);
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                viewTCPPortBlocklist();
                halt();
                break;
            case 2:
                addTCPPortToBlocklist();
                break;
            case 3:
                removeTCPPortFromBlocklist();
                break;
            case 4:
                return;
            default:
                printf("\nInvalid option. Please try again.\n");
                halt();
        }
    }
}

// 管理ip封鎖名單
void manageIPBlocklistMenu() {
    int choice;

    while (1) {
        system("clear");
        printf("============================================================\n");
        printf("                    MANAGE IP BLOCKLIST                     \n");
        printf("============================================================\n");
        printf(" You are now managing the IP Blocklist.                     \n");
        printf(" Please choose a category to feature:                       \n");
        printf("------------------------------------------------------------\n");
        printf(YELLOW " [1] " RESET "View IP Blocklist\n");
        printf(YELLOW " [2] " RESET "Add IP to Blocklist\n");
        printf(YELLOW " [3] " RESET "Remove IP from Blocklist\n");
        printf(YELLOW " [4] " RESET "Return to Blocklist Management Menu\n");
        printf("============================================================\n");
        printf(ORANGE "Enter your choice: " RESET);
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                viewIPBlocklist();
                halt();
                break;
            case 2:
                addIPToBlocklist();
                break;
            case 3:
                removeIPFromBlocklist();
                break;
            case 4:
                return;
            default:
                printf("\nInvalid option. Please try again.\n");
                halt();
        }
    }
}

// 管理封鎖名單
void manageBlocklistMenu() {
    int subChoice;

    while (1) {
        system("clear");
        printf("============================================================\n");
        printf("                BLOCKLIST MANAGEMENT MODULE                 \n");
        printf("============================================================\n");
        printf(" You are now in the Blocklist Management Module.            \n");
        printf(" Please choose a category to feature:                       \n");
        printf("------------------------------------------------------------\n");
        printf(YELLOW " [1] " RESET "Manage IP Blocklist\n");
        printf(YELLOW " [2] " RESET "Manage TCP Port Blocklist\n");
        printf(YELLOW " [3] " RESET "Manage UDP Port Blocklist\n");
        printf(YELLOW " [4] " RESET "Return to Main Menu\n");
        printf("============================================================\n");
        printf(ORANGE "Enter your choice: " RESET);
        scanf("%d", &subChoice);

        switch (subChoice) {
            case 1:
                manageIPBlocklistMenu();
                break;
            case 2:
                manageTCPPortBlocklistMenu();
                break;
            case 3:
                manageUDPPortBlocklistMenu();
                break;
            case 4:
                return;  // 返回主選單
            default:
                printf(BLUE "Invalid option. Please try again.\n" RESET);
                halt();
                break;
        }
    }
}