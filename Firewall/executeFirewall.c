#include <stdio.h>  // 標準輸入輸出函式庫
#include <stdlib.h>  // 標準通用工具函式庫
#include <string.h>  // 字串操作函式庫
#include <time.h>  // 時間相關函式與結構定義
#include <unistd.h>  // 提供操作系統底層函式庫
#include <termios.h> // 檢測是否有鍵盤輸入
#include "variables.h"  // 定義變數
#include "sharedFunctions.h"  // 共用函式
#include <netinet/ether.h>  // 對應MAC地址解析
#include <netinet/ip.h>  // IP協定相關結構定義
#include <netinet/tcp.h>  // TCP協定相關結構定義
#include <netinet/udp.h>  // UDP協定相關結構定義
#include <arpa/inet.h>  // 網路地址轉換函式庫
#include <linux/netfilter.h>  // Linux Netfilter的一些常數和資料結構
#include <libnetfilter_queue/libnetfilter_queue.h>  // Linux Netfilter queue函式庫

// 設定terminal為非阻塞模式
void setNonblockingMode(struct termios *oldTio) {
    struct termios newTio;
    tcgetattr(STDIN_FILENO, oldTio); // 保存原本的terminal設定
    newTio = *oldTio;
    newTio.c_lflag &= ~(ICANON | ECHO); // 關閉行緩衝和回顯
    newTio.c_cc[VMIN] = 0;
    newTio.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &newTio); // 設定新的terminal狀態
}

// 恢復原本的terminal設定
void restoreMode(struct termios *oldTio) {
    tcsetattr(STDIN_FILENO, TCSANOW, oldTio);
}

// 將封鎖記錄寫入日誌
void saveLogs(const char *violateRule, const char *mac, const char *sourceIP, const char *dstinationIP, const int packetLength, const char *protocolType, const int dstinationPort) {
    time_t now;
    struct tm *timeInfo;
    char timeString[20];  // "YYYY-MM-DD HH:MM:SS"長度為19+'\0'
    time(&now);  // 取得目前時間
    timeInfo = localtime(&now);  // 轉換為本地時間
    strftime(timeString, sizeof(timeString), "%Y-%m-%d %H:%M:%S", timeInfo);

    // 開啟檔案
    FILE *file = fopen("firewall.log", "a");
    if (file) {
        // 寫入的檔案
        fprintf(file, "%s VIOLATE_RULE=%s SOURCE_MAC=%s SOURCE_IP=%s DSTINATION_IP=%s PACKET_LENGTH=%d PROTOCOL=%s DSTINATION_PORT=%d\n", timeString, violateRule, mac, sourceIP, dstinationIP, packetLength, protocolType, dstinationPort);

        // 關閉開啟的檔案
        fclose(file);
    }
}

// 檢查udp port是否被列入封鎖清單
int checkUDPPort(int port) {
    for (int i = 0; i < udpPortNumber; i++) {
        if (udpPortBlocklist[i] == port) return 1;
    }

    return 0;
}

// 檢查tcp port是否被列入封鎖清單
int checkTCPPort(int port) {
    for (int i = 0; i < tcpPortNumber; i++) {
        if (tcpPortBlocklist[i] == port) return 1;
    }

    return 0;
}

// 檢查來源IP是否在封鎖清單中
int checkIP(char *ip) {
    for (int i = 0; i < ipNumber; i++) {
        if (strcmp(ip, ipBlocklist[i]) == 0) return 1;
    }

    return 0;
}

// 處理封包的callback函數，當有封包進入queue時會被呼叫
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    unsigned char *packet;  // 指向封包資料的指標
    int id = 0;  // 封包的識別碼 (packet ID)，用於設定處理結果

    // 從封包資料中取得封包標頭（packet header）
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph -> packet_id);  // 若成功取得封包標頭，就取出封包的識別碼，並轉換為主機位元組序
    }

    // 取得封包內容長度
    int packetLength = nfq_get_payload(nfa, &packet);

    // 確認payload存在
    if (packetLength >= 0) {  
        struct iphdr *ip = (struct iphdr *)packet;  // 將封包payload視為IP標頭
        
        // 取得來源mac
        struct ether_header *eth = (struct ether_header *)packet;
        char macString[18];
        snprintf(macString, sizeof(macString),
            "%02x:%02x:%02x:%02x:%02x:%02x",
            eth -> ether_shost[0],
            eth -> ether_shost[1],
            eth -> ether_shost[2],
            eth -> ether_shost[3],
            eth -> ether_shost[4],
            eth -> ether_shost[5]);

        // 取得ip
        uint32_t sourceIP = ip -> saddr;  // 來源ip位址
        uint32_t dstinationIP = ip -> daddr;  // 目的ip位址
        char sourceIPString[INET_ADDRSTRLEN];  // 用來儲存IP的字串形式
        char dstinationIPString[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(sourceIP), sourceIPString, INET_ADDRSTRLEN);  // 將IP轉換為字串
        inet_ntop(AF_INET, &(dstinationIP), dstinationIPString, INET_ADDRSTRLEN);

        // 取得目的port
        char protocolType[4];
        int dstinationPort;
        if (ip -> protocol == IPPROTO_TCP) {  // 封包中的protocol欄位是TCP
            strcpy(protocolType, "TCP");
            struct tcphdr *tcp = (struct tcphdr *)(packet + ip -> ihl * 4);  // 計算TCP標頭位置
            dstinationPort = ntohs(tcp -> dest);  // 取得目的port
        } else if (ip -> protocol == IPPROTO_UDP) {  // 封包中的protocol欄位是UDP
            strcpy(protocolType, "UDP");
            struct udphdr *udp = (struct udphdr *)(packet + ip -> ihl * 4);  // 計算UDP標頭位置
            dstinationPort = ntohs(udp -> dest);  // 取得目的port
        }

        // 檢查來源IP是否在封鎖清單中
        if (checkIP(sourceIPString)) {
            saveLogs("IP", macString, sourceIPString, dstinationIPString, packetLength, protocolType, dstinationPort);  // 紀錄封鎖的IP
            return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);  // 丟棄這個封包
        }

        // 檢查Port是否在封鎖清單中
        if (strcmp(protocolType, "TCP") == 0) {
            if (checkTCPPort(dstinationPort)) {
                saveLogs("TCPPORT", macString, sourceIPString, dstinationIPString, packetLength, protocolType, dstinationPort);  // 紀錄封鎖的IP
                return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);  // 丟棄這個封包
            }
        } else if (strcmp(protocolType, "UDP") == 0) {
            if (checkUDPPort(dstinationPort)) {
                saveLogs("UDPPORT", macString, sourceIPString, dstinationIPString, packetLength, protocolType, dstinationPort);
                return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
            }
        }

    }

    // 若沒有符合封鎖條件，就允許此封包通過
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

// 啟動防火牆
void startFirewall() {
    // 變數宣告
    struct nfq_handle *h;  // 處理網路封包的隊列
    struct nfq_q_handle *qh;  // 代表和管理Netfilter Queue中的隊列
    int fileDescriptor;
    int receive;
    char buffer[4096] __attribute__((aligned));

    // 設定終端為非阻塞模式
    struct termios oldTio;
    setNonblockingMode(&oldTio);

    // 嘗試Netfilter Queue
    h = nfq_open();
    if (!h) {
        printf(BLUE "Could not open NFQUEUE.\n" RESET);
        restoreMode(&oldTio);  // 恢復終端設定
        return;
    }

    // 將Netfilter Queue綁定到IPv4，並進行錯誤處理
    if (nfq_unbind_pf(h, AF_INET) < 0 || nfq_bind_pf(h, AF_INET) < 0) {
        printf(BLUE "Failed to bind NFQUEUE to IPv4 protocol.\n" RESET);
        restoreMode(&oldTio);  // 恢復終端設定
        return;
    }

    // 創建一個NFQUEUE queue
    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) {
        printf(BLUE "Failed to create NFQUEUE queue.\n" RESET);
        restoreMode(&oldTio);  // 恢復終端設定
        return;
    }

    // 設定NFQUEUE的模式為COPY_PACKET模式，0xffff表示最大長度的封包都會被複製到使用者空間進行處理
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        printf(BLUE "Could not set packet copy mode.\n" RESET);
        nfq_destroy_queue(qh);
        nfq_close(h);
        restoreMode(&oldTio);  // 恢復終端設定
        return;
    }

    // 取得NFQUEUE處理器的檔案描述符，可用來讀取封包資料
    fileDescriptor = nfq_fd(h);

    // 顯示訊息提示使用者防火牆已啟動，並說明如何停止
    printf(GREEN "Firewall started. Press option " LIGHTGREEN "ESC " GREEN "to stop.\n" RESET);

    while (1) {
        char ch;
        if (read(STDIN_FILENO, &ch, 1) > 0) {  // 讀取鍵盤輸入
            if (ch == 27) {  // 27是ESC鍵的ASCII值
                break;
            }
        }

        // 使用recv()從NFQUEUE的socket中接收封包資料並存到buffer
        receive = recv(fileDescriptor, buffer, sizeof(buffer), 0);

        // 如果有成功接收到封包，就交由nfq_handle_packet()解析與處理封包
        if (receive >= 0) {
            nfq_handle_packet(h, buffer, receive);
        } else {
            printf(RED "Receive failed.\n" RESET);
            halt();
            break;
        }
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
    restoreMode(&oldTio);  // 恢復終端設定
    printf(RED "Firewall stopped.\n" RESET);
    halt();
    return;
}

// 執行防火牆選單
void executeFirewallMenu() {
    int subChoice;

    while (1) {
        system("clear");
        printf("============================================================\n");
        printf("               FIREWALL MANAGEMENT MODULE                   \n");
        printf("============================================================\n");
        printf(" You are now in the Firewall Management Module.             \n");
        printf(" Please choose a category to feature:                       \n");
        printf("------------------------------------------------------------\n");
        printf(YELLOW " [1] " RESET "Start Firewall\n");
        printf(YELLOW " [2] " RESET "Return to Main Menu\n");
        printf("============================================================\n");
        printf(ORANGE "Enter your choice: " RESET);
        scanf("%d", &subChoice);

        switch (subChoice) {
            case 1:
                startFirewall();
                break;
            case 2:
                return;
            default:
                printf(BLUE "Invalid option. Please try again.\n" RESET);
                halt();
                break;
        }
    }
}