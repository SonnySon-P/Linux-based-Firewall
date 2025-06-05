#include <stdio.h>  // 標準輸入輸出函式庫
#include "variables.h"  // 定義變數

void halt() {
    int c;

    // 顯示提示訊息
    printf(CYAN "Press Enter to continue..." RESET);
    fflush(stdout);  // 確保訊息立即輸出

    // 清空輸入緩衝區
    while ((c = getchar()) != '\n' && c != EOF);

    // 等待Enter
    c = getchar();
    while (c != '\n' && c != EOF) {
        c = getchar();
    }
}