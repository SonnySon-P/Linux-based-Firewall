# Linux based Firewall

自製一套基於Linux核心的防火牆，可以有效阻擋惡意IP跟Port。

## 壹、基本說明
**動機：**
隨著近期RISC-V處理器市佔率的穩步提升，我一直希望能深入了解這項技術。回顧過去在學習計算機組織與結構課程時，曾經接觸過另一種精簡指令集架構-MIPS，因此我決定藉由開發一個RISC-V組合語言模擬器，來快速掌握不同指令集的結構與用途。

**目的：**
此程式基於RV32I指令集進行開發(不包含虛擬指令集)，可以通過讀取組合語言檔案(.asm)，執行數位邏輯運算，幫助我深入理解RISC-V指令集的各種細節。

**開發環境：**
* 虛擬機：VirtualBox
* 作業系統：Ubuntu 22.04
* 程式語言：C
* 程式編輯器：Visual Studio Code

**檔案說明：**
```bash
.
├── LICENSE
├── README.md
└──  Firewall  # 開發程式資料夾
      ├── main.c  # 主程式
      ├── variables.h  # 定義變數
      ├── sharedFunctions.h  # 共用函式
      ├── sharedFunctions.c  # 共用函式
      ├── manageBlocklist.h  # 管理封鎖名單
      ├── manageBlocklist.c  # 管理封鎖名單
      ├── executeFirewall.h  # 執行防火牆
      ├── executeFirewall.c  # 執行防火牆
      ├── viewLogs.h  # 查詢日誌
      ├── viewLogs.c  # 查詢日誌
      ├── blocklist.conf  # 封鎖名單
      ├── firewall.log  # 日誌
      └── firewall  # Unix執行檔
```

## 貳、設計概念
本程式設計具體流程如下：會使用NFQUEUE，是Linux Netfilter提供的一個機制，可讓封包轉交給程式進一步處理方式。當封包加入佇列後，開發者撰寫的程式可以檢查、修改或決定是否丟棄封包。

## 參、運行方式
**運行方式：**
* 安裝套件
```shell
sudo apt update
sudo apt update
sudo apt install build-essential
sudo apt install linux-headers-$(uname -r)
sudo apt install libnetfilter-queue-dev
sudo apt install libnfnetlink-dev
```
* 將進入主機的封包導入到Netfilter Queue
```shell
sudo iptables -I INPUT -j NFQUEUE --queue-num 0
```
* 編譯程式
```shell
gcc -D_GNU_SOURCE -o firewall main.c manageBlocklist.c executeFirewall.c sharedFunctions.c viewLogs.c -lnetfilter_queue
```
* 運行程式
```shell
sudo ./firewall
```
* 清空所有的iptables規則
```shell
sudo iptables -F
```
> [!Warning]
> 請特別注意，若有執行"sudo iptables -I INPUT -j NFQUEUE --queue-num 0"，記得事後需要執行"sudo iptables -F"，否則網路連線可能會發生異常。
