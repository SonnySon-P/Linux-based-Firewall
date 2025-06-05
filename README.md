# Linux-based-Firewall

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

**相依套件：**
```bash

```

**檔案說明：**
```bash
.
├── LICENSE
├── README.md
└──  code  # 開發程式資料夾
      ├── main.py  # 主程式
      ├── readFile.py  # 讀取組語模組
      ├── RV32IMemory.py  # 模擬memory模組
      ├── RV32IRegisters.py  # 模擬register模組
      ├── cpuCore.py  # 模擬CPU模組
      ├── instructionTyple.py  # instruction與Typle的對應模組
      ├── rType.py  # 模擬R-Type instruction運行模組
      ├── iType.py  # 模擬I-Type instruction運行模組
      ├── sType.py  # 模擬S-Type instruction運行模組
      ├── bType.py  # 模擬B-Type instruction運行模組
      ├── uType.py  # 模擬U-Type instruction運行模組
      ├── jType.py  # 模擬J-Type instruction運行模組
      ├── otherType.py  # 模擬ecall instruction運行模組
      └── try.asm  # 測試檔案
```

## 貳、設計概念
本程式設計可以分為以下幾個步驟，具體流程如下：
* 讀取.asm
* 組合語言正規化，提取語法
* 存入memory
* 運行instruction
  * 解析該instruction所屬哪種Type
  * 針對不同Type，提取不同參數
  * 針對該instruction，進行存取register、邏輯運算、轉跳...等操作

## 參、運行方式
**運行方式：** 請開啟終端機，並進入存放該檔案資料夾，執行以下指令進行模擬
```shell
python main.py try.asm
```
> [!Warning]
> 請特別注意，由於我在解讀RISC-V手冊時對於ecall系統調用號碼的理解尚不完全，因此目前實作中僅涵蓋了基本的讀取、寫入與關閉等功能。如果系統調用號碼有所錯誤，還請多多包涵。另外，對於某些指令，我直接以十進位進行處理，這樣的做法可能會導致本應使用二進位格式運算的結果有所偏差，尤其在不同位數下的計算結果可能會有所不同。敬請理解。
