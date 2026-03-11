# AD Security Validation Labs

本專案旨在提供 Active Directory (AD) 安全攻防驗證的標準化流程與指南。所有測試均基於真實 Lab 環境驗證，並針對 EDR (Endpoint Detection and Response) 系統的偵測能力進行深度分析。

## 包含文件

### 1. [DCSync 攻擊與 Golden Ticket 驗證指南](DCSync_Attack_Validation_README.md)
詳細說明如何重現 DCSync 攻擊並驗證 AD 防護機制。

**核心亮點：**
- **攻擊原理深度解析**：剖析 DRSUAPI 協定與 Mimikatz 工具行為。
- **偵測盲點揭露**：證實 Mimikatz 不會觸發 Event 4928/4929，打破常見偵測迷思。
- **黃金偵測指標**：確立 **Event 4662 + 複寫 GUID** 為唯一可靠的偵測特徵。
- **完整攻擊鏈路**：涵蓋從權限確認、Hash 提取到 Golden Ticket 偽造的全流程。

## 適用對象
- 資安分析師 (SOC Analyst)
- 滲透測試人員 (Red Team)
- 系統管理員 (System Admin)

## 重要聲明
本專案提供的資訊僅供授權的安全測試與教育用途。請勿在未經授權的生產環境中執行任何攻擊指令。
