# XSSProbe — XSS Vulnerability Detection Tool

一个用 Go 编写的 XSS 漏洞检测工具，支持静态分析、动态验证、WAF 识别与绕过、SPA 渲染等能力。

> **Disclaimer**: 本工具仅供合法安全测试和授权渗透测试使用。使用者需遵守当地法律法规，未经授权对目标系统进行扫描属于违法行为。

## 功能特性

### 核心检测能力

| 功能 | 说明 |
|------|------|
| **静态分析** | 40+ Source + 50+ Sink 模式匹配，跨行污点追踪 |
| **反射型动态验证** | chromedp 注入 payload，确认漏洞可利用 |
| **存储型 XSS 检测** | 自动填表提交 + 刷新检查持久化 |
| **结合分析模式** | 静态 + 动态结合，大幅降低误报率 |
| **上下文感知** | 检测注入点上下文（HTML/属性/JS/URL/CSS），选择最匹配的 payload |
| **过滤函数识别** | 识别 7 类过滤/消毒模式（URL 编码、HTML 编码、DOMPurify、CSP 等） |

### 自动化能力

| 功能 | 说明 |
|------|------|
| **SPA 渲染** | chromedp 渲染 Vue/React/Angular 等 SPA 应用 |
| **自动爬虫** | 站内页面自动发现，支持深度和数量限制 |
| **参数自动发现** | 从 HTML 表单、URL、JavaScript 中自动提取参数 |
| **WAF 自动识别** | 指纹识别 7 种主流 WAF（Cloudflare/AWS/ModSecurity/Akamai/Imperva/Sucuri/F5） |
| **Payload 库** | 137 个内置 payload，支持 WAF 绕过编码变体 |
| **自定义 Payload** | 支持单个 payload 字符串或文件批量加载 |

### 安全合规

| 功能 | 说明 |
|------|------|
| **域名范围锁定** | `-scope` 限制扫描范围，防止越界 |
| **速率限制** | 令牌桶限速器，上限 100 req/s，防止对目标造成压力 |
| **robots.txt 遵守** | 默认遵守爬虫规则 |
| **审计日志** | JSON 格式记录所有请求，`-verify`/`-stored`/`-crawl` 自动启用 |
| **法律声明** | 首次运行强制确认，`-yes` 必须配合 `-scope` 使用 |
| **Stored XSS 默认 DryRun** | `-stored` 默认不提交数据，需显式 `-dry-run=false` 才写入 |
| **危险 Payload 标记** | 数据外泄类 payload 标记为 `Dangerous`，默认排除，使用占位符域名 |
| **清理提醒** | 存储型测试完成后自动提示清理测试数据 |

## 安装

### 下载预编译二进制（推荐）

从 [Releases](https://github.com/Meco30701X/xssprobe/releases) 页面下载对应平台的二进制文件：

| 平台 | 文件 |
|------|------|
| Windows x64 | `xssprobe-windows-amd64.exe` |
| Linux x64 | `xssprobe-linux-amd64` |
| Linux ARM64 | `xssprobe-linux-arm64` |
| macOS Intel | `xssprobe-darwin-amd64` |
| macOS Apple Silicon | `xssprobe-darwin-arm64` |

```bash
# Linux/macOS
chmod +x xssprobe-linux-amd64
./xssprobe-linux-amd64 -u https://target.com

# Windows
.\xssprobe-windows-amd64.exe -u https://target.com
```

> 不需要安装 Go，下载即用。动态验证功能需要系统已安装 Chrome/Chromium。

### 从源码编译

```bash
git clone https://github.com/Meco30701X/xssprobe.git
cd xssprobe
go build -o xssprobe .
./xssprobe -u https://target.com
```

### 环境要求

- **Chrome/Chromium**（`-verify`、`-stored`、`-spa`、`-crawl` 功能需要）
  - Linux: `apt install chromium-browser`
  - Windows/macOS: 通常已安装 Chrome
- 纯静态分析（`-u` 不加验证标志）不需要 Chrome

## 使用方法

### 基础扫描

```bash
# 静态分析（最快，仅模式匹配）
./xssprobe -u https://target.com

# 反射型动态验证（推荐）
./xssprobe -u https://target.com -verify

# 存储型 XSS 检测
./xssprobe -u https://target.com -stored -dry-run

# SPA 渲染模式
./xssprobe -u https://target.com -spa

# 自动爬虫扫描
./xssprobe -u https://target.com -crawl -max-pages 100
```

### 结合分析模式（推荐，低误报）

```bash
# 静态 + 动态结合分析
./xssprobe -u https://target.com -analyze

# 限制动态验证数量
./xssprobe -u https://target.com -analyze -max-verify 5

# 跳过已过滤的发现
./xssprobe -u https://target.com -analyze -skip-filtered
```

### 参数发现

```bash
# 自动发现参数（默认开启）
./xssprobe -u https://target.com -verify

# 手动指定参数
./xssprobe -u https://target.com -verify -param "id,name,email"

# 加上常用参数 wordlist
./xssprobe -u https://target.com -verify -wordlist
```

### WAF 识别与绕过

```bash
# 自动检测 WAF（默认开启）
./xssprobe -u https://target.com -verify

# 手动指定 WAF
./xssprobe -u https://target.com -verify -waf cloudflare

# 关闭 WAF 自动检测
./xssprobe -u https://target.com -verify -auto-waf=false
```

### 自定义 Payload

```bash
# 单个 payload
./xssprobe -u https://target.com -verify -payload "<script>alert(1)</script>"

# 从文件加载 payload（每行一个）
./xssprobe -u https://target.com -verify -payloads custom_payloads.txt

# 合并自定义 + 内置 payload
./xssprobe -u https://target.com -verify -payloads custom.txt -payload-merge

# 优先测试自定义 payload
./xssprobe -u https://target.com -verify -payloads custom.txt -payload-first
```

### 合规扫描

```bash
# 限定域名 + 限速 + 审计日志
./xssprobe -u https://target.com -scope target.com -rate 2 -audit audit.log

# CI/CD 自动化（跳过法律确认）
./xssprobe -u https://target.com -scope target.com -yes
```

### 批量扫描

```bash
# 从文件读取 URL
./xssprobe -l urls.txt -threads 10

# Stdin 管道（BETA）
cat urls.txt | ./xssprobe -verify
```

### 带认证扫描

```bash
# Cookie
./xssprobe -u https://target.com -cookie "session=abc; token=xyz"

# 自定义 Header
./xssprobe -u https://target.com -H "Authorization: Bearer xxx"
```

### 输出

```bash
# JSON 导出
./xssprobe -u https://target.com -o result.json
```

## CLI 参数一览

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-u` | 目标 URL | — |
| `-l` | URL 文件路径 | — |
| `-f` | 本地 JS 文件 | — |
| `-o` | JSON 输出路径 | — |
| `-verify` | 启用反射型动态验证 | false |
| `-stored` | 启用存储型 XSS 检测 | false |
| `-spa` | SPA 渲染模式 | false |
| `-crawl` | 自动爬虫 | false |
| `-max-pages` | 最大爬取页数 | 50 |
| `-max-depth` | 最大爬取深度 | 3 |
| `-analyze` | 静态+动态结合分析 | false |
| `-max-verify` | 最大动态验证数 | 10 |
| `-skip-filtered` | 跳过已过滤发现 | false |
| `-cookie` | Cookie 字符串 | — |
| `-H` | 自定义 Header（可重复） | — |
| `-waf` | 指定 WAF 类型 | auto |
| `-auto-waf` | 自动检测 WAF | true |
| `-param` | 手动指定参数 | — |
| `-mine` | 自动发现参数 | true |
| `-wordlist` | 添加常用参数字典 | false |
| `-payload` | 自定义 payload 字符串 | — |
| `-payloads` | 自定义 payload 文件 | — |
| `-payload-merge` | 合并自定义与内置 payload | true |
| `-payload-first` | 优先测试自定义 payload | true |
| `-scope` | 域名范围锁定 | — |
| `-rate` | 每秒最大请求数 | 2 |
| `-audit` | 审计日志路径 | — |
| `-respect-robots` | 遵守 robots.txt | true |
| `-threads` | 批量扫描并发数 | 5 |
| `-wait` | SPA 渲染等待时间（秒） | 5 |
| `-dry-run` | 干运行模式 | false |
| `-safe` | 仅使用安全 payload | false |
| `-confirm` | 每次提交前确认 | false |
| `-yes` | 跳过法律确认 | false |

## 检测原理

### 静态分析

从页面/JS 中提取源码，通过正则匹配 Source（数据来源）和 Sink（危险操作），结合跨行污点追踪判断是否存在潜在的 DOM XSS：

```
Source: location.hash → var hash → var data → Sink: innerHTML
```

### 动态验证

使用 chromedp 无头浏览器加载页面，注入带有唯一标识符的 payload，通过以下方式验证：

- **Hash/Query 模式**: payload 注入 URL hash 或 query 参数，检查是否在 DOM 中反射
- **Canary 探测**: 发送探测字符串，分析反射位置和上下文
- **存储型**: 填写表单提交 → 刷新页面 → 检查 payload 是否持久化

### 上下文感知

检测注入点所在位置，选择最优 payload：

| 上下文 | 说明 | 选择策略 |
|--------|------|----------|
| HTML | 直接插入 HTML | `<script>` 标签 |
| Attribute | 在标签属性中 | `" onmouseover=...` |
| JS String | 在 JS 字符串中 | `';alert(1)//` |
| JS Code | 在 JS 代码中 | 直接注入 |
| URL | 在 URL 中 | `javascript:...` |
| CSS | 在样式中 | `expression(...)` |

## 项目结构

```
xssprobe/
├── main.go              # CLI 入口
├── scanner/
│   └── scanner.go       # 静态分析引擎
├── fetcher/
│   ├── fetcher.go       # HTTP 抓取
│   └── spa.go           # chromedp SPA 渲染
├── verifier/
│   └── verifier.go      # 动态验证引擎
├── analyzer/
│   └── analyzer.go      # 结合分析模块
├── context/
│   └── context.go       # 上下文感知
├── miner/
│   └── miner.go         # 参数自动发现
├── waf/
│   └── waf.go           # WAF 检测
├── compliance/          # 安全合规模块
│   ├── compliance.go
│   ├── scope.go
│   ├── ratelimit.go
│   ├── robots.go
│   ├── audit.go
│   └── legal.go
├── spider/
│   └── spider.go        # 自动爬虫
├── payloads/
│   └── payloads.go      # Payload 库
├── safety/
│   └── safety.go        # 安全机制
└── report/
    └── report.go        # 输出格式化
```

## 测试

```bash
# 运行所有测试
go test ./...

# 运行指定模块测试
go test ./scanner/...
go test ./compliance/...
go test ./waf/...
```

## License

[MIT License](LICENSE)

本项目仅供合法安全研究和授权测试使用。使用者需遵守当地法律法规。

## Author

**Meco30701X**
