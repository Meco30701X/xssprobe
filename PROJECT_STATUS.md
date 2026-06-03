# DOMXSS 项目状态总结

## 基本信息
- **仓库**: https://github.com/Meco30701X/domxss (私有)
- **语言**: Go (go 1.26, 需要 `/usr/local/go/bin/go`)
- **目录**: `/home/domxss/`
- **依赖**: chromedp (headless Chrome)
- **作者**: Meco30701X

## 项目结构
```
/home/domxss/
├── main.go              # CLI 入口
├── scanner/
│   └── scanner.go       # 静态分析: Source/Sink 模式匹配 + 跨行污点追踪
├── fetcher/
│   ├── fetcher.go       # HTTP 抓取页面、提取 JS
│   └── spa.go           # chromedp 渲染 SPA 页面、提取动态脚本
├── verifier/
│   └── verifier.go      # 动态验证: 反射型 + 存储型 XSS (chromedp)
├── compliance/          # 安全合规模块 (NEW)
│   ├── compliance.go    # 合规上下文主模块
│   ├── scope.go         # 域名范围锁定
│   ├── ratelimit.go     # 令牌桶限速器
│   ├── robots.go        # robots.txt 解析
│   ├── audit.go         # 审计日志 (JSON)
│   └── legal.go         # 合法使用确认
├── spider/
│   └── spider.go        # 自动爬虫 (发现站内页面)
├── payloads/
│   └── payloads.go      # Payload 库 (137个): 基础 + WAF绕过 + 编码变体
├── safety/
│   └── safety.go        # 安全机制: dry-run、safe payload、确认提示
├── report/
│   └── report.go        # 输出: 终端彩色 + JSON
├── go.mod / go.sum
└── .gitignore
```

## 已完成功能 (已推送到 GitHub main 分支)
1. **静态分析** — Source/Sink 模式匹配 (9种Source + 10种Sink)
2. **跨行污点追踪** — 变量赋值链追踪 (source → var1 → var2 → sink)
3. **反射型动态验证** — chromedp 注入 payload 确认 (hash/query)
4. **存储型 XSS 检测** — 自动填表提交 + 刷新检查持久化
5. **认证支持** — `-cookie` / `-H` 自定义 header
6. **Payload 库** — 137个 payload, WAF 绕过 (cloudflare/aws/modsec/generic)
7. **批量扫描** — `-l urls.txt -threads N`
8. **SPA 支持** — `-spa` chromedp 渲染, 自动检测 Vue/React/Angular
9. **安全机制** — `-dry-run` / `-safe` / `-confirm`
10. **自动爬虫** — `-crawl` chromedp 站内页面发现
11. **安全合规机制**
    - **域名范围锁定** — `-scope target.com` 限制扫描范围
    - **速率限制** — `-rate N` 令牌桶限速 (默认 2 req/s)
    - **robots.txt** — `-respect-robots` 遵守爬虫规则 (默认开启)
    - **审计日志** — `-audit audit.log` JSON 格式记录所有请求
    - **法律声明** — 首次运行强制确认, `-yes` 跳过 (CI/CD)
12. **结合分析模式** — `-analyze` 静态+动态结合, 降低误报
13. **过滤函数识别** — 识别 7 类过滤/消毒模式:
    - URL 编码 (encodeURIComponent, encodeURI, escape)
    - HTML 编码 (htmlEncode, HTML entities)
    - 消毒库 (DOMPurify, bleach, jsoup)
    - 安全 DOM 方法 (innerText, textContent)
    - 正则过滤 (replace patterns)
    - 白名单验证 (whitelist, allowlist)
    - CSP 指标 (CSP, nonce, strict-dynamic)
14. **参数自动发现** (NEW) — `-mine` 自动发现测试参数:
    - HTML 表单 (input/select/textarea name)
    - URL 参数 (链接中的查询参数)
    - JavaScript (URLSearchParams, getParameter)
    - 100+ 常用参数名 wordlist
    - `-param "id,name"` 手动指定参数

## 编译状态
✅ 编译通过, 无错误

## 环境注意事项
- Go 在 `/usr/local/go/bin/go`，需要 `export PATH=/usr/local/go/bin:$PATH`
- ⚠️ **每次 Bash 调用 CWD 会重置为 `/root/claude-workspace`**，必须用 `cd /home/domxss &&` 前缀
- 测试服务器用 Python 起在 localhost 不同端口 (9996-9999)
- GitHub 用 gh CLI 登录，账号 Meco30701X

## 功能用法速查
```bash
# 基础扫描
./domxss -u URL                          # 静态分析
./domxss -u URL -verify                  # 反射型验证
./domxss -u URL -stored -dry-run         # 存储型 (最安全)
./domxss -u URL -spa                     # SPA 渲染模式
./domxss -u URL -crawl -max-pages 100    # 自动爬虫扫描

# 结合分析 (推荐, 降低误报)
./domxss -u URL -analyze                 # 静态+动态结合分析
./domxss -u URL -analyze -max-verify 5   # 限制动态验证数量
./domxss -u URL -analyze -skip-filtered  # 跳过已过滤的发现

# 参数发现 + 验证
./domxss -u URL -verify                  # 自动发现参数 + 验证
./domxss -u URL -verify -param "id,name" # 手动指定参数
./domxss -u URL -verify -wordlist        # 加上常用参数 wordlist

# 合规扫描
./domxss -u URL -scope target.com -rate 2 -audit audit.log
./domxss -u URL -scope target.com -respect-robots -yes  # CI/CD

# 高级用法
./domxss -u URL -verify -waf cloudflare  # WAF 绕过
./domxss -l urls.txt -threads 10         # 批量扫描
./domxss -u URL -cookie "k=v" -H "K: V" # 带认证
./domxss -u URL -o result.json           # JSON 导出
```

## 下一步建议
- HTML 报告输出
- README 文档 (GitHub 展示)
- 单元测试
- Docker 镜像
- CI/CD 集成示例
