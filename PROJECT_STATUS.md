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
├── main.go              # CLI 入口 (15KB)
├── scanner/
│   └── scanner.go       # 静态分析: Source/Sink 模式匹配 + 跨行污点追踪
├── fetcher/
│   ├── fetcher.go       # HTTP 抓取页面、提取 JS
│   └── spa.go           # chromedp 渲染 SPA 页面、提取动态脚本
├── verifier/
│   └── verifier.go      # 动态验证: 反射型 + 存储型 XSS (chromedp)
├── crawler/
│   └── crawler.go       # 页面输入点检测 (表单、textarea、contenteditable)
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

## ⚠️ 当前编译错误

**问题**: `spider/spider.go` 第7行导入了 `"regexp"` 但未使用。

**修复方法**: 删除 `spider/spider.go` 第7行的 `"regexp"` 导入。

```go
// 当前 (错误):
import (
    "context"
    "fmt"
    "net/url"
    "regexp"     // ← 删除这行
    "strings"
    ...
)

// 修复后:
import (
    "context"
    "fmt"
    "net/url"
    "strings"
    ...
)
```

## 未提交的变更
- `main.go` 已修改 (添加了 spider 集成、-crawl/-max-pages/-max-depth 参数)
- `spider/` 目录未跟踪 (新的自动爬虫模块)

修复编译错误后需要:
```bash
cd /home/domxss
git add -A
git commit -m "feat: auto-crawler for site-wide scanning"
git push
```

## 环境注意事项
- Go 在 `/usr/local/go/bin/go`，需要 `export PATH=/usr/local/go/bin:$PATH`
- ⚠️ **每次 Bash 调用 CWD 会重置为 `/root/claude-workspace`**，必须用 `cd /home/domxss &&` 前缀
- 测试服务器用 Python 起在 localhost 不同端口 (9996-9999)
- GitHub 用 gh CLI 登录，账号 Meco30701X

## 功能用法速查
```bash
./domxss -u URL                          # 静态分析
./domxss -u URL -verify                  # 反射型验证
./domxss -u URL -stored -dry-run         # 存储型 (最安全)
./domxss -u URL -stored -safe -confirm   # 存储型 (安全payload+确认)
./domxss -u URL -spa                     # SPA 渲染模式
./domxss -u URL -crawl -max-pages 100    # 自动爬虫扫描
./domxss -u URL -verify -waf cloudflare  # WAF 绕过
./domxss -l urls.txt -threads 10         # 批量扫描
./domxss -u URL -cookie "k=v" -H "K: V" # 带认证
./domxss -u URL -o result.json           # JSON 导出
```

## 下一步建议
- 修复 spider.go 编译错误并提交
- HTML 报告输出
- README 文档 (GitHub 展示)
- 单元测试
- Docker 镜像
