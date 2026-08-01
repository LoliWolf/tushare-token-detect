# Tushare Token 积分检测器

一个用于检测 Tushare Token 积分等级的工具，通过调用不同权限级别的 API 接口来评估 Token 的积分下限。

## 功能特性

- 自动探测 Token 的积分等级
- 支持多种 input.json 格式
- 支持历史结果缓存，增量更新
- 原子写入，避免数据丢失
- 友好的命令行输出日志

## 安装依赖

```bash
pip install -r requirements.txt
```

## 使用方法

### 1. 准备输入文件

创建 `input.json` 文件，支持两种格式：

**格式一：简单数组**
```json
["token1", "token2", "token3"]
```

**格式二：对象格式**
```json
{
  "tokens": ["token1", "token2", "token3"]
}
```

### 2. 运行检测

```bash
python detect.py
```

### 3. 查看结果

检测完成后，结果会写入 `tushare_token_scores.json` 文件：

```json
{
  "token1": 120,
  "token2": 5000,
  "token3": 10000
}
```

### 命令行参数

```bash
# 指定输入文件
python detect.py --input my_tokens.json

# 指定输出文件
python detect.py --output results.json

# 同时指定输入输出
python detect.py --input tokens.json --output scores.json
```

## 检测原理

工具通过调用一系列不同积分要求的 Tushare API 接口来评估 Token 的积分等级：

| 积分要求 | API 接口 | 说明 |
|---------|----------|------|
| 120 | `daily` | 日线行情（基础权限） |
| 600 | `cn_gdp` | 中国 GDP 数据 |
| 2000 | `weekly` | 周线行情 |
| 3000 | `share_float` | 限售股解禁 |
| 4000 | `index_dailybasic` | 指数每日指标 |
| 5000 | `fund_adj` | 基金复权因子 |
| 6000 | `stk_nineturn` | 九转序列 |
| 10000 | `hm_detail` | 沪深港通资金明细 |

Token 的积分等级为其成功调用的 API 所需的最高积分值。

## 输出文件说明

- **input.json** - 输入的 Token 列表文件
- **tushare_token_scores.json** - 检测结果文件（包含历史记录）

## 注意事项

1. 检测过程中会有 0.8 秒的请求间隔，避免触发频率限制
2. 如果 Token 无效，检测会立即终止并返回 0 分
3. 如果遇到频率超限，该 API 会被跳过
4. 历史结果会被保留，取历次检测的最高分

## 示例输出

```
读取输入文件：input.json
输入 token 数：3
读取历史文件：tushare_token_scores.json
历史 token 数：0

[1/3] probing token=xxxxxxxxxxxxxxxx
[历史分数] 0
[通过] >= 120    api=daily
[通过] >= 600    api=cn_gdp
[权限不足] <  2000   api=weekly msg=xxx
[本次分数] 600
[最终分数] max(0, 600) = 600
[已更新文件] tushare_token_scores.json
```

## GitHub 防泄漏审计

`github_audit.py` 在 **GitHub 全站公开仓库** 中搜索疑似硬编码的 Tushare Token。对搜索结果，先按仓库 owner 匹配本地白名单（支持精确用户名和正则），匹配的仓库才下载文件进行本地检测。

搜索会组合 `tushare`、`TUSHARE_TOKEN`、`TS_TOKEN`、`ts.set_token` 和 `ts.pro_api` 等特征；本地检测覆盖 `TUSHARE_ACCESS_TOKEN`、`tushareApiKey`、`TS_API_TOKEN` 以及上下文中的通用 `token` 赋值。

> 注意：扫描到的 Token **原始值会被记录在输出 JSON 中**（`raw_token` 字段），用于统一回收清理。请妥善保管输出文件，用完即删。

### 1. 配置白名单

复制示例文件并填写允许扫描的 GitHub 用户名或组织。支持精确用户名和 `/正则/` 两种写法：

```bash
cp github_user_allowlist.example.json github_user_allowlist.json
```

```json
{
  "users": [
    "your-github-user",
    "/^my-org.*$/"
  ]
}
```

`github_user_allowlist.json` 已加入 `.gitignore`。

### 2. 配置环境变量

```bash
export GITHUB_TOKEN="你的 GitHub Token"
```

使用任意能调用公开 Code Search API 的 GitHub Token 即可（Classic token 或 Fine-grained token），不需要仓库写权限。

### 3. 运行审计

```bash
python github_audit.py
```

指定白名单和输出位置：

```bash
python github_audit.py \
  --allowlist github_user_allowlist.json \
  --output github_tushare_findings.json
```

其他参数：

- `--max-pages`：每个查询最多读取的搜索结果页数，1-10，默认 10
- `--search-interval`：相邻搜索请求的最小秒数，默认 6.2（避开 GitHub 搜索限流）
- `--fail-on-findings`：发现疑似泄漏时返回退出码 `1`，适合 CI

输出示例：

```json
{
  "schema_version": 1,
  "scanned_at": "2026-08-01T01:00:00Z",
  "repositories_scanned": 3,
  "total_results": 20,
  "skipped_results": 15,
  "scan_incomplete": false,
  "findings": [
    {
      "repository": "your-github-user/example",
      "path": "config.py",
      "line": 12,
      "url": "https://github.com/your-github-user/example/blob/main/config.py#L12",
      "detector": "named_constant",
      "fingerprint": "sha256:0123456789abcdef01234567",
      "raw_token": "实际扫描到的 Token 值"
    }
  ]
}
```

GitHub Code Search 只覆盖默认分支以及小于 384 KB 的可搜索文件，每次搜索最多返回 1,000 项。若 GitHub 返回不完整结果或文件无法读取，输出中的 `scan_incomplete` 会设为 `true`，进程返回退出码 `3`。检测结果是待人工确认的疑似泄漏，不能当作 Token 有效性结论。

> 不要把审计结果接入 `detect.py`。发现泄漏后应立即撤销/轮换对应 Token，并清理 Git 历史。

## 许可证

MIT License
