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
pip install requests
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

## 许可证

MIT License
