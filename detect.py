#!/usr/bin/env python3
# detect.py
#
# 用法：
#   pip install requests
#   python detect.py
#
# 指定并发：
#   python detect.py --workers 10
#
# 默认读取：
#   input.json
#
# 默认输出：
#   tushare_token_scores.json
#
# 输出格式：
#   {
#     "token1": 5000,
#     "token2": 120,
#     "token3": 0
#   }

import argparse
import json
import os
import sys
import time
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

API_URL = "http://api.tushare.pro"

DEFAULT_INPUT_FILE = "input.json"
DEFAULT_OUTPUT_FILE = "tushare_token_scores.json"

REQUEST_SLEEP = 0.8
DEFAULT_WORKERS = 10

log_lock = threading.Lock()


PROBES = [
    {
        "score": 120,
        "api_name": "daily",
        "params": {
            "ts_code": "000001.SZ",
            "start_date": "20240102",
            "end_date": "20240102",
        },
        "fields": "ts_code,trade_date,close",
    },
    {
        "score": 600,
        "api_name": "cn_gdp",
        "params": {
            "start_q": "2023Q1",
            "end_q": "2023Q1",
        },
        "fields": "quarter,gdp,gdp_yoy",
    },
    {
        "score": 2000,
        "api_name": "weekly",
        "params": {
            "ts_code": "000001.SZ",
            "start_date": "20240101",
            "end_date": "20240131",
        },
        "fields": "ts_code,trade_date,close",
    },
    {
        "score": 3000,
        "api_name": "share_float",
        "params": {
            "ts_code": "000001.SZ",
        },
        "fields": "ts_code,ann_date,float_date,float_share",
    },
    {
        "score": 4000,
        "api_name": "index_dailybasic",
        "params": {
            "ts_code": "000001.SH",
            "trade_date": "20240102",
        },
        "fields": "ts_code,trade_date,turnover_rate,pe",
    },
    {
        "score": 5000,
        "api_name": "fund_adj",
        "params": {
            "ts_code": "510300.SH",
            "start_date": "20240101",
            "end_date": "20240131",
        },
        "fields": "ts_code,trade_date,adj_factor",
    },
    {
        "score": 6000,
        "api_name": "stk_nineturn",
        "params": {
            "ts_code": "000001.SZ",
            "freq": "daily",
            "start_date": "20250101",
            "end_date": "20250131",
        },
        "fields": "ts_code,trade_date,freq,up_count,down_count",
    },
    {
        "score": 10000,
        "api_name": "hm_detail",
        "params": {
            "trade_date": "20230815",
        },
        "fields": "trade_date,ts_code,ts_name,buy_amount,sell_amount,net_amount,hm_name",
    },
]


def log(*args):
    with log_lock:
        print(*args, file=sys.stderr)


def mask_token(token: str) -> str:
    token = token.strip()
    if len(token) <= 12:
        return token[:3] + "***"
    return token[:6] + "..." + token[-6:]


def load_input_tokens(path: str):
    if not os.path.exists(path):
        raise FileNotFoundError(f"input 文件不存在：{path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # 支持：
    # 1. ["token1", "token2"]
    # 2. {"tokens": ["token1", "token2"]}
    if isinstance(data, list):
        raw_tokens = data
    elif isinstance(data, dict) and isinstance(data.get("tokens"), list):
        raw_tokens = data["tokens"]
    else:
        raise ValueError(
            "input.json 格式错误，只支持："
            '["token1", "token2"] 或 {"tokens": ["token1", "token2"]}'
        )

    tokens = []
    seen = set()

    for token in raw_tokens:
        token = str(token).strip()
        if not token:
            continue
        if token in seen:
            continue

        tokens.append(token)
        seen.add(token)

    return tokens


def call_tushare(session, token, api_name, params, fields):
    payload = {
        "api_name": api_name,
        "token": token,
        "params": params,
        "fields": fields,
    }

    resp = session.post(API_URL, json=payload, timeout=20)
    resp.raise_for_status()
    return resp.json()


def is_permission_error(code, msg):
    msg = msg or ""
    msg_lower = msg.lower()

    return (
        str(code) in {"2002", "-2001"}
        or "没有接口" in msg
        or "权限" in msg
        or "积分" in msg
        or "permission" in msg_lower
        or "not enough" in msg_lower
    )


def is_rate_limit_error(code, msg):
    msg = msg or ""
    return str(code) == "40203" or "频率超限" in msg


def is_token_error(code, msg):
    msg = msg or ""
    msg_lower = msg.lower()

    return (
        "token" in msg_lower
        and (
            "无效" in msg
            or "错误" in msg
            or "invalid" in msg_lower
            or "不存在" in msg
        )
    )


def load_history_score_map(path: str) -> dict:
    if not os.path.exists(path):
        return {}

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, dict):
            log(f"[历史文件格式错误] {path} 不是 JSON object，忽略历史")
            return {}

        result = {}
        for token, score in data.items():
            try:
                result[str(token)] = int(score)
            except Exception:
                log(f"[历史分数非法-忽略] token={mask_token(str(token))} score={score}")

        return result

    except Exception as e:
        log(f"[读取历史失败] path={path} err={e}")
        return {}


def atomic_write_json(path: str, data: dict):
    dir_name = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp_path = tempfile.mkstemp(
        prefix=".tushare_token_scores.",
        suffix=".tmp",
        dir=dir_name,
        text=True,
    )

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")

        os.replace(tmp_path, path)

    except Exception:
        try:
            os.remove(tmp_path)
        except Exception:
            pass
        raise


def probe_token_min_score(token: str, idx: int, total: int) -> int:
    """
    单个 token 内部仍然串行探测。
    10 并发发生在 token 维度，而不是一个 token 同时打多个接口。
    """
    lower_bound = 0
    token_show = mask_token(token)

    log(f"[{idx}/{total}] start token={token_show}")

    with requests.Session() as session:
        for probe in PROBES:
            score = probe["score"]
            api_name = probe["api_name"]

            try:
                result = call_tushare(
                    session=session,
                    token=token,
                    api_name=api_name,
                    params=probe["params"],
                    fields=probe["fields"],
                )
            except Exception as e:
                log(f"[{idx}/{total}] [请求失败] token={token_show} score={score} api={api_name} err={e}")
                time.sleep(REQUEST_SLEEP)
                continue

            code = result.get("code")
            msg = result.get("msg") or ""

            if code == 0:
                lower_bound = max(lower_bound, score)
                log(f"[{idx}/{total}] [通过] token={token_show} >= {score:<5} api={api_name}")

            elif is_rate_limit_error(code, msg):
                # 频率超限不能证明没权限，也不能加分；跳过，靠历史 max 兜底。
                log(f"[{idx}/{total}] [频率超限-跳过] token={token_show} score={score:<5} api={api_name} msg={msg}")

            elif is_token_error(code, msg):
                log(f"[{idx}/{total}] [token无效] token={token_show} api={api_name} msg={msg}")
                return 0

            elif is_permission_error(code, msg):
                log(f"[{idx}/{total}] [权限不足] token={token_show} < {score:<5} api={api_name} msg={msg}")

            else:
                log(f"[{idx}/{total}] [未知结果-跳过] token={token_show} score={score:<5} api={api_name} code={code} msg={msg}")

            time.sleep(REQUEST_SLEEP)

    log(f"[{idx}/{total}] done token={token_show} current_score={lower_bound}")
    return lower_bound


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        default=DEFAULT_INPUT_FILE,
        help="输入 token JSON 文件，默认 input.json",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT_FILE,
        help="输出积分下限 JSON 文件，默认 tushare_token_scores.json",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help="token 级别并发数，默认 10",
    )
    args = parser.parse_args()

    tokens = load_input_tokens(args.input)
    history_map = load_history_score_map(args.output)
    score_map = dict(history_map)

    total = len(tokens)
    workers = max(1, int(args.workers))

    log(f"读取输入文件：{args.input}")
    log(f"输入 token 数：{total}")
    log(f"读取历史文件：{args.output}")
    log(f"历史 token 数：{len(history_map)}")
    log(f"并发数：{workers}")

    futures = {}

    with ThreadPoolExecutor(max_workers=workers) as executor:
        for idx, token in enumerate(tokens, start=1):
            future = executor.submit(probe_token_min_score, token, idx, total)
            futures[future] = token

        finished = 0

        for future in as_completed(futures):
            token = futures[future]
            token_show = mask_token(token)
            old_score = int(history_map.get(token, 0))

            try:
                current_score = int(future.result())
            except Exception as e:
                log(f"[任务异常] token={token_show} err={e}")
                current_score = 0

            final_score = max(old_score, current_score)
            score_map[token] = final_score

            finished += 1

            log(
                f"[合并] token={token_show} "
                f"history={old_score}, current={current_score}, final={final_score} "
                f"({finished}/{total})"
            )

            # 每完成一个 token 就落盘，避免中途断掉丢结果。
            atomic_write_json(args.output, score_map)
            log(f"[已更新文件] {args.output}")

    atomic_write_json(args.output, score_map)
    log(f"完成，已写入：{args.output}")


if __name__ == "__main__":
    main()