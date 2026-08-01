from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

GITHUB_API_URL = "https://api.github.com"
GITHUB_API_VERSION = "2022-11-28"
DEFAULT_ALLOWLIST_FILE = "github_user_allowlist.json"
DEFAULT_OUTPUT_FILE = "github_tushare_findings.json"
DEFAULT_TIMEOUT = 20.0
DEFAULT_SEARCH_INTERVAL = 6.2
DEFAULT_MAX_PAGES = 10
MAX_SEARCH_RESULTS = 1000
MAX_FILE_BYTES = 1024 * 1024

GITHUB_LOGIN_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$"
)
TOKEN_VALUE = r"[A-Za-z0-9]{32,128}(?![A-Za-z0-9])"
ASSIGNMENT_OPERATOR = r"(?::=|=>|=|:)"

# GitHub Search API 每个查询最多允许 5 个布尔运算符。搜索只用于定位可能的文件，
# 真正的候选判断在本地完成。
SEARCH_TERMS = (
    '"tushare"',
    '"ts.set_token"',
    '"ts.pro_api"',
    '"TUSHARE_TOKEN"',
    '"TS_TOKEN"',
)

# GitHub Code Search 不支持括号，直接 OR 拼接
SEARCH_QUERIES = [
    " OR ".join(SEARCH_TERMS[:3]) + " in:file",
    " OR ".join(SEARCH_TERMS[3:]) + " in:file",
]

DETECTORS = (
    (
        "set_token_call",
        re.compile(
            rf"(?ix)\b(?:ts|tushare)\s*\.\s*set_token\s*\(\s*"
            rf"(?:token\s*=\s*)?[\"'](?P<secret>{TOKEN_VALUE})[\"']"
        ),
        False,
    ),
    (
        "pro_api_call",
        re.compile(
            rf"(?ix)\b(?:ts|tushare)\s*\.\s*pro_api\s*\(\s*"
            rf"(?:token\s*=\s*)?[\"'](?P<secret>{TOKEN_VALUE})[\"']"
        ),
        False,
    ),
    (
        "named_constant",
        re.compile(
            rf"(?ix)\b(?:"
            rf"tushare[_-]?(?:(?:api|access|pro)[_-]?)?(?:token|key|secret)"
            rf"|ts[_-]?(?:(?:api|access)[_-]?)?(?:token|key)"
            rf")\b\s*[\"']?\s*{ASSIGNMENT_OPERATOR}\s*"
            rf"[\"']?(?P<secret>{TOKEN_VALUE})[\"']?"
        ),
        False,
    ),
    (
        "contextual_token",
        re.compile(
            rf"(?ix)\b(?:token|api[_-]?key|access[_-]?token|secret)\b"
            rf"\s*[\"']?\s*{ASSIGNMENT_OPERATOR}\s*"
            rf"[\"']?(?P<secret>{TOKEN_VALUE})[\"']?"
        ),
        True,
    ),
)

PLACEHOLDER_MARKERS = (
    "example",
    "placeholder",
    "replace",
    "sample",
    "changeme",
    "dummy",
    "yourtoken",
    "your_tushare",
    "tokenhere",
    "testtoken",
)


class AuditError(RuntimeError):
    """可安全展示给终端用户的审计错误。"""


class GitHubAPIError(AuditError):
    """GitHub API 调用失败，错误信息不得包含文件内容。"""


@dataclass(frozen=True)
class Finding:
    repository: str
    path: str
    line: int
    url: str
    detector: str
    fingerprint: str
    raw_token: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository": self.repository,
            "path": self.path,
            "line": self.line,
            "url": self.url,
            "detector": self.detector,
            "fingerprint": self.fingerprint,
            "raw_token": self.raw_token,
        }


def log(message: str) -> None:
    print(message, file=sys.stderr)


def normalize_login(login: str) -> str:
    value = login.strip()
    if not GITHUB_LOGIN_RE.fullmatch(value):
        raise AuditError(f"GitHub 用户名格式非法：{login!r}")
    return value.casefold()


@dataclass(frozen=True)
class Allowlist:
    exact: frozenset[str]
    patterns: tuple[re.Pattern[str], ...]

    def is_allowed(self, login: str) -> bool:
        normalized = normalize_login(login)
        if normalized in self.exact:
            return True
        for pattern in self.patterns:
            if pattern.fullmatch(normalized):
                return True
        return False

    @classmethod
    def empty(cls) -> "Allowlist":
        return cls(exact=frozenset(), patterns=())


def load_allowlist(path: str | os.PathLike[str]) -> Allowlist:
    allowlist_path = Path(path)
    if not allowlist_path.is_file():
        raise AuditError(f"白名单文件不存在：{allowlist_path}")

    try:
        with allowlist_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as exc:
        raise AuditError(
            f"白名单不是合法 JSON：{allowlist_path}（第 {exc.lineno} 行）"
        ) from None
    except OSError as exc:
        raise AuditError(f"无法读取白名单：{allowlist_path}（{exc}）") from None

    if isinstance(data, dict):
        raw_users = data.get("users")
    else:
        raw_users = data

    if not isinstance(raw_users, list):
        raise AuditError('白名单格式必须是 ["user"] 或 {"users": ["user"]}')

    exact: set[str] = set()
    patterns: list[re.Pattern[str]] = []

    for entry in raw_users:
        if not isinstance(entry, str):
            raise AuditError("白名单中的 GitHub 用户名必须是字符串")
        if entry.startswith("/") and entry.endswith("/"):
            try:
                patterns.append(re.compile(entry[1:-1]))
            except re.error:
                continue
        else:
            exact.add(normalize_login(entry))

    return Allowlist(exact=frozenset(exact), patterns=tuple(patterns))


def load_required_secret(environ: Mapping[str, str], name: str) -> str:
    value = environ.get(name, "").strip()
    if not value:
        raise AuditError(f"缺少环境变量：{name}")
    return value


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def is_plausible_secret(candidate: str) -> bool:
    lowered = candidate.casefold()
    if not 32 <= len(candidate) <= 128:
        return False
    if any(marker in lowered for marker in PLACEHOLDER_MARKERS):
        return False
    if len(set(candidate)) < 8:
        return False
    return shannon_entropy(candidate) >= 3.0


def fingerprint_secret(candidate: str) -> str:
    digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
    return f"sha256:{digest[:24]}"


def line_number_at(content: str, offset: int) -> int:
    return content.count("\n", 0, offset) + 1


def has_tushare_context(content: str, offset: int) -> bool:
    lines = content.splitlines()
    line_index = line_number_at(content, offset) - 1
    start = max(0, line_index - 2)
    end = min(len(lines), line_index + 3)
    context = "\n".join(lines[start:end]).casefold()
    return (
        "tushare" in context
        or "ts.set_token" in context
        or "ts.pro_api" in context
    )


def safe_line_url(html_url: str, line: int) -> str:
    parsed = urlparse(html_url)
    if parsed.scheme != "https" or parsed.netloc.casefold() != "github.com":
        raise GitHubAPIError("GitHub 搜索结果包含非 github.com 文件链接")
    return f"{html_url.split('#', 1)[0]}#L{line}"


def scan_content(
    content: str,
    repository: str,
    path: str,
    html_url: str,
) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[int, str]] = set()

    for detector_name, detector, needs_context in DETECTORS:
        for match in detector.finditer(content):
            candidate = match.group("secret")
            if needs_context and not has_tushare_context(content, match.start()):
                continue
            if not is_plausible_secret(candidate):
                continue

            line = line_number_at(content, match.start("secret"))
            fingerprint = fingerprint_secret(candidate)
            identity = (line, fingerprint)
            if identity in seen:
                continue
            seen.add(identity)

            findings.append(
                Finding(
                    repository=repository,
                    path=path,
                    line=line,
                    url=safe_line_url(html_url, line),
                    detector=detector_name,
                    fingerprint=fingerprint,
                    raw_token=candidate,
                )
            )

    return findings


class GitHubClient:
    def __init__(
        self,
        token: str,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        search_interval: float = DEFAULT_SEARCH_INTERVAL,
        session: requests.Session | None = None,
    ) -> None:
        self.timeout = timeout
        self.search_interval = max(0.0, search_interval)
        self._last_search_at: float | None = None
        self.session = session or requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": GITHUB_API_VERSION,
                "User-Agent": "tushare-token-defensive-audit/1.0",
            }
        )

    def _request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.netloc.casefold() != "api.github.com":
            raise GitHubAPIError("拒绝访问非 api.github.com 地址")

        try:
            response = self.session.request(
                method,
                url,
                timeout=self.timeout,
                **kwargs,
            )
        except requests.RequestException as exc:
            raise GitHubAPIError(f"GitHub API 请求失败：{type(exc).__name__}") from None

        if response.status_code >= 400:
            request_id = response.headers.get("X-GitHub-Request-Id", "unknown")
            if response.status_code in {403, 429}:
                reset_at = response.headers.get("X-RateLimit-Reset", "unknown")
                raise GitHubAPIError(
                    f"GitHub API 限流或拒绝访问（HTTP {response.status_code}, "
                    f"reset={reset_at}, request_id={request_id}）"
                )
            raise GitHubAPIError(
                f"GitHub API 返回 HTTP {response.status_code}（request_id={request_id}）"
            )
        return response

    @staticmethod
    def _json_object(response: requests.Response) -> dict[str, Any]:
        try:
            data = response.json()
        except (ValueError, json.JSONDecodeError):
            raise GitHubAPIError("GitHub API 返回了无效 JSON") from None
        if not isinstance(data, dict):
            raise GitHubAPIError("GitHub API JSON 结构异常")
        return data

    def _wait_for_search_slot(self) -> None:
        if self._last_search_at is not None and self.search_interval > 0:
            elapsed = time.monotonic() - self._last_search_at
            remaining = self.search_interval - elapsed
            if remaining > 0:
                time.sleep(remaining)
        self._last_search_at = time.monotonic()

    def search_global(
        self,
        *,
        max_pages: int,
    ) -> tuple[list[dict[str, Any]], bool]:
        """全站搜索公开代码中可能包含 Tushare Token 的文件。"""
        results: dict[tuple[str, str], dict[str, Any]] = {}
        incomplete = False

        for query in SEARCH_QUERIES:
            for page in range(1, max_pages + 1):
                self._wait_for_search_slot()
                response = self._request(
                    "GET",
                    f"{GITHUB_API_URL}/search/code",
                    params={"q": query, "per_page": 100, "page": page},
                )
                payload = self._json_object(response)
                items = payload.get("items")
                if not isinstance(items, list):
                    raise GitHubAPIError("GitHub 代码搜索结果结构异常")

                incomplete = incomplete or payload.get("incomplete_results") is True
                try:
                    total_count = int(payload.get("total_count") or 0)
                except (TypeError, ValueError):
                    raise GitHubAPIError("GitHub 代码搜索结果数量格式异常") from None
                if total_count < 0:
                    raise GitHubAPIError("GitHub 代码搜索结果数量格式异常")
                if total_count > MAX_SEARCH_RESULTS:
                    incomplete = True

                for item in items:
                    if not isinstance(item, dict):
                        continue
                    result_repo = item.get("repository") or {}
                    if not isinstance(result_repo, dict):
                        continue
                    full_name = str(result_repo.get("full_name") or "")
                    path = str(item.get("path") or "")
                    if not full_name or not path:
                        continue
                    results[(full_name.casefold(), path)] = item

                if len(items) < 100:
                    if page * 100 < min(total_count, MAX_SEARCH_RESULTS):
                        incomplete = True
                    break
                if page * 100 >= min(total_count, MAX_SEARCH_RESULTS):
                    break
                if page == max_pages:
                    incomplete = True

        return list(results.values()), incomplete

    def fetch_file_text(self, item: Mapping[str, Any]) -> str | None:
        api_url = str(item.get("url") or "")
        if not api_url:
            raise GitHubAPIError("GitHub 搜索结果缺少文件 API 地址")

        response = self._request(
            "GET",
            api_url,
            headers={"Accept": "application/vnd.github.raw+json"},
        )
        content = response.content
        if len(content) > MAX_FILE_BYTES:
            return None
        return content.decode("utf-8", errors="replace")


def atomic_write_json(path: str | os.PathLike[str], data: Mapping[str, Any]) -> None:
    output_path = Path(path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(
        prefix=f".{output_path.name}.",
        suffix=".tmp",
        dir=output_path.parent,
        text=True,
    )

    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        os.replace(temp_path, output_path)
        os.chmod(output_path, 0o600)
    except Exception:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise


def audit_user(
    client: GitHubClient,
    allowlist: Allowlist,
    *,
    max_pages: int,
) -> dict[str, Any]:
    items, scan_incomplete = client.search_global(max_pages=max_pages)

    scanned_repos: set[str] = set()
    findings: list[Finding] = []
    skipped_count = 0

    for item in items:
        result_repo = item.get("repository") or {}
        if not isinstance(result_repo, dict):
            continue
        full_name = str(result_repo.get("full_name") or "")
        owner_login = full_name.split("/", 1)[0] if "/" in full_name else ""

        if not allowlist.is_allowed(owner_login):
            skipped_count += 1
            continue

        scanned_repos.add(full_name.casefold())
        path = str(item.get("path") or "")
        html_url = str(item.get("html_url") or "")
        try:
            content = client.fetch_file_text(item)
            if content is None:
                scan_incomplete = True
                log(f"[跳过超大文件] repository={full_name} path={path!r}")
                continue
            findings.extend(
                scan_content(
                    content=content,
                    repository=full_name,
                    path=path,
                    html_url=html_url,
                )
            )
        except GitHubAPIError as exc:
            scan_incomplete = True
            log(f"[文件读取失败] repository={full_name} path={path!r}：{exc}")

    if skipped_count:
        log(f"已跳过 {skipped_count} 个不匹配白名单的仓库文件")

    unique_findings = {
        (
            finding.repository.casefold(),
            finding.path,
            finding.line,
            finding.fingerprint,
        ): finding
        for finding in findings
    }
    ordered_findings = sorted(
        unique_findings.values(),
        key=lambda finding: (
            finding.repository.casefold(),
            finding.path,
            finding.line,
            finding.fingerprint,
        ),
    )

    return {
        "schema_version": 1,
        "scanned_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "repositories_scanned": len(scanned_repos),
        "total_results": len(items),
        "skipped_results": skipped_count,
        "scan_incomplete": scan_incomplete,
        "findings": [finding.to_dict() for finding in ordered_findings],
    }


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1 or parsed > 10:
        raise argparse.ArgumentTypeError("必须在 1 到 10 之间")
    return parsed


def non_negative_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed < 0:
        raise argparse.ArgumentTypeError("必须是大于等于 0 的有限数值")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="在 GitHub 公开仓库中审计 Tushare Token 泄漏，按白名单过滤仓库 owner"
    )
    parser.add_argument(
        "--allowlist",
        default=DEFAULT_ALLOWLIST_FILE,
        help=f"扫描 user/organization 白名单 JSON，支持 /regex/，默认 {DEFAULT_ALLOWLIST_FILE}",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT_FILE,
        help=f"审计结果 JSON（包含原始 Token），默认 {DEFAULT_OUTPUT_FILE}",
    )
    parser.add_argument(
        "--max-pages",
        type=positive_int,
        default=DEFAULT_MAX_PAGES,
        help="最多读取的搜索结果页数，1-10，默认 10",
    )
    parser.add_argument(
        "--search-interval",
        type=non_negative_float,
        default=DEFAULT_SEARCH_INTERVAL,
        help="相邻代码搜索请求的最小秒数，默认 6.2",
    )
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="发现疑似泄漏时返回退出码 1，适合 CI",
    )
    return parser


def run(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    client_type: type[GitHubClient] = GitHubClient,
) -> int:
    args = build_parser().parse_args(argv)

    allowlist = load_allowlist(args.allowlist)

    active_environ = os.environ if environ is None else environ
    github_token = load_required_secret(active_environ, "GITHUB_TOKEN")

    client = client_type(
        github_token,
        search_interval=args.search_interval,
    )
    report = audit_user(
        client,
        allowlist,
        max_pages=args.max_pages,
    )
    atomic_write_json(args.output, report)

    finding_count = len(report["findings"])
    log(f"扫描完成：仓库 {report['repositories_scanned']}，疑似泄漏 {finding_count}")
    log(f"扫描结果已写入: {args.output}")

    if report["scan_incomplete"]:
        log("警告：扫描不完整，请检查日志后重试")
        return 3
    if finding_count and args.fail_on_findings:
        return 1
    return 0


def main() -> int:
    try:
        return run()
    except AuditError as exc:
        log(f"错误：{exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
