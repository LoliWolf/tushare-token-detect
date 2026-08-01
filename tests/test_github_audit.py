import json
import os
import tempfile
import unittest
from pathlib import Path

import github_audit


class GitHubAuditTests(unittest.TestCase):
    def write_json(self, directory: str, name: str, data):
        path = Path(directory, name)
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_allowlist_is_exact_and_case_insensitive(self):
        with tempfile.TemporaryDirectory() as directory:
            allowlist = self.write_json(
                directory,
                "allowlist.json",
                {"users": ["Approved-User"]},
            )

            self.assertEqual(
                github_audit.enforce_allowlist("approved-user", str(allowlist)),
                "approved-user",
            )
            with self.assertRaises(github_audit.WhitelistDenied):
                github_audit.enforce_allowlist("approved-user-2", str(allowlist))

    def test_denied_user_never_constructs_github_client(self):
        class ClientMustNotBeCreated:
            def __init__(self, *args, **kwargs):
                raise AssertionError("白名单拒绝后不应创建 GitHub 客户端")

        with tempfile.TemporaryDirectory() as directory:
            allowlist = self.write_json(
                directory,
                "allowlist.json",
                {"users": ["approved-user"]},
            )
            output = Path(directory, "result.json")

            with self.assertRaises(github_audit.WhitelistDenied):
                github_audit.run(
                    [
                        "--user",
                        "blocked-user",
                        "--allowlist",
                        str(allowlist),
                        "--output",
                        str(output),
                    ],
                    environ={},
                    client_type=ClientMustNotBeCreated,
                )

            self.assertFalse(output.exists())

    def test_scan_content_returns_only_metadata_and_hmac(self):
        candidate = "a1B2c3D4e5F6a7B8" * 3
        content = (
            "import tushare as ts\n"
            f"token = \"{candidate}\"\n"
            "pro = ts.pro_api(token)\n"
        )

        findings = github_audit.scan_content(
            content,
            "approved-user/repo",
            "settings.py",
            "https://github.com/approved-user/repo/blob/main/settings.py",
            b"k" * 32,
        )

        self.assertEqual(len(findings), 1)
        finding_data = findings[0].to_dict()
        serialized = json.dumps(finding_data)
        self.assertNotIn(candidate, serialized)
        self.assertEqual(finding_data["line"], 2)
        self.assertEqual(finding_data["detector"], "contextual_token")
        self.assertRegex(
            finding_data["fingerprint"],
            r"^hmac-sha256:[0-9a-f]{24}$",
        )
        self.assertTrue(finding_data["url"].endswith("#L2"))

    def test_go_style_assignment_and_approximate_constant_are_detected(self):
        candidate = "f0E1d2C3b4A59687" * 3
        content = f'TUSHARE_ACCESS_TOKEN := "{candidate}"\n'

        findings = github_audit.scan_content(
            content,
            "approved-user/repo",
            "config.go",
            "https://github.com/approved-user/repo/blob/main/config.go",
            b"k" * 32,
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].detector, "named_constant")

    def test_placeholder_and_unrelated_generic_token_are_ignored(self):
        plausible = "a1B2c3D4e5F6a7B8" * 3
        placeholder = "exampletokenvalue" * 3
        content = (
            f'TUSHARE_TOKEN = "{placeholder}"\n'
            f'auth_token = "{plausible}"\n'
        )

        findings = github_audit.scan_content(
            content,
            "approved-user/repo",
            "config.py",
            "https://github.com/approved-user/repo/blob/main/config.py",
            b"k" * 32,
        )

        self.assertEqual(findings, [])

    def test_repository_permission_filter_fails_closed(self):
        class FakeResponse:
            def __init__(self):
                self.status_code = 200
                self.headers = {}

            def json(self):
                return [
                    {
                        "full_name": "Approved-User/writable",
                        "owner": {"login": "Approved-User"},
                        "permissions": {"push": True},
                    },
                    {
                        "full_name": "Approved-User/read-only",
                        "owner": {"login": "Approved-User"},
                        "permissions": {"pull": True},
                    },
                    {
                        "full_name": "Other-User/writable",
                        "owner": {"login": "Other-User"},
                        "permissions": {"admin": True},
                    },
                ]

        class FakeSession:
            def __init__(self):
                self.headers = {}
                self.called = 0

            def request(self, method, url, **kwargs):
                self.called += 1
                return FakeResponse()

        session = FakeSession()
        client = github_audit.GitHubClient(
            "github-test-token",
            search_interval=0,
            session=session,
        )

        repositories = client.writable_repositories("approved-user")

        self.assertEqual(repositories, ["Approved-User/writable"])
        self.assertEqual(session.called, 1)

    def test_client_rejects_non_github_api_url_without_request(self):
        class FakeSession:
            def __init__(self):
                self.headers = {}
                self.called = False

            def request(self, method, url, **kwargs):
                self.called = True
                raise AssertionError("非 GitHub API URL 不应发送请求")

        session = FakeSession()
        client = github_audit.GitHubClient(
            "github-test-token",
            search_interval=0,
            session=session,
        )

        with self.assertRaises(github_audit.GitHubAPIError):
            client._request("GET", "https://example.com/file")
        self.assertFalse(session.called)

    def test_search_marks_github_result_cap_as_incomplete(self):
        class FakeResponse:
            def __init__(self):
                self.status_code = 200
                self.headers = {}

            def json(self):
                return {
                    "total_count": 1001,
                    "incomplete_results": False,
                    "items": [],
                }

        class FakeSession:
            def __init__(self):
                self.headers = {}

            def request(self, method, url, **kwargs):
                return FakeResponse()

        client = github_audit.GitHubClient(
            "github-test-token",
            search_interval=0,
            session=FakeSession(),
        )

        items, incomplete = client.search_repository(
            "Approved-User/repo",
            max_pages=1,
        )

        self.assertEqual(items, [])
        self.assertTrue(incomplete)

    def test_run_writes_no_candidate_and_uses_private_file_mode(self):
        candidate = "0a1B2c3D4e5F6789" * 3

        class FakeClient:
            constructed = 0

            def __init__(self, token, *, search_interval):
                self.token = token
                self.search_interval = search_interval
                FakeClient.constructed += 1

            def writable_repositories(self, target_user):
                self.test_case.assertEqual(target_user, "approved-user")
                return ["Approved-User/repo"]

            def search_repository(self, repository, *, max_pages):
                self.test_case.assertEqual(repository, "Approved-User/repo")
                self.test_case.assertEqual(max_pages, 1)
                return (
                    [
                        {
                            "path": "config.py",
                            "html_url": (
                                "https://github.com/Approved-User/repo/"
                                "blob/main/config.py"
                            ),
                        }
                    ],
                    False,
                )

            def fetch_file_text(self, item):
                return f'import tushare\nTUSHARE_TOKEN = "{candidate}"\n'

        FakeClient.test_case = self

        with tempfile.TemporaryDirectory() as directory:
            allowlist = self.write_json(
                directory,
                "allowlist.json",
                {"users": ["approved-user"]},
            )
            output = Path(directory, "result.json")
            exit_code = github_audit.run(
                [
                    "--user",
                    "Approved-User",
                    "--allowlist",
                    str(allowlist),
                    "--output",
                    str(output),
                    "--max-pages",
                    "1",
                    "--search-interval",
                    "0",
                    "--fail-on-findings",
                ],
                environ={
                    "GITHUB_TOKEN": "github-test-token",
                    "TUSHARE_AUDIT_HMAC_KEY": "k" * 32,
                },
                client_type=FakeClient,
            )

            report_text = output.read_text(encoding="utf-8")
            report = json.loads(report_text)
            self.assertEqual(exit_code, 1)
            self.assertEqual(FakeClient.constructed, 1)
            self.assertEqual(len(report["findings"]), 1)
            self.assertNotIn(candidate, report_text)
            self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
