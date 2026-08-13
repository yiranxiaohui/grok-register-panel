import json
import stat
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

if "curl_cffi" not in sys.modules:
    sys.modules["curl_cffi"] = types.SimpleNamespace(CurlMime=object, requests=types.SimpleNamespace(post=None))

import sso_to_auth_json as auth


class _Response:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self):
        return self._payload


class _Multipart:
    instances = []

    def __init__(self):
        self.parts = []
        self.closed = False
        self.__class__.instances.append(self)

    def addpart(self, name, **kwargs):
        self.parts.append((name, kwargs))

    def close(self):
        self.closed = True


class Grok2APIRemoteUploadTests(unittest.TestCase):
    def setUp(self):
        _Multipart.instances.clear()

    def test_imports_account_proxy_without_using_it_for_admin_transport(self):
        calls = []

        def fake_post(url, **kwargs):
            calls.append((url, kwargs))
            if url.endswith("/auth/login"):
                return _Response(payload={"data": {"tokens": {"accessToken": "short-lived-token"}}})
            return _Response(text='event: complete\ndata: {"created":1,"updated":0}\n\n')

        token = {"access_token": "access", "refresh_token": "refresh", "expires_in": 3600}
        account_proxy = "http://worker:proxy-pass@proxy.example:8080"
        with patch.object(auth, "CurlMime", _Multipart), patch.object(auth.requests, "post", side_effect=fake_post):
            name = auth.upload_grok2api_auth_remote(
                "https://grok2api.example.test/",
                "admin",
                "secret",
                token,
                email="user@example.test",
                proxy=account_proxy,
            )

        self.assertEqual(name, "g2a-user@example.test.json")
        self.assertEqual(calls[0][1]["json"], {"username": "admin", "password": "secret"})
        self.assertEqual(calls[1][1]["headers"]["Authorization"], "Bearer short-lived-token")
        self.assertNotIn("files", calls[1][1])
        multipart = calls[1][1]["multipart"]
        self.assertIs(multipart, _Multipart.instances[0])
        self.assertTrue(multipart.closed)
        self.assertEqual(len(multipart.parts), 1)
        field, uploaded = multipart.parts[0]
        self.assertEqual(field, "files")
        self.assertEqual(uploaded["filename"], name)
        self.assertEqual(uploaded["content_type"], "application/json")
        document = json.loads(uploaded["data"])
        self.assertEqual(document["provider"], "grok_build")
        self.assertEqual(document["access_token"], "access")
        self.assertEqual(document["refresh_token"], "refresh")
        self.assertEqual(document["email"], "user@example.test")
        self.assertEqual(document["proxy_url"], account_proxy)
        self.assertEqual(calls[0][1]["proxies"], {"all": ""})
        self.assertEqual(calls[1][1]["proxies"], {"all": ""})

    def test_direct_import_omits_account_proxy(self):
        calls = []

        def fake_post(url, **kwargs):
            calls.append((url, kwargs))
            if url.endswith("/auth/login"):
                return _Response(payload={"data": {"tokens": {"accessToken": "short-lived-token"}}})
            return _Response(text='event: complete\ndata: {"created":1,"updated":0}\n\n')

        with patch.object(auth, "CurlMime", _Multipart), patch.object(auth.requests, "post", side_effect=fake_post):
            auth.upload_grok2api_auth_remote(
                "https://grok2api.example.test",
                "admin",
                "secret",
                {"access_token": "access", "refresh_token": "refresh"},
                email="direct@example.test",
            )

        document = json.loads(calls[1][1]["multipart"].parts[0][1]["data"])
        self.assertNotIn("proxy_url", document)
        self.assertEqual(calls[0][1]["proxies"], {"all": ""})
        self.assertEqual(calls[1][1]["proxies"], {"all": ""})

    def test_local_auth_preserves_sso_for_provider_exports(self):
        with tempfile.TemporaryDirectory() as temp:
            path = auth.write_grok2api_auth(
                Path(temp),
                {"access_token": "example-access", "refresh_token": "example-refresh"},
                email="user@example.test",
                sso="sso=example-sso-token-value-1234567890",
            )
            document = json.loads(path.read_text(encoding="utf-8"))
            mode = stat.S_IMODE(path.stat().st_mode)

        entry = next(iter(document.values()))
        self.assertEqual(entry["sso_token"], "example-sso-token-value-1234567890")
        self.assertEqual(mode, 0o600)

    def test_imports_build_web_and_console_with_one_admin_login(self):
        calls = []

        def fake_post(url, **kwargs):
            calls.append((url, kwargs))
            if url.endswith("/auth/login"):
                return _Response(payload={"data": {"tokens": {"accessToken": "short-lived-token"}}})
            return _Response(text='event: complete\ndata: {"created":1,"updated":0}\n\n')

        token = {"access_token": "access", "refresh_token": "refresh"}
        sso = "example-sso-token-value-1234567890"
        account_proxy = "socks5h://worker:proxy-pass@proxy.example:1080"
        with patch.object(auth, "CurlMime", _Multipart), patch.object(auth.requests, "post", side_effect=fake_post):
            names = auth.upload_grok2api_accounts_remote(
                "https://grok2api.example.test",
                "admin",
                "secret",
                token,
                sso=sso,
                email="user@example.test",
                proxy=account_proxy,
                account_types=["grok_console", "grok_build", "grok_web"],
            )

        self.assertEqual(len(calls), 4)
        self.assertEqual(
            [url for url, _kwargs in calls[1:]],
            [
                "https://grok2api.example.test/api/admin/v1/accounts/import",
                "https://grok2api.example.test/api/admin/v1/accounts/web/import",
                "https://grok2api.example.test/api/admin/v1/accounts/console/import",
            ],
        )
        self.assertEqual(
            names,
            {
                "grok_build": "g2a-user@example.test.json",
                "grok_web": "g2a-web-user@example.test.json",
                "grok_console": "g2a-console-user@example.test.json",
            },
        )
        documents = [
            json.loads(kwargs["multipart"].parts[0][1]["data"])
            for _url, kwargs in calls[1:]
        ]
        self.assertEqual([item["provider"] for item in documents], ["grok_build", "grok_web", "grok_console"])
        self.assertEqual(documents[0]["access_token"], "access")
        self.assertEqual(documents[1]["sso_token"], sso)
        self.assertEqual(documents[1]["tier"], "auto")
        self.assertEqual(documents[2]["sso_token"], sso)
        self.assertTrue(all(item["proxy_url"] == account_proxy for item in documents))
        self.assertTrue(all(instance.closed for instance in _Multipart.instances))

    def test_closes_multipart_when_import_request_fails(self):
        calls = 0

        def fake_post(url, **kwargs):
            nonlocal calls
            calls += 1
            if url.endswith("/auth/login"):
                return _Response(payload={"data": {"tokens": {"accessToken": "short-lived-token"}}})
            raise RuntimeError("temporary import failure")

        with patch.object(auth, "CurlMime", _Multipart), patch.object(auth.requests, "post", side_effect=fake_post):
            with self.assertRaisesRegex(RuntimeError, "temporary import failure"):
                auth.upload_grok2api_auth_remote(
                    "https://grok2api.example.test",
                    "admin",
                    "secret",
                    {"access_token": "access", "refresh_token": "refresh"},
                )

        self.assertEqual(calls, 2)
        self.assertTrue(_Multipart.instances[0].closed)

    def test_does_not_expose_login_response_body_on_failure(self):
        with patch.object(auth.requests, "post", return_value=_Response(status_code=401, text="password leaked")):
            with self.assertRaisesRegex(RuntimeError, r"登录失败 HTTP 401") as caught:
                auth.upload_grok2api_auth_remote("https://grok2api.example.test", "admin", "secret", {})
        self.assertNotIn("password leaked", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
