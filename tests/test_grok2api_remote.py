import json
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

if "curl_cffi" not in sys.modules:
    sys.modules["curl_cffi"] = types.SimpleNamespace(requests=types.SimpleNamespace(post=None))

import sso_to_auth_json as auth


class _Response:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self):
        return self._payload


class Grok2APIRemoteUploadTests(unittest.TestCase):
    def test_imports_account_proxy_without_using_it_for_admin_transport(self):
        calls = []

        def fake_post(url, **kwargs):
            calls.append((url, kwargs))
            if url.endswith("/auth/login"):
                return _Response(payload={"data": {"tokens": {"accessToken": "short-lived-token"}}})
            return _Response(text='event: complete\ndata: {"created":1,"updated":0}\n\n')

        token = {"access_token": "access", "refresh_token": "refresh", "expires_in": 3600}
        account_proxy = "http://worker:proxy-pass@proxy.example:8080"
        with patch.object(auth.requests, "post", side_effect=fake_post):
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
        uploaded = calls[1][1]["files"]["files"]
        self.assertEqual(uploaded[0], name)
        document = json.loads(uploaded[1])
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

        with patch.object(auth.requests, "post", side_effect=fake_post):
            auth.upload_grok2api_auth_remote(
                "https://grok2api.example.test",
                "admin",
                "secret",
                {"access_token": "access", "refresh_token": "refresh"},
                email="direct@example.test",
            )

        document = json.loads(calls[1][1]["files"]["files"][1])
        self.assertNotIn("proxy_url", document)
        self.assertEqual(calls[0][1]["proxies"], {"all": ""})
        self.assertEqual(calls[1][1]["proxies"], {"all": ""})

    def test_does_not_expose_login_response_body_on_failure(self):
        with patch.object(auth.requests, "post", return_value=_Response(status_code=401, text="password leaked")):
            with self.assertRaisesRegex(RuntimeError, r"登录失败 HTTP 401") as caught:
                auth.upload_grok2api_auth_remote("https://grok2api.example.test", "admin", "secret", {})
        self.assertNotIn("password leaked", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
