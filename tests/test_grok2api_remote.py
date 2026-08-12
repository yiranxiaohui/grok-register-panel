import json
import sys
import types
import unittest
from unittest.mock import patch

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
    def test_login_then_imports_grok2api_document(self):
        calls = []

        def fake_post(url, **kwargs):
            calls.append((url, kwargs))
            if url.endswith("/auth/login"):
                return _Response(payload={"data": {"tokens": {"accessToken": "short-lived-token"}}})
            return _Response(text='event: complete\ndata: {"created":1,"updated":0}\n\n')

        token = {"access_token": "access", "refresh_token": "refresh", "expires_in": 3600}
        with patch.object(auth.requests, "post", side_effect=fake_post):
            name = auth.upload_grok2api_auth_remote(
                "https://grok2api.example.test/", "admin", "secret", token, email="user@example.test"
            )

        self.assertEqual(name, "g2a-user@example.test.json")
        self.assertEqual(calls[0][1]["json"], {"username": "admin", "password": "secret"})
        self.assertEqual(calls[1][1]["headers"]["Authorization"], "Bearer short-lived-token")
        uploaded = calls[1][1]["files"]["files"]
        self.assertEqual(uploaded[0], name)
        document = json.loads(uploaded[1])
        self.assertIn(auth.AUTH_KEY, document)
        self.assertEqual(document[auth.AUTH_KEY]["email"], "user@example.test")

    def test_does_not_expose_login_response_body_on_failure(self):
        with patch.object(auth.requests, "post", return_value=_Response(status_code=401, text="password leaked")):
            with self.assertRaisesRegex(RuntimeError, r"登录失败 HTTP 401") as caught:
                auth.upload_grok2api_auth_remote("https://grok2api.example.test", "admin", "secret", {})
        self.assertNotIn("password leaked", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
