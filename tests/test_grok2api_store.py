import tempfile
from pathlib import Path

from webui import grok2api_store


class _Response:
    status_code = 200

    @staticmethod
    def json():
        return {"data": {"tokens": {"accessToken": "short-lived-token"}}}


def run() -> None:
    old_config = grok2api_store.CONFIG_PATH
    old_lock = grok2api_store.LOCK_PATH
    try:
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / "config.json"
            lock = Path(temp) / "config.json.lock"
            grok2api_store.CONFIG_PATH = config
            grok2api_store.LOCK_PATH = lock

            saved = grok2api_store.save_grok2api_config({
                "enabled": True,
                "remote_url": "https://grok2api.example.test/",
                "username": "admin",
                "password": "first-secret",
                "account_types": ["grok_console", "grok_build", "grok_console"],
            })
            assert saved["configured"] is True
            assert saved["password_configured"] is True
            assert "password" not in saved
            assert saved["account_types"] == ["grok_build", "grok_console"]

            preserved = grok2api_store.save_grok2api_config({
                "enabled": True,
                "remote_url": "https://grok2api.example.test",
                "username": "operator",
                "password": "",
                "account_types": ["grok_web"],
            })
            assert preserved["password_configured"] is True
            assert preserved["account_types"] == ["grok_web"]

            seen = []
            result = grok2api_store.test_grok2api_config(
                {
                    "remote_url": "https://grok2api.example.test",
                    "username": "operator",
                    "password": "",
                    "account_types": ["grok_web"],
                },
                http_post=lambda url, **kwargs: seen.append((url, kwargs)) or _Response(),
            )
            assert result["ok"] is True
            assert seen[0][0].endswith("/api/admin/v1/auth/login")
            assert seen[0][1]["json"]["password"] == "first-secret"

            cleared = grok2api_store.save_grok2api_config({}, clear_password=True)
            assert cleared["password_configured"] is False

            try:
                grok2api_store.save_grok2api_config({"account_types": []})
            except grok2api_store.Grok2APIConfigError as exc:
                assert "至少选择一种" in str(exc)
            else:
                raise AssertionError("empty account_types should be rejected")
    finally:
        grok2api_store.CONFIG_PATH = old_config
        grok2api_store.LOCK_PATH = old_lock


if __name__ == "__main__":
    run()
    print("OK grok2api store")
