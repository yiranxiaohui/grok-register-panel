import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from webui import grok2api_export


def _write_nested_auth(path: Path, *, email: str, access: str, refresh: str) -> None:
    path.write_text(
        json.dumps(
            {
                "https://auth.x.ai::example-client-id": {
                    "key": access,
                    "auth_mode": "oidc",
                    "email": email,
                    "user_id": "example-user-id",
                    "principal_id": "example-principal-id",
                    "refresh_token": refresh,
                    "expires_at": "2026-08-13T00:00:00Z",
                    "oidc_client_id": "example-client-id",
                }
            }
        )
        + "\n",
        encoding="utf-8",
    )


def test_build_grok2api_export_converts_nested_local_auth_to_import_batch():
    old_config = grok2api_export.CONFIG_PATH
    old_default = grok2api_export.DEFAULT_AUTH_DIR
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        auth_dir = root / "local-auth"
        auth_dir.mkdir()
        config = root / "config.json"
        config.write_text(
            json.dumps({"grok2api_auth_dir": "local-auth"}), encoding="utf-8"
        )
        _write_nested_auth(
            auth_dir / "g2a-user@example.test.json",
            email="user@example.test",
            access="example-access-token",
            refresh="example-refresh-token",
        )
        grok2api_export.CONFIG_PATH = config
        grok2api_export.DEFAULT_AUTH_DIR = root / "unused"
        try:
            exported = grok2api_export.build_grok2api_export(
                datetime(2026, 8, 12, 18, 30, 0, tzinfo=timezone.utc)
            )
        finally:
            grok2api_export.CONFIG_PATH = old_config
            grok2api_export.DEFAULT_AUTH_DIR = old_default

    assert exported.filename == "grok2api-accounts-20260812-183000.json"
    assert exported.account_count == 1
    document = json.loads(exported.content)
    assert list(document) == ["accounts"]
    assert document["accounts"] == [
        {
            "provider": "grok_build",
            "name": "user@example.test",
            "client_id": "example-client-id",
            "access_token": "example-access-token",
            "refresh_token": "example-refresh-token",
            "id_token": "",
            "token_type": "Bearer",
            "scope": "",
            "expires_at": "2026-08-13T00:00:00Z",
            "email": "user@example.test",
            "user_id": "example-user-id",
            "principal_id": "example-principal-id",
        }
    ]


def test_build_grok2api_export_rejects_empty_and_invalid_auth_dirs():
    old_config = grok2api_export.CONFIG_PATH
    old_default = grok2api_export.DEFAULT_AUTH_DIR
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        config = root / "config.json"
        config.write_text("{}", encoding="utf-8")
        auth_dir = root / "auth"
        auth_dir.mkdir()
        grok2api_export.CONFIG_PATH = config
        grok2api_export.DEFAULT_AUTH_DIR = auth_dir
        try:
            try:
                grok2api_export.build_grok2api_export()
            except grok2api_export.Grok2APIExportEmptyError as exc:
                assert "没有本地 Grok2API auth" in str(exc)
            else:
                raise AssertionError("empty auth directory should not export")

            (auth_dir / "g2a-invalid.json").write_text(
                '{"entry":{"email":"user@example.test"}}', encoding="utf-8"
            )
            try:
                grok2api_export.build_grok2api_export()
            except grok2api_export.Grok2APIExportError as exc:
                assert "没有可导出的" in str(exc)
                assert "user@example.test" not in str(exc)
            else:
                raise AssertionError("invalid auth file should not export")
        finally:
            grok2api_export.CONFIG_PATH = old_config
            grok2api_export.DEFAULT_AUTH_DIR = old_default


if __name__ == "__main__":
    test_build_grok2api_export_converts_nested_local_auth_to_import_batch()
    test_build_grok2api_export_rejects_empty_and_invalid_auth_dirs()
    print("OK grok2api export")
