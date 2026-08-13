# -*- coding: utf-8 -*-
from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import grok_register_ttk as register


def test_registration_uploads_selected_grok2api_account_types():
    config_keys = (
        "cpa_auto_add",
        "cpa_auth_dir",
        "cpa_remote_url",
        "cpa_management_key",
        "grok2api_auth_dir",
        "grok2api_remote_url",
        "grok2api_admin_username",
        "grok2api_admin_password",
        "grok2api_account_types",
        "bfs_check",
        "cpa_token_mode",
    )
    previous_config = {key: register.config.get(key) for key in config_keys}
    previous_functions = (
        register._resolve_cpa_proxy,
        register._s2cpa.sso_to_token,
        register._s2cpa.token_to_cpa_record,
        register._s2cpa.decode_jwt_payload,
        register._s2cpa.upload_grok2api_accounts_remote,
    )
    uploads = []
    account_proxy = "socks5h://example-user:example-pass@proxy.example:1080"
    token = {"access_token": "example-access", "refresh_token": "example-refresh"}
    register.config.update(
        {
            "cpa_auto_add": True,
            "cpa_auth_dir": "",
            "cpa_remote_url": "",
            "cpa_management_key": "",
            "grok2api_auth_dir": "",
            "grok2api_remote_url": "https://grok2api.example.test",
            "grok2api_admin_username": "operator",
            "grok2api_admin_password": "example-password",
            "grok2api_account_types": ["grok_console", "grok_build", "grok_web"],
            "bfs_check": False,
            "cpa_token_mode": "device_protocol",
        }
    )
    register._resolve_cpa_proxy = lambda: account_proxy
    register._s2cpa.sso_to_token = lambda *_args, **_kwargs: token
    register._s2cpa.token_to_cpa_record = lambda *_args, **_kwargs: {
        "access_token": "example-access"
    }
    register._s2cpa.decode_jwt_payload = lambda *_args, **_kwargs: {}
    register._s2cpa.upload_grok2api_accounts_remote = (
        lambda *args, **kwargs: uploads.append((args, kwargs))
        or {
            "grok_build": "build.json",
            "grok_web": "web.json",
            "grok_console": "console.json",
        }
    )
    try:
        result = register.add_sso_to_cpa(
            "sso=example-sso-token-value-1234567890",
            email="user@example.test",
        )
    finally:
        (
            register._resolve_cpa_proxy,
            register._s2cpa.sso_to_token,
            register._s2cpa.token_to_cpa_record,
            register._s2cpa.decode_jwt_payload,
            register._s2cpa.upload_grok2api_accounts_remote,
        ) = previous_functions
        for key, value in previous_config.items():
            if value is None:
                register.config.pop(key, None)
            else:
                register.config[key] = value

    assert result is True
    assert len(uploads) == 1
    args, kwargs = uploads[0]
    assert args == (
        "https://grok2api.example.test",
        "operator",
        "example-password",
        token,
    )
    assert kwargs == {
        "sso": "example-sso-token-value-1234567890",
        "email": "user@example.test",
        "proxy": account_proxy,
        "account_types": ("grok_build", "grok_web", "grok_console"),
    }


if __name__ == "__main__":
    test_registration_uploads_selected_grok2api_account_types()
    print("OK grok2api worker integration")
