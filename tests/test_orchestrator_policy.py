#!/usr/bin/env python3
from __future__ import annotations

import tempfile
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import run_until_100 as orch
from retry_policy import PRECHECK_EXIT_CODE


class FakeProcess:
    def __init__(self, pid: int, return_code: int):
        self.pid = pid
        self.return_code = return_code

    def poll(self):
        return self.return_code


def _run_with_exit_codes(exit_codes, *, continuous=False, proxy_waits=()):
    names = (
        "apply_control",
        "kill_batch",
        "cpa_count",
        "read_blocklist_asns",
        "start_batch",
        "batch_alive",
        "count_risk",
        "count_ok",
        "analyze_risks_and_expand",
        "orchestrator_failure_limit",
        "wait_for_continuous_proxy_pool",
        "log",
    )
    previous = {name: getattr(orch, name) for name in names}
    previous_base = orch.BASE0
    previous_target = orch.TARGET_CPA
    previous_rounds = orch.MAX_ROUNDS
    previous_continuous = orch.CONTINUOUS
    launches = []
    batch_counts = []
    messages = []
    codes = iter(exit_codes)
    wait_results = iter(proxy_waits)
    try:
        with tempfile.TemporaryDirectory() as temp:
            log_path = Path(temp) / "batch.log"
            log_path.write_text("", encoding="utf-8")
            orch.BASE0 = 0
            orch.TARGET_CPA = 1
            orch.MAX_ROUNDS = 10
            orch.CONTINUOUS = continuous
            orch.apply_control = lambda: None
            orch.kill_batch = lambda: None
            orch.cpa_count = lambda: 0
            orch.read_blocklist_asns = lambda: set()
            orch.batch_alive = lambda _pid: False
            orch.count_risk = lambda _path: 0
            orch.count_ok = lambda _path: 0
            orch.analyze_risks_and_expand = lambda _path: []
            orch.orchestrator_failure_limit = lambda: 2
            orch.wait_for_continuous_proxy_pool = lambda: next(wait_results, False)
            orch.log = messages.append

            def start_batch(count):
                code = next(codes)
                launches.append(code)
                batch_counts.append(count)
                return FakeProcess(100 + len(launches), code), log_path

            orch.start_batch = start_batch
            original_sleep = orch.time.sleep
            orch.time.sleep = lambda _seconds: None
            try:
                orch.main()
            finally:
                orch.time.sleep = original_sleep
    finally:
        for name, value in previous.items():
            setattr(orch, name, value)
        orch.BASE0 = previous_base
        orch.TARGET_CPA = previous_target
        orch.MAX_ROUNDS = previous_rounds
        orch.CONTINUOUS = previous_continuous
    return launches, batch_counts, messages


def test_precheck_failure_stops_orchestrator_immediately():
    launches, _, messages = _run_with_exit_codes([PRECHECK_EXIT_CODE])
    assert launches == [PRECHECK_EXIT_CODE]
    assert any("precheck failed" in message for message in messages)


def test_consecutive_abnormal_batches_are_bounded():
    launches, _, messages = _run_with_exit_codes([1, 1, 1])
    assert launches == [1, 1]
    assert any("consecutive batch failures=2/2" in message for message in messages)


def test_continuous_mode_starts_successive_fixed_batches_until_safety_stop():
    launches, batch_counts, messages = _run_with_exit_codes(
        [0, PRECHECK_EXIT_CODE], continuous=True
    )
    assert launches == [0, PRECHECK_EXIT_CODE]
    assert batch_counts == [orch.CONTINUOUS_BATCH_COUNT, orch.CONTINUOUS_BATCH_COUNT]
    assert any("ROUND 2 continuous" in message for message in messages)
    assert any("precheck failed" in message for message in messages)


def test_proxy_cooldown_batch_failure_does_not_count_toward_stop_limit():
    launches, _, messages = _run_with_exit_codes(
        [1, PRECHECK_EXIT_CODE],
        continuous=True,
        proxy_waits=[False, True, False, False],
    )
    assert launches == [1, PRECHECK_EXIT_CODE]
    assert any("caused by proxy cooldown" in message for message in messages)
    assert not any("consecutive batch failures" in message for message in messages)


def _proxy_item(
    status,
    *,
    proxy_id="proxy-one",
    remaining=0,
    reason="",
    enabled=True,
):
    return {
        "id": proxy_id,
        "enabled": enabled,
        "stored_status": status,
        "cooldown_remaining_seconds": remaining,
        "cooldown_reason": reason,
    }


def _run_proxy_wait(snapshots, *, start_result=None):
    previous = {
        "CONTINUOUS": orch.CONTINUOUS,
        "read_proxy_pool": orch.read_proxy_pool,
        "start_proxy_tests": orch.start_proxy_tests,
        "log": orch.log,
        "sleep": orch.time.sleep,
    }
    messages = []
    sleeps = []
    tested = []
    remaining = list(snapshots)
    last = remaining[-1]
    try:
        orch.CONTINUOUS = True

        def read_pool():
            return remaining.pop(0) if remaining else last

        orch.read_proxy_pool = read_pool

        def start_tests(ids):
            tested.append(list(ids))
            return dict(start_result or {"ok": True, "running": True})

        orch.start_proxy_tests = start_tests
        orch.log = messages.append
        orch.time.sleep = sleeps.append
        waited = orch.wait_for_continuous_proxy_pool()
    finally:
        orch.CONTINUOUS = previous["CONTINUOUS"]
        orch.read_proxy_pool = previous["read_proxy_pool"]
        orch.start_proxy_tests = previous["start_proxy_tests"]
        orch.log = previous["log"]
        orch.time.sleep = previous["sleep"]
    return waited, sleeps, tested, messages


def test_continuous_mode_waits_until_risk_cooldown_releases_proxy():
    waited, sleeps, tested, messages = _run_proxy_wait(
        [
            {
                "items": [_proxy_item("cooldown", remaining=45, reason="risk")],
                "test_job": {"running": False},
            },
            {
                "items": [_proxy_item("healthy")],
                "test_job": {"running": False},
            },
        ]
    )
    assert waited is True
    assert sleeps == [orch.PROXY_COOLDOWN_POLL_SECONDS]
    assert tested == []
    assert any("all 1 enabled proxies cooling down" in message for message in messages)
    assert any("continuous registration resumes" in message for message in messages)


def test_continuous_mode_retests_network_proxy_after_cooldown():
    waited, sleeps, tested, messages = _run_proxy_wait(
        [
            {
                "items": [_proxy_item("cooldown", remaining=1, reason="network")],
                "test_job": {"running": False},
            },
            {
                "items": [_proxy_item("unknown")],
                "test_job": {"running": False},
            },
            {
                "items": [_proxy_item("unknown")],
                "test_job": {"running": True},
            },
            {
                "items": [_proxy_item("healthy")],
                "test_job": {"running": False},
            },
        ]
    )
    assert waited is True
    assert sleeps == [1, orch.PROXY_TEST_POLL_SECONDS, orch.PROXY_TEST_POLL_SECONDS]
    assert tested == [["proxy-one"]]
    assert any("network cooldown expired" in message for message in messages)


def test_continuous_mode_does_not_wait_for_non_cooldown_misconfiguration():
    waited, sleeps, tested, _ = _run_proxy_wait(
        [
            {
                "items": [_proxy_item("unknown")],
                "test_job": {"running": False},
            }
        ]
    )
    assert waited is False
    assert sleeps == []
    assert tested == []


if __name__ == "__main__":
    test_precheck_failure_stops_orchestrator_immediately()
    test_consecutive_abnormal_batches_are_bounded()
    test_continuous_mode_starts_successive_fixed_batches_until_safety_stop()
    test_proxy_cooldown_batch_failure_does_not_count_toward_stop_limit()
    test_continuous_mode_waits_until_risk_cooldown_releases_proxy()
    test_continuous_mode_retests_network_proxy_after_cooldown()
    test_continuous_mode_does_not_wait_for_non_cooldown_misconfiguration()
    print("OK orchestrator policy")
