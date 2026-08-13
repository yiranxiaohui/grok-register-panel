#!/usr/bin/env python3
"""Orchestrate target-based or continuous registration batches."""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
import urllib.request
from collections import Counter
from pathlib import Path

from runtime_platform import batch_launch_command, popen_group_kwargs, runtime_python
from retry_policy import PRECHECK_EXIT_CODE, orchestrator_failure_limit
from secure_files import append_private_text, best_effort_fchmod, ensure_private_dir
from webui.blacklist_store import add_asn as add_blacklist_asn
from webui.blacklist_store import read_blacklist
from webui.proxy_store import read_proxy_pool, start_proxy_tests
from webui.process_utils import (
    find_managed_processes,
    terminate_managed_processes,
    write_pid_file,
)

ROOT = Path(__file__).resolve().parent
AUTHS = Path(__import__("os").environ.get("CPA_AUTH_DIR", str(ROOT / "cpa_auth")))
LOG_DIR = ROOT / "log"
RESULTS = LOG_DIR / "register_results.jsonl"
ORCH_LOG = LOG_DIR / f"orch100-fixed-{time.strftime('%Y%m%d-%H%M%S')}.log"
WORKERS = 3
BASE0 = int(__import__("os").environ.get("ORCH_BASE_CPA", "0") or 0)
TARGET_CPA = BASE0 + int(__import__("os").environ.get("ORCH_ADD_COUNT", "100") or 100)
RISK_PAUSE = 10
MAX_ROUNDS = 60
CONTINUOUS = False
CONTINUOUS_BATCH_COUNT = 40
PROXY_COOLDOWN_POLL_SECONDS = 30
PROXY_TEST_POLL_SECONDS = 2
CONTROL_FILE = LOG_DIR / "monitor_control.json"


def load_control() -> dict:
    try:
        if CONTROL_FILE.exists():
            return json.loads(CONTROL_FILE.read_text() or "{}")
    except Exception:
        pass
    return {}


def apply_control() -> None:
    global WORKERS, RISK_PAUSE, TARGET_CPA, BASE0, CONTINUOUS
    c = load_control()
    CONTINUOUS = c.get("mode") == "continuous"
    if c.get("workers"):
        try:
            WORKERS = max(1, min(24, int(c["workers"])))
        except Exception:
            pass
    if c.get("risk_pause"):
        try:
            RISK_PAUSE = max(1, int(c["risk_pause"]))
        except Exception:
            pass
    if CONTINUOUS:
        BASE0 = cpa_count()
        return
    # 再跑 N 个：以当前 CPA 为基线
    add_count = c.get("add_count")
    if add_count is not None and str(add_count).strip() != "":
        try:
            n = max(1, int(add_count))
            now = len(list(AUTHS.glob("xai-*.json")))
            BASE0 = now
            TARGET_CPA = now + n
            return
        except Exception:
            pass
    if c.get("target_cpa"):
        try:
            TARGET_CPA = int(c["target_cpa"])
        except Exception:
            pass
    if c.get("base_cpa") is not None:
        try:
            BASE0 = int(c["base_cpa"])
        except Exception:
            pass

os.chdir(ROOT)
ensure_private_dir(LOG_DIR)


def log(msg: str) -> None:
    from runtime_platform import beijing_strftime

    line = f"[{beijing_strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    append_private_text(ORCH_LOG, line + "\n")


def cpa_count() -> int:
    return len(list(AUTHS.glob("xai-*.json")))


def kill_batch() -> None:
    """Stop only batch processes that belong to this project root."""
    terminate_managed_processes(ROOT, ("run_batch_headless.py",))


def start_batch(count: int):
    logname = LOG_DIR / f"batch-orch-{time.strftime('%Y%m%d-%H%M%S')}-n{count}.log"
    fd = os.open(logname, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    best_effort_fchmod(fd, 0o600)
    fout = os.fdopen(fd, "w", encoding="utf-8")
    try:
        proc = subprocess.Popen(
            batch_launch_command(
                ROOT,
                count,
                WORKERS,
                python_path=runtime_python(ROOT),
            ),
            cwd=str(ROOT),
            stdout=fout,
            stderr=subprocess.STDOUT,
            **popen_group_kwargs(),
        )
    finally:
        fout.close()
    write_pid_file(LOG_DIR / "batch100.pid", proc.pid)
    log(f"started pid={proc.pid} count={count} workers={WORKERS} log={logname.name}")
    return proc, logname


def read_blocklist_asns() -> set:
    return set(read_blacklist().get("asns") or {7922, 5650})


def add_asn_to_blocklist(asn: int, isp_hint: str = "") -> bool:
    if int(asn) in read_blocklist_asns():
        log(f"ASN{asn} already blocked")
        return False
    added = add_blacklist_asn(asn, isp_hint, source="auto")
    if added:
        clean_hint = re.sub(r"\s+", " ", str(isp_hint or "")).strip()[:80]
        log(f"ADDED blacklist AS{int(asn)} ({clean_hint})")
    return added


def lookup_asn(ip: str, timeout: float = 5.0) -> dict:
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        data = json.loads(opener.open(f"https://ipwho.is/{ip}", timeout=timeout).read())
        conn = data.get("connection") or {}
        asn = int(conn.get("asn"))
        return {
            "asn": asn,
            "isp": re.sub(r"\s+", " ", str(conn.get("isp") or "")).strip()[:120],
            "org": re.sub(r"\s+", " ", str(conn.get("org") or "")).strip()[:120],
            "city": re.sub(r"\s+", " ", str(data.get("city") or "")).strip()[:80],
        }
    except Exception as e:
        return {"error": str(e)}


def count_risk(logpath: Path) -> int:
    """只计注册风控拒绝次数（SSO超时/其它失败不计）。

    优先 [结果] status=risk（每号一行）；否则 失败 [注册风控]。
    """
    if not logpath.exists():
        return 0
    text = logpath.read_text(errors="replace")
    n = len(re.findall(r"\[结果\] status=risk\b", text))
    if n > 0:
        return n
    return len(re.findall(r"\[-\] 失败 \[注册风控\]", text))


def count_ok(logpath: Path) -> int:
    if not logpath.exists():
        return 0
    return len(re.findall(r"\[\+\] 注册成功:", logpath.read_text(errors="replace")))


def analyze_risks_and_expand(logpath: Path) -> list:
    """Add ASN to blacklist if risk-only and enough samples. Bounded time."""
    added = []
    t0 = time.time()
    blocked = read_blocklist_asns()
    risk_ips: list[str] = []
    ok_ips: list[str] = []

    if logpath.exists():
        text = logpath.read_text(errors="replace")
        worker_ip: dict[str, str] = {}
        for line in text.splitlines():
            m = re.match(r"\[\d+:\d+:\d+\] \[(W\d+)\] (.*)", line)
            if not m:
                continue
            w, msg = m.group(1), m.group(2)
            im = re.search(r"出口IP=([\d.]+)", msg)
            if im:
                worker_ip[w] = im.group(1)
            # only count unique risk via result line or failure line once
            if "[结果] status=risk" in msg:
                im2 = re.search(r"ip=([\d.]+)", msg)
                if im2:
                    risk_ips.append(im2.group(1))
                elif worker_ip.get(w):
                    risk_ips.append(worker_ip[w])
            elif "[-] 失败 [注册风控]" in msg and worker_ip.get(w):
                # only if no result line captured this ip already this second - still may dup
                risk_ips.append(worker_ip[w])
            if "[结果] status=ok" in msg:
                im2 = re.search(r"ip=([\d.]+)", msg)
                if im2:
                    ok_ips.append(im2.group(1))

    # dedupe preserve order
    def uniq(seq):
        seen = set()
        out = []
        for x in seq:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out

    risk_ips = uniq(risk_ips)
    ok_ips = uniq(ok_ips)

    risk_as: Counter = Counter()
    ok_as: Counter = Counter()
    meta_by_as = {}

    # cap lookups
    for ip in risk_ips[:20]:
        if time.time() - t0 > 45:
            log("analyze timeout, stop ASN lookups")
            break
        meta = lookup_asn(ip, timeout=5)
        a = meta.get("asn")
        if a is None:
            log(f"  lookup fail ip={ip} {meta.get('error')}")
            continue
        risk_as[a] += 1
        meta_by_as[a] = meta
    for ip in ok_ips[:30]:
        if time.time() - t0 > 55:
            break
        meta = lookup_asn(ip, timeout=5)
        a = meta.get("asn")
        if a is None:
            continue
        ok_as[a] += 1

    log(f"analyze risk_ips={risk_ips} risk_as={dict(risk_as)} ok_as={dict(ok_as)}")
    for asn, nbad in risk_as.most_common():
        if asn in blocked:
            continue
        nok = ok_as.get(asn, 0)
        meta = meta_by_as.get(asn) or {}
        isp = meta.get("isp") or meta.get("org") or ""
        # only-bad with >=2 unique risk IPs, or >=3 risk hits
        if nok == 0 and nbad >= 2:
            if add_asn_to_blocklist(int(asn), isp):
                added.append(asn)
                blocked.add(asn)
        elif nok == 0 and nbad >= 1 and len(risk_ips) >= 5:
            # after full pause at 5 risks, allow single-ASN only-bad add
            if add_asn_to_blocklist(int(asn), isp):
                added.append(asn)
                blocked.add(asn)
    log(f"analyze done in {time.time()-t0:.1f}s added={added}")
    return added


def batch_alive(pid: int) -> bool:
    del pid
    return bool(find_managed_processes(ROOT, ("run_batch_headless.py",)))


def wait_for_continuous_proxy_pool() -> bool:
    """Wait while every enabled managed proxy is cooling down.

    Returns whether a cooldown/test wait was entered. Risk cooldowns become
    healthy through the store's normal expiry path. Network cooldowns are
    explicitly probed after expiry before they can be reused.
    """
    if not CONTINUOUS:
        return False

    waited = False
    network_ids: set[str] = set()
    while True:
        try:
            pool = read_proxy_pool()
        except Exception as exc:
            log(f"[proxy-wait] unable to read proxy pool: {exc}")
            return waited

        items = list(pool.get("items") or [])
        if not items:
            return waited
        enabled = [item for item in items if item.get("enabled")]
        if not enabled:
            return waited
        if any(item.get("stored_status") == "healthy" for item in enabled):
            if waited:
                log("[proxy-wait] healthy proxy available, continuous registration resumes")
            return waited

        test_job = pool.get("test_job") or {}
        if test_job.get("running"):
            if not waited:
                log("[proxy-wait] proxy retest is running, waiting for result")
            waited = True
            time.sleep(PROXY_TEST_POLL_SECONDS)
            continue

        cooling = [
            item
            for item in enabled
            if item.get("stored_status") == "cooldown"
        ]
        if len(cooling) == len(enabled):
            waited = True
            for item in cooling:
                if item.get("cooldown_reason") == "network" and item.get("id"):
                    network_ids.add(str(item["id"]))
            remaining = max(
                1,
                min(int(item.get("cooldown_remaining_seconds") or 1) for item in cooling),
            )
            sleep_seconds = min(remaining, PROXY_COOLDOWN_POLL_SECONDS)
            log(
                f"[proxy-wait] all {len(enabled)} enabled proxies cooling down; "
                f"next retry in {sleep_seconds}s (earliest expiry {remaining}s)"
            )
            time.sleep(sleep_seconds)
            continue

        retest_ids = [
            str(item.get("id"))
            for item in enabled
            if str(item.get("id") or "") in network_ids
            and item.get("stored_status") == "unknown"
        ]
        if retest_ids:
            result = start_proxy_tests(retest_ids)
            if result.get("ok") or result.get("running"):
                waited = True
                log(
                    f"[proxy-wait] network cooldown expired; "
                    f"retesting {len(retest_ids)} proxy(s) before reuse"
                )
                time.sleep(PROXY_TEST_POLL_SECONDS)
                continue
            log(
                f"[proxy-wait] unable to start proxy retest: "
                f"{result.get('error') or 'unknown error'}"
            )
        return waited


def main():
    apply_control()
    kill_batch()
    current = cpa_count()
    if CONTINUOUS:
        log(
            f"ORCH continuous start cpa_now={current} base0={BASE0} "
            f"batch_size={CONTINUOUS_BATCH_COUNT}"
        )
    else:
        log(
            f"ORCH target start cpa_now={current} base0={BASE0} "
            f"target={TARGET_CPA} need={TARGET_CPA - current}"
        )
    need0 = TARGET_CPA - current
    if not CONTINUOUS and need0 <= 0:
        log(f"TARGET already met (need={need0}). Set monitor add_count / target_cpa then restart.")
        log(f"ORCH DONE cpa={cpa_count()} delta={cpa_count() - BASE0} target={TARGET_CPA} rounds=0")
        log(f"final blocklist={sorted(read_blocklist_asns())}")
        return

    log(f"rules: workers={WORKERS} pause_on_risk_only={RISK_PAUSE} SSO ignored block={sorted(read_blocklist_asns())}")
    
    round_i = 0
    consecutive_batch_failures = 0
    failure_limit = orchestrator_failure_limit()
    while CONTINUOUS or (cpa_count() < TARGET_CPA and round_i < MAX_ROUNDS):
        if CONTINUOUS:
            wait_for_continuous_proxy_pool()
        round_i += 1
        current = cpa_count()
        need = None if CONTINUOUS else TARGET_CPA - current
        batch_n = (
            CONTINUOUS_BATCH_COUNT
            if CONTINUOUS
            else min(max(int(need) + 8, 15), 40)
        )
        goal = "continuous" if CONTINUOUS else f"need={need}"
        log(
            f"=== ROUND {round_i} {goal} batch_n={batch_n} cpa={current} "
            f"block={sorted(read_blocklist_asns())} ==="
        )
        try:
            proc, logpath = start_batch(batch_n)
        except Exception as e:
            log(f"start_batch failed: {e}")
            consecutive_batch_failures += 1
            if consecutive_batch_failures >= failure_limit:
                log(
                    f"ORCH STOP consecutive batch start failures="
                    f"{consecutive_batch_failures}/{failure_limit}"
                )
                return
            time.sleep(5)
            continue
        t0 = time.time()
        while True:
            time.sleep(15)
            try:
                alive = proc.poll() is None and batch_alive(proc.pid)
            except Exception:
                alive = False
            risks = count_risk(logpath)
            oks = count_ok(logpath)
            delta = cpa_count() - BASE0
            delta_goal = "continuous" if CONTINUOUS else str(max(TARGET_CPA - BASE0, 0))
            log(f"  mon ok={oks} risk={risks} cpa_delta={delta}/{delta_goal} alive={alive}")
            if not CONTINUOUS and cpa_count() >= TARGET_CPA:
                log("TARGET reached")
                kill_batch()
                break
            if risks >= RISK_PAUSE:
                log(f"  HIT {RISK_PAUSE} 注册风控 rejects (risk={risks}), pause+blacklist")
                kill_batch()
                try:
                    added = analyze_risks_and_expand(logpath)
                    log(f"  added={added} block={sorted(read_blocklist_asns())}")
                except Exception as e:
                    log(f"  analyze error (continue anyway): {e}")
                break
            if not alive:
                return_code = proc.poll()
                log(f"  batch exited rc={return_code}")
                if (
                    CONTINUOUS
                    and return_code not in (0, None)
                    and wait_for_continuous_proxy_pool()
                ):
                    consecutive_batch_failures = 0
                    log(
                        "  batch failure was caused by proxy cooldown; "
                        "starting a new round"
                    )
                    break
                if return_code == PRECHECK_EXIT_CODE:
                    log("ORCH STOP xAI registration page precheck failed")
                    return
                if return_code not in (0, None):
                    consecutive_batch_failures += 1
                    if consecutive_batch_failures >= failure_limit:
                        log(
                            f"ORCH STOP consecutive batch failures="
                            f"{consecutive_batch_failures}/{failure_limit}"
                        )
                        return
                else:
                    consecutive_batch_failures = 0
                try:
                    analyze_risks_and_expand(logpath)
                except Exception as e:
                    log(f"  analyze error: {e}")
                break
            if time.time() - t0 > 2400:
                log("  round timeout 40m, restart")
                kill_batch()
                break
        time.sleep(3)
        if not CONTINUOUS and cpa_count() >= TARGET_CPA:
            break

    final = cpa_count()
    target_label = "continuous" if CONTINUOUS else str(TARGET_CPA)
    log(f"ORCH DONE cpa={final} delta={final - BASE0} target={target_label} rounds={round_i}")
    log(f"final blocklist={sorted(read_blocklist_asns())}")
    print(f"SUMMARY delta={final - BASE0} cpa={final} log={ORCH_LOG}", flush=True)


if __name__ == "__main__":
    main()
