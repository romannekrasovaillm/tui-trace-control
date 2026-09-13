#!/usr/bin/env python3
"""Bounded, read-only checks for the TUI trace protocol v1. No enforcement."""

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
import posixpath
import re
import stat
import sys

VERSION = "1.0.0"
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
KINDS = {"heartbeat", "tool_call", "tool_result", "message", "lifecycle", "coverage_gap", "policy_change"}
ORIGINS = {"runner", "collector", "worker", "external"}
OPERATIONS = {"read", "write", "delete", "network", "shell", "spawn", "credentials_read", "privilege_change", "monitor_change", "trace_delete"}
MAX_CONFIG = 1024 * 1024
HARD_MAX_FILE = 64 * 1024 * 1024
HARD_MAX_LINE = 1024 * 1024


class InputError(Exception):
    """Static error code; never include raw payloads or secret values."""


def digest(data):
    return hashlib.sha256(data).hexdigest()


def integer(value, minimum=0, maximum=10**9):
    return type(value) is int and minimum <= value <= maximum


def token(value):
    return isinstance(value, str) and TOKEN.fullmatch(value) is not None


def pairs_unique(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise InputError("duplicate_json_key")
        obj[key] = value
    return obj


def reject_constant(_):
    raise InputError("nonfinite_json_number")


def parse_json(data):
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=pairs_unique,
                          parse_constant=reject_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise InputError("invalid_json") from exc


def instant(value):
    if not isinstance(value, str) or len(value) > 64:
        raise InputError("invalid_timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError()
        return parsed.astimezone(dt.timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise InputError("invalid_timestamp") from exc


def path_value(value):
    if not isinstance(value, str) or not value.startswith("/") or value.startswith("//") or "\x00" in value:
        raise InputError("invalid_absolute_path")
    return posixpath.normpath(value)


def host_value(value):
    if not isinstance(value, str) or not value or len(value) > 253:
        raise InputError("invalid_host")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    try:
        host = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise InputError("invalid_host") from exc
    labels = host.split(".")
    if not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
        raise InputError("invalid_host")
    return host


def within(path, roots):
    return any(root == "/" or path == root or path.startswith(root + "/") for root in roots)


def read_regular(path, maximum):
    """Walk by directory FDs, rejecting links and special files, then read a stable prefix."""
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise InputError("platform_not_supported")
    absolute = os.path.abspath(path)
    parts = absolute.split("/")[1:]
    directory_fd = None
    file_fd = None
    try:
        directory_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode):
            raise InputError("not_regular_file")
        if before.st_size > maximum:
            raise InputError("file_size_limit")
        chunks = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(file_fd, min(remaining, 65536))
            if not chunk:
                raise InputError("file_changed_during_read")
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        os.lseek(file_fd, 0, os.SEEK_SET)
        check = hashlib.sha256()
        remaining = len(data)
        while remaining:
            chunk = os.read(file_fd, min(remaining, 65536))
            if not chunk:
                raise InputError("file_changed_during_read")
            check.update(chunk)
            remaining -= len(chunk)
        after = os.fstat(file_fd)
        if check.hexdigest() != digest(data) or after.st_size < before.st_size:
            raise InputError("file_changed_during_read")
        return data, {"path": absolute, "device": before.st_dev, "inode": before.st_ino,
                      "size_at_open": before.st_size, "size_after_read": after.st_size}
    except OSError as exc:
        raise InputError("file_unavailable_or_unsafe") from exc
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if directory_fd is not None:
            os.close(directory_fd)


def contract_check(obj):
    if not isinstance(obj, dict) or type(obj.get("schema_version")) is not int or obj["schema_version"] != 1:
        raise InputError("invalid_contract_version")
    if not token(obj.get("run_id")) or not token(obj.get("contract_id")) or obj.get("mode") not in {"observe", "enforce"}:
        raise InputError("invalid_contract_identity")
    scope, monitor = obj.get("scope"), obj.get("monitor")
    if not isinstance(scope, dict) or not isinstance(monitor, dict):
        raise InputError("invalid_contract_sections")
    for key in ("read_roots", "write_roots", "protected_roots", "allowed_hosts", "allowed_tools", "allowed_operations", "denied_operations"):
        values = scope.get(key)
        if not isinstance(values, list):
            raise InputError("invalid_contract_list")
        fn = path_value if key.endswith("roots") else host_value if key == "allowed_hosts" else None
        if fn:
            scope[key] = [fn(v) for v in values]
        elif not all(token(v) for v in values):
            raise InputError("invalid_contract_token")
    for key in ("max_tool_calls", "max_consecutive_failures"):
        if not integer(scope.get(key), 1):
            raise InputError("invalid_contract_limit")
    agents = monitor.get("expected_agents")
    if not isinstance(agents, list) or not agents or not all(token(v) for v in agents) or len(set(agents)) != len(agents):
        raise InputError("invalid_expected_agents")
    for key in ("poll_seconds", "heartbeat_seconds", "heartbeat_timeout_seconds"):
        if not integer(monitor.get(key), 1, 86400):
            raise InputError("invalid_monitor_interval")
    if monitor["heartbeat_timeout_seconds"] < monitor["heartbeat_seconds"]:
        raise InputError("invalid_heartbeat_timeout")
    if not integer(monitor.get("clock_skew_seconds"), 0, 3600):
        raise InputError("invalid_clock_skew")
    for key, cap in (("max_line_bytes", HARD_MAX_LINE), ("max_file_bytes", HARD_MAX_FILE), ("max_events", 100000)):
        if not integer(monitor.get(key), 1, cap):
            raise InputError("invalid_parser_limit")
    return obj


class Report:
    def __init__(self, now):
        self.obj = {"report_schema_version": 1, "scanner_version": VERSION,
                    "created_at": now.isoformat(), "enforcement_performed": False,
                    "findings": [], "coverage_issues": []}

    def add(self, rule, severity="medium", location=None, coverage=False):
        item = {"rule": rule, "severity": severity}
        if location:
            item.update(location)
        identity = {"run_id": self.obj.get("run_id"), "contract_id": self.obj.get("contract_id"), **item}
        item["finding_id"] = digest(json.dumps(identity, sort_keys=True).encode())[:20]
        self.obj["coverage_issues" if coverage else "findings"].append(item)

    def finish(self):
        findings = self.obj["findings"]
        if any(f["severity"] in {"high", "critical"} for f in findings):
            verdict, code = "pause_required", 20
        elif self.obj["coverage_issues"]:
            verdict, code = "indeterminate", 30
        elif findings:
            verdict, code = "review", 10
        else:
            verdict, code = "no_findings", 0
        self.obj.update(verdict=verdict, exit_code=code,
                        coverage="incomplete" if self.obj["coverage_issues"] else "no_structural_gaps_detected")
        return self.obj, code


def previous_check(previous, report, current, committed, meta, contract_hash, run_id, contract_id):
    if not isinstance(previous, dict) or previous.get("report_schema_version") != 1 or not isinstance(previous.get("input"), dict):
        raise InputError("invalid_previous_report")
    old = previous["input"]
    count, sha = old.get("committed_bytes"), old.get("sha256")
    if not integer(count, 0, HARD_MAX_FILE) or not isinstance(sha, str) or not re.fullmatch("[0-9a-f]{64}", sha):
        raise InputError("invalid_previous_prefix")
    if not isinstance(previous.get("contract_sha256"), str) or previous.get("run_id") != run_id or previous.get("contract_id") != contract_id:
        raise InputError("previous_identity_mismatch")
    if previous["contract_sha256"] != contract_hash:
        report.add("contract_changed_since_baseline", "high")
    if any(old.get(k) != meta[k] for k in ("path", "device", "inode")):
        report.add("trace_identity_changed", "high")
    if count > committed:
        report.add("trace_truncated_since_baseline", "high")
    elif digest(current[:count]) != sha:
        report.add("trace_prefix_changed", "high")


def scan(args):
    now = instant(args.now) if args.now else dt.datetime.now(dt.timezone.utc)
    report = Report(now)
    try:
        contract_raw, _ = read_regular(args.contract, MAX_CONFIG)
        cfg = contract_check(parse_json(contract_raw))
        scope, monitor = cfg["scope"], cfg["monitor"]
        run_id, contract_id = cfg["run_id"], cfg["contract_id"]
        contract_hash = digest(contract_raw)
        report.obj.update(run_id=run_id, contract_id=contract_id, contract_sha256=contract_hash,
                          mode=cfg["mode"], replay_clock=bool(args.now), final=bool(args.final))
        data, meta = read_regular(args.trace, monitor["max_file_bytes"])
        committed = data.rfind(b"\n") + 1
        report.obj["input"] = dict(meta, committed_bytes=committed, sha256=digest(data[:committed]),
                                   snapshot_sha256=digest(data), tail_bytes=len(data) - committed)
        if not data:
            report.add("empty_trace", coverage=True)
        if committed != len(data):
            report.add("partial_last_line", coverage=True)
        if args.previous:
            raw, _ = read_regular(args.previous, HARD_MAX_FILE)
            previous_check(parse_json(raw), report, data, committed, meta, contract_hash, run_id, contract_id)
            report.obj["continuity"] = "compared_to_previous"
        else:
            report.obj["continuity"] = "first_snapshot_no_external_baseline"
        expected = set(monitor["expected_agents"])
        seen_ids, seqs, timestamps, beats, calls, finished, failures = set(), {}, {}, {}, {}, set(), {}
        valid_events, tool_count, offset = 0, 0, 0
        for line_number, raw_line in enumerate(data[:committed].split(b"\n")[:-1], 1):
            line = raw_line + b"\n"
            loc = {"line": line_number, "byte_start": offset, "byte_end": offset + len(line)}
            offset += len(line)
            if line_number > monitor["max_events"]:
                report.add("event_limit", location=loc, coverage=True)
                break
            if len(line) > monitor["max_line_bytes"]:
                report.add("line_size_limit", location=loc, coverage=True)
                continue
            try:
                event = parse_json(line)
                if not isinstance(event, dict) or type(event.get("schema_version")) is not int or event["schema_version"] != 1:
                    raise InputError("invalid_event_version")
                if any(not token(event.get(k)) for k in ("contract_id", "run_id", "agent_id", "event_id")):
                    raise InputError("invalid_event_identity")
                if not integer(event.get("seq"), 1) or not isinstance(event.get("payload"), dict):
                    raise InputError("invalid_event_envelope")
                if event.get("kind") not in KINDS or event.get("origin") not in ORIGINS:
                    raise InputError("unknown_event_kind_or_origin")
                stamp = instant(event.get("timestamp"))
                agent, eid, seq = event["agent_id"], event["event_id"], event["seq"]
                loc.update(agent_id=agent, event_id=eid)
                if event["run_id"] != run_id or event["contract_id"] != contract_id or agent not in expected:
                    raise InputError("unexpected_run_contract_or_agent")
                if eid in seen_ids:
                    raise InputError("duplicate_event_id")
                seen_ids.add(eid)
                if seq != seqs.get(agent, 0) + 1:
                    report.add("sequence_gap_or_reorder", location=loc, coverage=True)
                seqs[agent] = max(seq, seqs.get(agent, 0))
                if stamp > now + dt.timedelta(seconds=monitor["clock_skew_seconds"]):
                    report.add("future_event_timestamp", location=loc, coverage=True)
                if agent in timestamps and stamp < timestamps[agent] - dt.timedelta(seconds=monitor["clock_skew_seconds"]):
                    report.add("clock_moved_backwards", location=loc, coverage=True)
                timestamps[agent] = max(stamp, timestamps.get(agent, stamp))
                valid_events += 1
                kind, payload = event["kind"], event["payload"]
                if kind in {"heartbeat", "tool_call", "tool_result"} and event["origin"] not in {"runner", "collector"}:
                    report.add("unverified_control_event_source", location=loc, coverage=True)
                if kind == "heartbeat":
                    if event["origin"] in {"runner", "collector"} and stamp <= now + dt.timedelta(seconds=monitor["clock_skew_seconds"]):
                        beats[agent] = max(stamp, beats.get(agent, stamp))
                elif kind == "coverage_gap":
                    report.add("reported_coverage_gap", location=loc, coverage=True)
                elif kind == "policy_change":
                    report.add("reported_policy_change", location=loc)
                elif kind == "tool_call":
                    if any(not token(payload.get(k)) for k in ("call_id", "tool", "operation")):
                        raise InputError("invalid_call_fields")
                    tool_count += 1
                    key = (agent, payload["call_id"])
                    if key in calls:
                        raise InputError("duplicate_call_id")
                    calls[key] = {"tool": payload["tool"], "location": dict(loc)}
                    if tool_count == scope["max_tool_calls"] + 1:
                        report.add("tool_call_budget_exceeded", "high", loc)
                    if payload["tool"] not in scope["allowed_tools"]:
                        report.add("tool_outside_scope", "high", loc)
                    operation = payload["operation"]
                    if operation in scope["denied_operations"]:
                        report.add("operation_explicitly_denied", "high", loc)
                    elif operation not in OPERATIONS:
                        report.add("unknown_operation", location=loc, coverage=True)
                    elif operation not in scope["allowed_operations"]:
                        report.add("operation_outside_scope", "high", loc)
                    if type(payload.get("targets_complete")) is not bool or not isinstance(payload.get("targets"), list):
                        raise InputError("invalid_targets")
                    if not payload["targets_complete"]:
                        report.add("incomplete_operation_targets", location=loc, coverage=True)
                    found_path_read, found_path_write, found_host = False, False, False
                    for target in payload["targets"]:
                        if not isinstance(target, dict):
                            raise InputError("invalid_target")
                        if target.get("type") == "path":
                            value = path_value(target.get("value"))
                            access = target.get("access")
                            if access not in {"read", "write"}:
                                raise InputError("invalid_path_access")
                            found_path_read |= access == "read"
                            found_path_write |= access == "write"
                            overlaps_protected = within(value, scope["protected_roots"]) or (
                                access == "write" and any(within(root, [value]) for root in scope["protected_roots"]))
                            if overlaps_protected:
                                report.add("protected_path_target", "high", loc)
                            elif not within(value, scope[access + "_roots"]):
                                report.add("path_outside_scope", "high", loc)
                        elif target.get("type") == "host":
                            found_host = True
                            if host_value(target.get("value")) not in scope["allowed_hosts"]:
                                report.add("host_outside_scope", "high", loc)
                        else:
                            raise InputError("unknown_target_type")
                    if ((operation == "read" and not found_path_read) or
                        (operation in {"write", "delete"} and not found_path_write) or
                        (operation == "network" and not found_host)):
                        report.add("missing_required_target", location=loc, coverage=True)
                elif kind == "tool_result":
                    if not token(payload.get("call_id")) or payload.get("status") not in {"success", "error", "denied", "cancelled"}:
                        raise InputError("invalid_result_fields")
                    key = (agent, payload["call_id"])
                    if key not in calls or key in finished:
                        raise InputError("orphan_or_duplicate_result")
                    finished.add(key)
                    failure_key = (agent, calls[key]["tool"])
                    if payload["status"] == "success":
                        failures[failure_key] = 0
                    elif payload["status"] in {"error", "denied"}:
                        failures[failure_key] = failures.get(failure_key, 0) + 1
                        if failures[failure_key] == scope["max_consecutive_failures"]:
                            report.add("repeated_tool_failures", location=loc)
            except (InputError, TypeError, ValueError, OverflowError, RecursionError) as exc:
                code = str(exc) if isinstance(exc, InputError) else "invalid_event_types"
                report.add(code, location=loc, coverage=True)
        for agent in sorted(expected):
            if agent not in beats:
                report.add("missing_heartbeat", location={"agent_id": agent}, coverage=True)
            elif (now - beats[agent]).total_seconds() > monitor["heartbeat_timeout_seconds"]:
                report.add("stale_heartbeat", location={"agent_id": agent}, coverage=True)
        if args.final:
            for key in calls.keys() - finished:
                report.add("missing_final_tool_result", location=calls[key]["location"], coverage=True)
        report.obj["stats"] = {"valid_envelope_events": valid_events, "tool_calls": tool_count,
                               "open_calls": len(calls.keys() - finished), "expected_agents": len(expected),
                               "agents_with_events": len(seqs), "last_seq": seqs}
    except (InputError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        report.add(str(exc) if isinstance(exc, InputError) else "invalid_input_types", coverage=True)
    return report.finish()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", required=True)
    parser.add_argument("--trace", required=True)
    parser.add_argument("--previous")
    parser.add_argument("--now", help="Replay/test clock, ISO 8601 with timezone; omit for live monitoring")
    parser.add_argument("--final", action="store_true", help="Require every tool call to have a result")
    args = parser.parse_args()
    try:
        result, code = scan(args)
    except InputError as exc:
        report = Report(dt.datetime.now(dt.timezone.utc))
        report.add(str(exc), coverage=True)
        result, code = report.finish()
    print(json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
