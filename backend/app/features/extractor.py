"""Plan feature extractor producing 38-feature numerical vectors for ML inference."""

from __future__ import annotations

import json
import re
from typing import Any
import numpy as np

# Inspection regex patterns aligned with ArgumentInspector
SQL_RE = re.compile(r"(?i)\b(UNION\s+SELECT|DROP\s+TABLE|OR\s+1=1|--|\bSELECT\b.*\bFROM\b)")
TRAVERSAL_RE = re.compile(r"(\.\./|\.\.\\)")
SENSITIVE_PATH_RE = re.compile(r"(?i)(/etc/passwd|/etc/shadow|\.ssh/|id_rsa|\.aws/credentials|\.env)")
IPV4_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
CREDENTIAL_RE = re.compile(r"(?i)(password|secret|bearer\s+[a-z0-9_\-\.]+|api[_-]?key|private[_-]?key)")
BASE64_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{40,}={0,2})\b")
PII_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b|\b\d{3}-\d{2}-\d{4}\b")

KNOWN_TOOLS = {
    "database_query": "tool_db_query_count",
    "file_read": "tool_file_read_count",
    "file_write": "tool_file_write_count",
    "http_post": "tool_http_post_count",
    "email_send": "tool_email_send_count",
    "shell_exec": "tool_shell_exec_count",
    "directory_search": "tool_directory_search_count",
}

FEATURE_NAMES = [
    "step_count",
    "unique_tool_count",
    "tool_db_query_count",
    "tool_file_read_count",
    "tool_file_write_count",
    "tool_http_post_count",
    "tool_email_send_count",
    "tool_shell_exec_count",
    "tool_directory_search_count",
    "tool_unknown_count",
    "has_write_operation",
    "write_step_count",
    "has_irreversible_step",
    "irreversible_step_count",
    "perm_required_count",
    "perm_admin_count",
    "perm_network_ext_count",
    "perm_filesystem_count",
    "dest_external_count",
    "dest_has_ip_literal",
    "sens_count_public",
    "sens_count_internal",
    "sens_count_confidential",
    "sens_count_restricted",
    "sens_count_secret",
    "has_sensitive_data",
    "arg_sql_keyword_count",
    "arg_path_traversal_count",
    "arg_sensitive_path_count",
    "arg_suspicious_url_count",
    "arg_encoded_payload_count",
    "arg_credential_pattern_count",
    "arg_pii_pattern_count",
    "kill_chain_recon_count",
    "kill_chain_access_count",
    "kill_chain_exfil_count",
    "mcp_server_count",
    "mcp_resource_uri_count",
]

# Diagnostic features kept for observability but excluded from model input vector
DIAGNOSTIC_FEATURE_NAMES = [
    "total_estimated_cost",
    "max_step_cost",
    "arg_total_length",
    "arg_max_length",
]


def extract_features_dict(plan: dict[str, Any], mcp_meta: dict[str, Any] | None = None) -> dict[str, float]:
    """Extract a dictionary mapping feature names to float values, including diagnostic features."""
    steps = plan.get("steps", [])
    if not isinstance(steps, list):
        steps = [plan] if isinstance(plan, dict) else []

    step_count = len(steps)
    tools_seen = set()
    tool_counts = {v: 0.0 for v in KNOWN_TOOLS.values()}
    unknown_tools = 0.0

    write_count = 0.0
    irrev_count = 0.0
    total_cost = 0.0
    max_cost = 0.0

    perm_count = 0.0
    perm_admin = 0.0
    perm_net_ext = 0.0
    perm_fs = 0.0

    dest_ext = 0.0
    dest_ip = 0.0

    sens_pub = 0.0
    sens_int = 0.0
    sens_conf = 0.0
    sens_rest = 0.0
    sens_sec = 0.0

    arg_tot_len = 0.0
    arg_max_len = 0.0
    sql_hits = 0.0
    traversal_hits = 0.0
    sens_path_hits = 0.0
    susp_url_hits = 0.0
    encoded_hits = 0.0
    cred_hits = 0.0
    pii_hits = 0.0

    recon_count = 0.0
    access_count = 0.0
    exfil_count = 0.0

    for step in steps:
        if not isinstance(step, dict):
            continue

        tool_name = str(step.get("tool_name", "")).strip()
        if tool_name:
            tools_seen.add(tool_name)
            if tool_name in KNOWN_TOOLS:
                tool_counts[KNOWN_TOOLS[tool_name]] += 1.0
            else:
                unknown_tools += 1.0

        side_effect = str(step.get("side_effect_class", "")).casefold()
        if side_effect == "write":
            write_count += 1.0

        if not step.get("reversible", True):
            irrev_count += 1.0

        cost = float(step.get("estimated_cost", 0.0) or 0.0)
        total_cost += cost
        if cost > max_cost:
            max_cost = cost

        perms = step.get("permissions_required", []) or []
        if isinstance(perms, list):
            perm_count += len(perms)
            for p in perms:
                p_str = str(p).casefold()
                if "admin" in p_str or "root" in p_str:
                    perm_admin += 1.0
                if "network" in p_str or "external" in p_str or "internet" in p_str:
                    perm_net_ext += 1.0
                if "file" in p_str or "fs" in p_str:
                    perm_fs += 1.0

        dest = str(step.get("destination", "")).casefold()
        if dest == "external":
            dest_ext += 1.0

        sens = str(step.get("data_sensitivity", "")).casefold()
        if sens == "public":
            sens_pub += 1.0
        elif sens == "internal":
            sens_int += 1.0
        elif sens == "confidential":
            sens_conf += 1.0
        elif sens == "restricted":
            sens_rest += 1.0
        elif sens in {"secret", "top-secret"}:
            sens_sec += 1.0

        stage = str(step.get("kill_chain_stage", "")).casefold()
        if stage in {"recon", "discovery"}:
            recon_count += 1.0
        elif stage in {"access", "execution"}:
            access_count += 1.0
        elif stage in {"exfil", "exfiltration"}:
            exfil_count += 1.0

        # Argument text scanning
        args = step.get("arguments", {})
        arg_str = json.dumps(args, ensure_ascii=False) if isinstance(args, (dict, list)) else str(args)
        arg_len = len(arg_str)
        arg_tot_len += arg_len
        if arg_len > arg_max_len:
            arg_max_len = float(arg_len)

        if IPV4_RE.search(arg_str):
            dest_ip += 1.0
        if SQL_RE.search(arg_str):
            sql_hits += 1.0
        if TRAVERSAL_RE.search(arg_str):
            traversal_hits += 1.0
        if SENSITIVE_PATH_RE.search(arg_str):
            sens_path_hits += 1.0
        if "http://" in arg_str or "attacker.example" in arg_str:
            susp_url_hits += 1.0
        if BASE64_RE.search(arg_str):
            encoded_hits += 1.0
        if CREDENTIAL_RE.search(arg_str):
            cred_hits += 1.0
        if PII_RE.search(arg_str):
            pii_hits += 1.0

    # MCP metadata
    mcp_server = 1.0 if (mcp_meta and mcp_meta.get("server_name")) else 0.0
    mcp_resources = float(len(mcp_meta.get("resource_uris") or [])) if mcp_meta else 0.0

    res = {
        "step_count": float(step_count),
        "unique_tool_count": float(len(tools_seen)),
        "tool_db_query_count": tool_counts["tool_db_query_count"],
        "tool_file_read_count": tool_counts["tool_file_read_count"],
        "tool_file_write_count": tool_counts["tool_file_write_count"],
        "tool_http_post_count": tool_counts["tool_http_post_count"],
        "tool_email_send_count": tool_counts["tool_email_send_count"],
        "tool_shell_exec_count": tool_counts["tool_shell_exec_count"],
        "tool_directory_search_count": tool_counts["tool_directory_search_count"],
        "tool_unknown_count": unknown_tools,
        "has_write_operation": 1.0 if write_count > 0 else 0.0,
        "write_step_count": write_count,
        "has_irreversible_step": 1.0 if irrev_count > 0 else 0.0,
        "irreversible_step_count": irrev_count,
        "perm_required_count": perm_count,
        "perm_admin_count": perm_admin,
        "perm_network_ext_count": perm_net_ext,
        "perm_filesystem_count": perm_fs,
        "dest_external_count": dest_ext,
        "dest_has_ip_literal": dest_ip,
        "sens_count_public": sens_pub,
        "sens_count_internal": sens_int,
        "sens_count_confidential": sens_conf,
        "sens_count_restricted": sens_rest,
        "sens_count_secret": sens_sec,
        "has_sensitive_data": 1.0 if (sens_conf + sens_rest + sens_sec) > 0 else 0.0,
        "arg_sql_keyword_count": sql_hits,
        "arg_path_traversal_count": traversal_hits,
        "arg_sensitive_path_count": sens_path_hits,
        "arg_suspicious_url_count": susp_url_hits,
        "arg_encoded_payload_count": encoded_hits,
        "arg_credential_pattern_count": cred_hits,
        "arg_pii_pattern_count": pii_hits,
        "kill_chain_recon_count": recon_count,
        "kill_chain_access_count": access_count,
        "kill_chain_exfil_count": exfil_count,
        "mcp_server_count": mcp_server,
        "mcp_resource_uri_count": mcp_resources,
        # Diagnostics (accessible via dict, excluded from FEATURE_NAMES)
        "total_estimated_cost": total_cost,
        "max_step_cost": max_cost,
        "arg_total_length": arg_tot_len,
        "arg_max_length": arg_max_len,
    }
    return res


def extract_features(plan: dict[str, Any], mcp_meta: dict[str, Any] | None = None) -> np.ndarray:
    """Extract a 1D NumPy array with exactly 38 floats in the canonical feature order."""
    f_dict = extract_features_dict(plan, mcp_meta)
    return np.array([f_dict[k] for k in FEATURE_NAMES], dtype=float)
