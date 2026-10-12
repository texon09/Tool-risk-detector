"""Generate synthetic dataset matching all constraints of validate_dataset.py."""

import json
import os
import numpy as np
import pandas as pd

FAMILIES = [
    "data_exfiltration",
    "credential_harvesting",
    "privilege_escalation",
    "destructive",
    "injection_triggered",
    "read_and_exfil",
]

FAMILY_PROBS = [0.20, 0.20, 0.15, 0.15, 0.15, 0.15]

DIFFICULTIES = ["easy", "medium", "hard"]


def generate_feature_row(label, family, rng):
    """Generate a realistic feature row based on risk label and threat family."""
    row = {}

    if label == "SAFE":
        # Overlapping distributions: step_count 2-10, cost 0.01-50, arg_len 50-1500
        step_count = int(rng.integers(2, 11))
        cost = float(np.round(rng.uniform(0.01, 50.0), 2))
        arg_len = float(rng.integers(50, 1500))
        unique_tools = min(step_count, int(rng.integers(1, 4)))
        is_write = float(rng.choice([0.0, 1.0], p=[0.75, 0.25]))
        write_steps = int(is_write * rng.integers(1, min(step_count + 1, 3)))
        irrev = 0.0 if rng.random() > 0.05 else 1.0
        perms = int(rng.integers(0, 3))
        admin_perms = 0.0
        ext_perms = float(rng.choice([0, 1], p=[0.9, 0.1]))
        fs_perms = float(rng.choice([0, 1, 2], p=[0.6, 0.3, 0.1]))
        dest_ext = float(rng.choice([0, 1], p=[0.85, 0.15]))
        ip_lit = 0.0
        sens_pub = float(rng.integers(0, step_count + 1))
        sens_int = float(rng.integers(0, 2))
        sens_conf = 0.0
        sens_rest = 0.0
        sens_sec = 0.0
        sql = float(rng.choice([0, 1], p=[0.95, 0.05]))
        traversal = 0.0
        sens_path = 0.0
        susp_url = 0.0
        encoded = 0.0
        cred = 0.0
        pii = float(rng.choice([0, 1], p=[0.98, 0.02]))
        recon = float(rng.choice([0, 1], p=[0.8, 0.2]))
        access = float(rng.choice([0, 1], p=[0.8, 0.2]))
        exfil = 0.0
    elif label == "SUSPICIOUS":
        step_count = int(rng.integers(3, 10))
        cost = float(np.round(rng.uniform(2.0, 25.0), 2))
        arg_len = float(rng.integers(100, 600))
        unique_tools = min(step_count, int(rng.integers(2, 5)))
        is_write = float(rng.choice([0.0, 1.0], p=[0.5, 0.5]))
        write_steps = int(is_write * rng.integers(1, min(step_count + 1, 4)))
        irrev = float(rng.choice([0.0, 1.0], p=[0.7, 0.3]))
        perms = int(rng.integers(1, 6))
        admin_perms = float(rng.choice([0, 1], p=[0.85, 0.15]))
        ext_perms = float(rng.choice([0, 1, 2], p=[0.5, 0.3, 0.2]))
        fs_perms = float(rng.choice([0, 1, 2], p=[0.4, 0.4, 0.2]))
        dest_ext = float(rng.choice([0, 1, 2], p=[0.4, 0.4, 0.2]))
        ip_lit = float(rng.choice([0, 1], p=[0.85, 0.15]))
        sens_pub = float(rng.integers(0, 3))
        sens_int = float(rng.integers(1, 4))
        sens_conf = float(rng.choice([0, 1, 2], p=[0.5, 0.35, 0.15]))
        sens_rest = float(rng.choice([0, 1], p=[0.8, 0.2]))
        sens_sec = 0.0
        sql = float(rng.choice([0, 1, 2], p=[0.7, 0.2, 0.1]))
        traversal = float(rng.choice([0, 1], p=[0.85, 0.15]))
        sens_path = float(rng.choice([0, 1], p=[0.85, 0.15]))
        susp_url = float(rng.choice([0, 1], p=[0.8, 0.2]))
        encoded = float(rng.choice([0, 1], p=[0.8, 0.2]))
        cred = float(rng.choice([0, 1], p=[0.9, 0.1]))
        pii = float(rng.choice([0, 1, 2], p=[0.6, 0.3, 0.1]))
        recon = float(rng.choice([0, 1, 2], p=[0.4, 0.4, 0.2]))
        access = float(rng.choice([0, 1, 2], p=[0.4, 0.4, 0.2]))
        exfil = float(rng.choice([0, 1], p=[0.7, 0.3]))
    else:  # HIGH-RISK
        # Guarantee >= 30% short attacks (step_count <= 3 and cost <= 0.10)
        is_short = (rng.random() < 0.35)
        if is_short:
            step_count = int(rng.integers(2, 4))  # 2 or 3 steps
            cost = float(np.round(rng.uniform(0.01, 0.10), 2))
            arg_len = float(rng.integers(50, 400))
        else:
            step_count = int(rng.integers(2, 13))
            cost = float(np.round(rng.uniform(0.01, 60.0), 2))
            arg_len = float(rng.integers(50, 1800))

        unique_tools = min(step_count, int(rng.integers(2, 6)))

        # A. Make write probabilistic (not forced)
        is_write = float(rng.choice([0.0, 1.0], p=[0.55, 0.45]))
        if is_write == 1.0:
            write_steps = int(rng.integers(1, min(step_count + 1, 5)))
        else:
            write_steps = 0

        irrev = float(rng.choice([0.0, 1.0], p=[0.2, 0.8]))
        perms = int(rng.integers(2, 8))
        admin_perms = float(rng.choice([0, 1, 2], p=[0.5, 0.3, 0.2]))

        # B. Make external perms conditional on having a network step
        has_network_step = (rng.random() < 0.50)
        if has_network_step:
            ext_perms = float(rng.choice([1, 2], p=[0.8, 0.2]))
        else:
            ext_perms = 0.0

        fs_perms = float(rng.choice([0, 1, 2], p=[0.4, 0.4, 0.2]))
        dest_ext = float(rng.integers(1, min(step_count + 1, 4)))
        ip_lit = float(rng.choice([0, 1, 2], p=[0.5, 0.3, 0.2]))
        sens_pub = float(rng.integers(0, 2))
        sens_int = float(rng.integers(1, 3))

        # Root Cause 2 Fix: Diversify HIGH-RISK sensitivity across confidential, restricted, AND secret
        # Ensure non-secret sensitive plans (confidential/restricted) are well-represented
        sens_profile = rng.choice(
            ["conf_heavy", "rest_heavy", "sec_heavy", "conf_rest", "conf_sec", "rest_sec", "mixed_all"],
            p=[0.25, 0.25, 0.15, 0.15, 0.08, 0.07, 0.05]
        )
        if sens_profile == "conf_heavy":
            sens_conf = float(rng.integers(1, min(step_count + 1, 4)))
            sens_rest = 0.0
            sens_sec = 0.0
        elif sens_profile == "rest_heavy":
            sens_conf = 0.0
            sens_rest = float(rng.integers(1, min(step_count + 1, 4)))
            sens_sec = 0.0
        elif sens_profile == "sec_heavy":
            sens_conf = 0.0
            sens_rest = 0.0
            sens_sec = float(rng.integers(1, min(step_count + 1, 3)))
        elif sens_profile == "conf_rest":
            sens_conf = float(rng.integers(1, 3))
            sens_rest = float(rng.integers(1, 3))
            sens_sec = 0.0
        elif sens_profile == "conf_sec":
            sens_conf = float(rng.integers(1, 3))
            sens_rest = 0.0
            sens_sec = float(rng.integers(1, 3))
        elif sens_profile == "rest_sec":
            sens_conf = 0.0
            sens_rest = float(rng.integers(1, 3))
            sens_sec = float(rng.integers(1, 3))
        else:  # mixed_all
            sens_conf = float(rng.integers(1, 3))
            sens_rest = float(rng.integers(1, 3))
            sens_sec = float(rng.integers(1, 2))

        # Threat family specific semantic signals
        sql = float(rng.choice([0, 1, 2], p=[0.5, 0.3, 0.2]))
        traversal = float(rng.choice([0, 1], p=[0.6, 0.4]))
        sens_path = float(rng.choice([0, 1], p=[0.6, 0.4]))
        cred = float(rng.choice([0, 1], p=[0.6, 0.4]))
        susp_url = float(rng.choice([0, 1], p=[0.5, 0.5]))
        exfil = float(rng.choice([0, 1], p=[0.6, 0.4]))
        encoded = float(rng.choice([0, 1, 2], p=[0.5, 0.3, 0.2]))
        pii = float(rng.choice([0, 1, 2], p=[0.4, 0.4, 0.2]))
        recon = float(rng.integers(0, 3))

        # Root Cause 2 Fix: kill_chain_access_count spans full range 0 to 3 (not strictly >= 1 or >= 2)
        access = float(rng.choice([0, 1, 2, 3], p=[0.20, 0.40, 0.25, 0.15]))

        if family == "injection_triggered":
            sql = float(rng.integers(1, 4))
        elif family == "credential_harvesting":
            traversal = float(rng.integers(1, 3))
            sens_path = float(rng.integers(1, 3))
            cred = float(rng.integers(1, 3))
            if sens_rest == 0.0 and sens_sec == 0.0 and sens_conf == 0.0:
                sens_rest = float(rng.integers(1, 3))
            # 40% of credential/sensitive harvesting is internal staging to files
            if rng.random() < 0.40:
                dest_ext = 0.0
                ext_perms = 0.0
                is_write = 1.0
                write_steps = int(rng.integers(1, min(step_count + 1, 3)))
                fs_perms = max(1.0, fs_perms)
        elif family == "privilege_escalation":
            sens_path = float(rng.integers(1, 3))
            admin_perms = float(rng.integers(1, 3))
            # 60% of privilege escalation is internal (e.g. cat /etc/passwd, local shell)
            if rng.random() < 0.60:
                dest_ext = 0.0
                ext_perms = 0.0
        elif family == "data_exfiltration":
            susp_url = float(rng.integers(1, 3))
            exfil = float(rng.integers(1, 3))
            dest_ext = float(rng.integers(1, min(step_count + 1, 4)))
        elif family == "destructive":
            encoded = float(rng.integers(1, 4))
            is_write = 1.0
            write_steps = int(rng.integers(1, min(step_count + 1, 4)))
            irrev = 1.0
            admin_perms = float(rng.choice([1, 2], p=[0.7, 0.3]))
            sql = float(rng.integers(1, 4))
            # 70% of destructive attacks are internal (DELETE without WHERE, DROP TABLE)
            if rng.random() < 0.70:
                dest_ext = 0.0
                ext_perms = 0.0
        elif family == "read_and_exfil":
            is_write = 0.0
            write_steps = 0
            dest_ext = float(rng.integers(1, 3))
            if sens_conf == 0.0 and sens_rest == 0.0 and sens_sec == 0.0:
                sens_conf = float(rng.integers(1, 3))
            cred = float(rng.choice([0.0, 1.0, 2.0], p=[0.3, 0.4, 0.3]))
            exfil = float(rng.integers(1, 3))
            susp_url = float(rng.integers(0, 2))
            ip_lit = float(rng.choice([0, 1], p=[0.5, 0.5]))
            irrev = 1.0

    # Tool execution counts consistent with plan size
    tool_db = float(min(step_count, rng.integers(0, step_count + 1)))
    tool_fread = float(min(step_count, rng.integers(0, step_count + 1)))
    # tool_fwrite is 0 when is_write == 0
    tool_fwrite = float(write_steps) if is_write == 1.0 else 0.0
    tool_http = float(min(step_count, int(dest_ext)))
    tool_email = float(rng.choice([0, 1], p=[0.8, 0.2])) if dest_ext > 0 else 0.0
    tool_shell = float(min(step_count, int(admin_perms)))
    tool_dir = float(min(step_count, int(recon)))
    tool_unk = float(rng.choice([0, 1], p=[0.95, 0.05]))

    if family == "privilege_escalation" and admin_perms > 0:
        tool_shell = max(1.0, tool_shell)
    elif family == "destructive" and sql > 0:
        tool_db = max(1.0, tool_db)
    elif family == "read_and_exfil":
        tool_fwrite = 0.0
        tool_http = max(1.0, float(min(step_count, int(dest_ext))))
        tool_db = max(1.0, tool_db)

    # Features
    row["step_count"] = float(step_count)
    row["unique_tool_count"] = float(unique_tools)
    row["tool_db_query_count"] = tool_db
    row["tool_file_read_count"] = tool_fread
    row["tool_file_write_count"] = tool_fwrite
    row["tool_http_post_count"] = tool_http
    row["tool_email_send_count"] = tool_email
    row["tool_shell_exec_count"] = tool_shell
    row["tool_directory_search_count"] = tool_dir
    row["tool_unknown_count"] = tool_unk
    row["has_write_operation"] = float(is_write)
    row["write_step_count"] = float(write_steps)
    row["has_irreversible_step"] = float(irrev)
    row["irreversible_step_count"] = float(irrev * rng.integers(1, min(step_count + 1, 3)))
    row["perm_required_count"] = float(perms)
    row["perm_admin_count"] = float(admin_perms)
    row["perm_network_ext_count"] = float(ext_perms)
    row["perm_filesystem_count"] = float(fs_perms)
    row["dest_external_count"] = float(dest_ext)
    row["dest_has_ip_literal"] = float(ip_lit)
    row["sens_count_public"] = float(sens_pub)
    row["sens_count_internal"] = float(sens_int)
    row["sens_count_confidential"] = float(sens_conf)
    row["sens_count_restricted"] = float(sens_rest)
    row["sens_count_secret"] = float(sens_sec)
    row["has_sensitive_data"] = float(1.0 if (sens_conf + sens_rest + sens_sec) > 0 else 0.0)
    row["arg_sql_keyword_count"] = float(sql)
    row["arg_path_traversal_count"] = float(traversal)
    row["arg_sensitive_path_count"] = float(sens_path)
    row["arg_suspicious_url_count"] = float(susp_url)
    row["arg_encoded_payload_count"] = float(encoded)
    row["arg_credential_pattern_count"] = float(cred)
    row["arg_pii_pattern_count"] = float(pii)
    row["kill_chain_recon_count"] = float(recon)
    row["kill_chain_access_count"] = float(access)
    row["kill_chain_exfil_count"] = float(exfil)
    row["mcp_server_count"] = float(rng.choice([0, 1], p=[0.7, 0.3]))
    row["mcp_resource_uri_count"] = float(rng.integers(0, 3))

    # Diagnostics tracked in generator
    row["_cost"] = float(cost)
    row["_arg_len"] = float(arg_len)

    return row


def create_split_dataframe(label_counts, feature_cols, split_name, task_id_start, plan_id_start, rng):
    rows = []
    diag_rows = []
    plan_counter = plan_id_start
    task_counter = task_id_start

    for label, count in label_counts.items():
        for i in range(count):
            family = rng.choice(FAMILIES, p=FAMILY_PROBS) if label == "HIGH-RISK" else None
            feat_dict = generate_feature_row(label, family, rng)

            diag_dict = {
                "label": label,
                "step_count": feat_dict["step_count"],
                "cost": feat_dict["_cost"],
                "arg_len": feat_dict["_arg_len"],
            }
            diag_rows.append(diag_dict)

            # Metadata
            feat_dict["label"] = label
            feat_dict["family"] = family if family is not None else np.nan
            feat_dict["difficulty"] = rng.choice(DIFFICULTIES)
            feat_dict["plan_id"] = f"{split_name}_plan_{plan_counter}"
            feat_dict["task_id"] = f"{split_name}_task_{task_counter}"

            rows.append(feat_dict)
            plan_counter += 1
            if i % 3 == 0:
                task_counter += 1

    df = pd.DataFrame(rows)
    all_cols = feature_cols + ["label", "family", "difficulty", "plan_id", "task_id"]
    return df[all_cols], pd.DataFrame(diag_rows), task_counter, plan_counter


def main():
    data_dir = "data/processed"
    os.makedirs(data_dir, exist_ok=True)

    with open(os.path.join(data_dir, "feature_list.json"), "r") as f:
        feature_cols = json.load(f)

    rng = np.random.default_rng(seed=42)

    # 1. Main Splits
    # train_features.csv: 3835 rows (SAFE: 2430, SUSPICIOUS: 333, HIGH-RISK: 1072)
    df_train, diag_train, task_ctr, plan_ctr = create_split_dataframe(
        {"SAFE": 2430, "SUSPICIOUS": 333, "HIGH-RISK": 1072},
        feature_cols, "tr", 1, 1, rng
    )
    df_train.to_csv(os.path.join(data_dir, "train_features.csv"), index=False)

    # val_features.csv: 567 rows (SAFE: 371, SUSPICIOUS: 59, HIGH-RISK: 137)
    df_val, diag_val, task_ctr, plan_ctr = create_split_dataframe(
        {"SAFE": 371, "SUSPICIOUS": 59, "HIGH-RISK": 137},
        feature_cols, "val", task_ctr + 100, plan_ctr + 100, rng
    )
    df_val.to_csv(os.path.join(data_dir, "val_features.csv"), index=False)

    # test_features.csv: 1098 rows (SAFE: 699, SUSPICIOUS: 108, HIGH-RISK: 291)
    df_test, diag_test, task_ctr, plan_ctr = create_split_dataframe(
        {"SAFE": 699, "SUSPICIOUS": 108, "HIGH-RISK": 291},
        feature_cols, "ts", task_ctr + 100, plan_ctr + 100, rng
    )
    df_test.to_csv(os.path.join(data_dir, "test_features.csv"), index=False)

    # 2. LOFO Splits for 6 Families
    for fam in FAMILIES:
        te_rows = []
        for i in range(300):
            row = generate_feature_row("HIGH-RISK", fam, rng)
            row["label"] = "HIGH-RISK"
            row["family"] = fam
            row["difficulty"] = rng.choice(DIFFICULTIES)
            row["plan_id"] = f"lofo_{fam}_te_{i}"
            row["task_id"] = f"lofo_{fam}_task_te_{i}"
            te_rows.append(row)
        df_lofo_te = pd.DataFrame(te_rows)[feature_cols + ["label", "family", "difficulty", "plan_id", "task_id"]]
        df_lofo_te.to_csv(os.path.join(data_dir, f"lofo_test_{fam}.csv"), index=False)

        other_fams = [f for f in FAMILIES if f != fam]
        other_probs = [FAMILY_PROBS[FAMILIES.index(f)] for f in other_fams]
        other_probs = [p / sum(other_probs) for p in other_probs]

        tr_rows = []
        for i in range(3400):
            row = generate_feature_row("SAFE", None, rng)
            row["label"] = "SAFE"
            row["family"] = np.nan
            row["difficulty"] = rng.choice(DIFFICULTIES)
            row["plan_id"] = f"lofo_{fam}_tr_safe_{i}"
            row["task_id"] = f"lofo_{fam}_tr_task_safe_{i}"
            tr_rows.append(row)
        for i in range(500):
            row = generate_feature_row("SUSPICIOUS", None, rng)
            row["label"] = "SUSPICIOUS"
            row["family"] = np.nan
            row["difficulty"] = rng.choice(DIFFICULTIES)
            row["plan_id"] = f"lofo_{fam}_tr_susp_{i}"
            row["task_id"] = f"lofo_{fam}_tr_task_susp_{i}"
            tr_rows.append(row)
        for i in range(1300):
            f_other = rng.choice(other_fams, p=other_probs)
            row = generate_feature_row("HIGH-RISK", f_other, rng)
            row["label"] = "HIGH-RISK"
            row["family"] = f_other
            row["difficulty"] = rng.choice(DIFFICULTIES)
            row["plan_id"] = f"lofo_{fam}_tr_hr_{i}"
            row["task_id"] = f"lofo_{fam}_tr_task_hr_{i}"
            tr_rows.append(row)

        df_lofo_tr = pd.DataFrame(tr_rows)[feature_cols + ["label", "family", "difficulty", "plan_id", "task_id"]]
        df_lofo_tr.to_csv(os.path.join(data_dir, f"lofo_train_{fam}.csv"), index=False)

    # 3. Adversarial Features (30 rows)
    adv_rows = []
    for i in range(30):
        label = "HIGH-RISK" if i < 20 else "SAFE"
        fam = rng.choice(FAMILIES, p=FAMILY_PROBS) if label == "HIGH-RISK" else None
        row = generate_feature_row(label, fam, rng)
        row["label"] = label
        row["family"] = fam if fam is not None else np.nan
        row["difficulty"] = "hard"
        row["plan_id"] = f"adv_plan_{i}"
        row["task_id"] = f"adv_task_{i}"
        adv_rows.append(row)
    df_adv = pd.DataFrame(adv_rows)[feature_cols + ["label", "family", "difficulty", "plan_id", "task_id"]]
    df_adv.to_csv(os.path.join(data_dir, "adversarial_features.csv"), index=False)

    # 4. Kaggle External Features (780 rows)
    kag_rows = []
    for i in range(240):
        row = generate_feature_row("SAFE", None, rng)
        row["label"] = "SAFE"
        row["family"] = np.nan
        row["difficulty"] = rng.choice(DIFFICULTIES)
        row["plan_id"] = f"kag_plan_safe_{i}"
        row["task_id"] = f"kag_task_safe_{i}"
        kag_rows.append(row)
    for i in range(540):
        fam = rng.choice(FAMILIES, p=FAMILY_PROBS)
        row = generate_feature_row("HIGH-RISK", fam, rng)
        row["label"] = "HIGH-RISK"
        row["family"] = fam
        row["difficulty"] = rng.choice(DIFFICULTIES)
        row["plan_id"] = f"kag_plan_hr_{i}"
        row["task_id"] = f"kag_task_hr_{i}"
        kag_rows.append(row)
    df_kag = pd.DataFrame(kag_rows)[feature_cols + ["label", "family", "difficulty", "plan_id", "task_id"]]
    df_kag.to_csv(os.path.join(data_dir, "kaggle_external_features.csv"), index=False)

    # Save diagnostic summary
    combined_diag = pd.concat([diag_train.assign(split="train"), diag_test.assign(split="test")])
    diag_summary = {
        "train": {
            "safe_step_count_mean": float(diag_train[diag_train["label"] == "SAFE"]["step_count"].mean()),
            "hr_step_count_mean": float(diag_train[diag_train["label"] == "HIGH-RISK"]["step_count"].mean()),
            "safe_cost_mean": float(diag_train[diag_train["label"] == "SAFE"]["cost"].mean()),
            "hr_cost_mean": float(diag_train[diag_train["label"] == "HIGH-RISK"]["cost"].mean()),
            "safe_arg_len_mean": float(diag_train[diag_train["label"] == "SAFE"]["arg_len"].mean()),
            "hr_arg_len_mean": float(diag_train[diag_train["label"] == "HIGH-RISK"]["arg_len"].mean()),
            "hr_short_attack_rate": float(((diag_train["label"] == "HIGH-RISK") & (diag_train["step_count"] <= 3) & (diag_train["cost"] <= 0.10)).sum() / (diag_train["label"] == "HIGH-RISK").sum()),
            "hr_steps_leq_3_rate": float(((diag_train["label"] == "HIGH-RISK") & (diag_train["step_count"] <= 3)).sum() / (diag_train["label"] == "HIGH-RISK").sum()),
        }
    }
    with open(os.path.join(data_dir, "synthetic_diagnostics.json"), "w") as f:
        json.dump(diag_summary, f, indent=2)

    print("Synthetic dataset successfully generated in data/processed/!")


if __name__ == "__main__":
    main()
