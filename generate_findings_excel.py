import pandas as pd
import numpy as np
import re
import sys

def load_findings_csv(path):
    # Only grab the first line for columns, because columns are very long
    with open(path, encoding="utf-8") as f:
        header = f.readline().strip().split(",")
        summary_idx = header.index("Summary")
        issue_key_idx = header.index("Issue key")
        status_idx = header.index("Status")
        priority_idx = header.index("Priority")
        # Description is not a column, but is in the block after the columns, so we parse it later

        findings = []
        for line in f:
            if not line.startswith("Prisma Cloud"):
                continue
            row = line.strip().split(",")
            summary = row[summary_idx] if len(row) > summary_idx else ""
            issue_key = row[issue_key_idx] if len(row) > issue_key_idx else ""
            status = row[status_idx] if len(row) > status_idx else ""
            priority = row[priority_idx] if len(row) > priority_idx else ""
            description = ",".join(row[priority_idx+1:]).replace("\\n", "\n")
            # Try to extract CVE number and link for clarity
            cve_match = re.search(r"CVE number: ([\w\-]+)", description)
            cve_link_match = re.search(r"CVE link: (https?://\S+)", description)
            cve_number = cve_match.group(1) if cve_match else ""
            cve_link = cve_link_match.group(1) if cve_link_match else ""
            findings.append({
                "Summary": summary,
                "Issue key": issue_key,
                "Status": status,
                "Priority": priority,
                "Description": description.strip(),
                "CVE number": cve_number,
                "CVE link": cve_link
            })
        return pd.DataFrame(findings)

def get_top_critical(df, n=5):
    priority_map = {"1 Critical": 1, "Critical": 1, "2 High": 2, "High": 2, "3 Medium": 3, "Medium": 3, "4 Low": 4, "Low": 4}
    df = df.copy()
    df["PriorityRank"] = df["Priority"].map(priority_map).fillna(999)
    def extract_cvss(desc):
        m = re.search(r"CVSS score: ([0-9.]+)", desc)
        return float(m.group(1)) if m else np.nan
    df["CVSS"] = df["Description"].map(extract_cvss)
    df = df.sort_values(by=["PriorityRank", "CVSS"], ascending=[True, False])
    return df.head(n).drop(columns=["PriorityRank", "CVSS"])

def get_findings_diff(old_df, new_df):
    def make_key(row):
        return f"{row['Issue key']}|{row['CVE number']}" if row['CVE number'] else row['Issue key']
    old_df = old_df.copy()
    new_df = new_df.copy()
    old_df["Key"] = old_df.apply(make_key, axis=1)
    new_df["Key"] = new_df.apply(make_key, axis=1)
    old_keys = set(old_df["Key"])
    new_keys = set(new_df["Key"])

    resolved = old_df[~old_df["Key"].isin(new_keys)]
    new = new_df[~new_df["Key"].isin(old_keys)]
    ongoing = new_df[new_df["Key"].isin(old_keys)]

    merged = pd.merge(
        old_df[["Key", "Status", "Priority"]],
        new_df[["Key", "Status", "Priority"]],
        on="Key", how="inner", suffixes=("_old", "_new")
    )
    merged["Progress"] = np.where(
        (merged["Status_old"] != merged["Status_new"]) | (merged["Priority_old"] != merged["Priority_new"]),
        "Changed",
        "Unchanged"
    )
    return resolved, new, ongoing, merged

def format_table(ws, start_row, nrows, ncols, table_name, headers):
    ws.add_table(start_row, 0, start_row+nrows-1, ncols-1, {
        'name': table_name,
        'columns': [{'header': h} for h in headers],
        'style': 'Table Style Medium 2'
    })

def export_to_excel(highlevel_summary, top_critical, old_df, new_df, ongoing_summary, ongoing_findings, output_excel):
    import xlsxwriter
    with pd.ExcelWriter(output_excel, engine="xlsxwriter") as writer:
        # Sheet 1: High-level summary and top critical
        highlevel_summary.to_excel(writer, sheet_name="Summary", index=False, startrow=0)
        top_critical_start = len(highlevel_summary) + 2  # one blank row between tables
        top_critical.to_excel(writer, sheet_name="Summary", index=False, startrow=top_critical_start)
        workbook = writer.book
        ws_summary = writer.sheets["Summary"]
        format_table(ws_summary, 0, len(highlevel_summary), len(highlevel_summary.columns), "SummaryTable", list(highlevel_summary.columns))
        format_table(ws_summary, top_critical_start, len(top_critical), len(top_critical.columns), "TopCriticalTable", list(top_critical.columns))

        # Sheet 2: April
        old_df.to_excel(writer, sheet_name="April Findings", index=False)
        ws_april = writer.sheets["April Findings"]
        format_table(ws_april, 0, len(old_df), len(old_df.columns), "AprilTable", list(old_df.columns))

        # Sheet 3: May
        new_df.to_excel(writer, sheet_name="May Findings", index=False)
        ws_may = writer.sheets["May Findings"]
        format_table(ws_may, 0, len(new_df), len(new_df.columns), "MayTable", list(new_df.columns))

        # Sheet 4: Ongoing
        ongoing_summary.to_excel(writer, sheet_name="Ongoing Progress", index=False, startrow=0)
        ongoing_findings_start = len(ongoing_summary) + 2
        ongoing_findings.to_excel(writer, sheet_name="Ongoing Progress", index=False, startrow=ongoing_findings_start)
        ws_ongoing = writer.sheets["Ongoing Progress"]
        format_table(ws_ongoing, 0, len(ongoing_summary), len(ongoing_summary.columns), "OngoingSummaryTable", list(ongoing_summary.columns))
        format_table(ws_ongoing, ongoing_findings_start, len(ongoing_findings), len(ongoing_findings.columns), "OngoingFindingsTable", list(ongoing_findings.columns))

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python generate_findings_excel.py dmdt_042025.csv dmdt_052025.csv")
        sys.exit(1)
    april_path = sys.argv[1]
    may_path = sys.argv[2]

    april = load_findings_csv(april_path)
    may = load_findings_csv(may_path)
    # KEEP "CVE number" in your DataFrames for downstream keying!
    columns = ["Summary", "Issue key", "Status", "Priority", "Description", "CVE number"]
    april = april[columns]
    may = may[columns]

    summary_data = {
        "File": ["April", "May"],
        "Total Findings": [len(april), len(may)],
        "Critical": [(april["Priority"].str.contains("Critical", case=False)).sum(), (may["Priority"].str.contains("Critical", case=False)).sum()],
        "High": [(april["Priority"].str.contains("High", case=False)).sum(), (may["Priority"].str.contains("High", case=False)).sum()],
        "Medium": [(april["Priority"].str.contains("Medium", case=False)).sum(), (may["Priority"].str.contains("Medium", case=False)).sum()],
        "Low": [(april["Priority"].str.contains("Low", case=False)).sum(), (may["Priority"].str.contains("Low", case=False)).sum()],
    }
    summary_df = pd.DataFrame(summary_data)

    top_critical = get_top_critical(may, n=5)
    resolved, new_findings, ongoing, ongoing_progress = get_findings_diff(april, may)
    ongoing_summary = ongoing_progress.rename(columns={
        "Status_old": "Status (April)",
        "Priority_old": "Priority (April)",
        "Status_new": "Status (May)",
        "Priority_new": "Priority (May)"
    })[["Key", "Status (April)", "Priority (April)", "Status (May)", "Priority (May)", "Progress"]]
    ongoing_findings = may[may["Issue key"].isin(ongoing["Issue key"])][columns]

    export_to_excel(
        summary_df,
        top_critical,
        april,
        may,
        ongoing_summary,
        ongoing_findings,
        "findings_summary.xlsx"
    )

    print("Excel report generated: findings_summary.xlsx")