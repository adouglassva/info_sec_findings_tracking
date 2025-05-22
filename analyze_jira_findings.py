import csv
import sys
import os
from collections import defaultdict, OrderedDict

def find_csv_file(path):
    if os.path.exists(path):
        return path
    elif not path.lower().endswith('.csv') and os.path.exists(path + '.csv'):
        return path + '.csv'
    else:
        return None

def load_findings(csv_path):
    findings = {}
    with open(csv_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            cve = row.get("CVE number", "").strip()
            issue_key = row.get("Issue key", "").strip()
            unique = f"{issue_key}|{cve}" if cve else issue_key
            findings[unique] = row
    return findings

def count_by_severity(findings):
    severity_count = defaultdict(int)
    for f in findings.values():
        severity = f.get("Priority", "Unknown")
        severity_count[severity] += 1
    return severity_count

def summarize(findings, label):
    severity_count = count_by_severity(findings)
    print(f"\n{label} Findings by Severity:")
    for sev, count in severity_count.items():
        print(f"  {sev}: {count}")
    print(f"  Total: {len(findings)}")
    return severity_count

def markdown_summary_table(summary_dict):
    # summary_dict: {label: {severity: count, ..., "Total": n}}
    # Find all severities
    all_sevs = set()
    for v in summary_dict.values():
        all_sevs.update(k for k in v if k != "Total")
    # Sort by critical-high-medium-low etc if possible
    sev_order = sorted(all_sevs, key=lambda x: (str(x)))
    header = "| Category | " + " | ".join(sev_order) + " | Total |"
    sep = "|" + " --- |" * (len(sev_order) + 2)
    lines = [header, sep]
    for label, counts in summary_dict.items():
        row = [label]
        for sev in sev_order:
            row.append(str(counts.get(sev, 0)))
        row.append(str(counts.get("Total", 0)))
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)

def main(old_csv, new_csv):
    old_csv_file = find_csv_file(old_csv)
    new_csv_file = find_csv_file(new_csv)
    if not old_csv_file:
        print(f"ERROR: Could not find file '{old_csv}' (tried with and without .csv extension).")
        sys.exit(1)
    if not new_csv_file:
        print(f"ERROR: Could not find file '{new_csv}' (tried with and without .csv extension).")
        sys.exit(1)

    print(f"Loading old findings from {old_csv_file}")
    old_findings = load_findings(old_csv_file)
    print(f"Loading new findings from {new_csv_file}")
    new_findings = load_findings(new_csv_file)

    resolved_keys = set(old_findings.keys()) - set(new_findings.keys())
    new_keys = set(new_findings.keys()) - set(old_findings.keys())
    ongoing_keys = set(old_findings.keys()) & set(new_findings.keys())

    resolved = {k: old_findings[k] for k in resolved_keys}
    new = {k: new_findings[k] for k in new_keys}
    ongoing = {k: new_findings[k] for k in ongoing_keys}

    print("\n==== Findings Comparison Summary ====")
    print(f"Resolved findings: {len(resolved)}")
    print(f"New findings: {len(new)}")
    print(f"Ongoing findings: {len(ongoing)}")

    summary = OrderedDict()
    summary["Resolved"] = summarize(resolved, "Resolved")
    summary["New"] = summarize(new, "New")
    summary["Ongoing"] = summarize(ongoing, "Ongoing")

    # Add totals for markdown table
    for label, d in summary.items():
        d["Total"] = sum(v for k, v in d.items() if k != "Total")

    summary_table = markdown_summary_table(summary)

    # Ensure the reports directory exists
    os.makedirs("reports", exist_ok=True)
    with open("reports/findings_report.md", "w", encoding='utf-8') as report:
        report.write("# Findings Comparison Report\n\n")
        report.write("## Findings Comparison Summary Table\n")
        report.write(summary_table + "\n\n")

        report.write(f"## Resolved Findings ({len(resolved)})\n")
        for k in resolved:
            row = resolved[k]
            report.write(f"- {row.get('Summary', '')} (CVE: {row.get('CVE number', '')})\n")
        report.write(f"\n## New Findings ({len(new)})\n")
        for k in new:
            row = new[k]
            report.write(f"- {row.get('Summary', '')} (CVE: {row.get('CVE number', '')})\n")
        report.write(f"\n## Ongoing Findings ({len(ongoing)})\n")
        for k in ongoing:
            row = ongoing[k]
            report.write(f"- {row.get('Summary', '')} (CVE: {row.get('CVE number', '')})\n")
    print("\nMarkdown report generated: reports/findings_report.md")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python scripts/analyze_jira_findings.py <old_csv> <new_csv>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])