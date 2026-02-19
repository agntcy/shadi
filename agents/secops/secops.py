import argparse
import os

from skills import skill_collect_security_issues


def parse_args():
    parser = argparse.ArgumentParser(description="Run the SHADI SecOps agent")
    parser.add_argument(
        "--provider",
        choices=["google", "azure", "anthropic"],
        help="Override the LLM provider from SHADI (google, azure, anthropic)",
    )
    parser.add_argument(
        "--labels",
        default="security,cve,vulnerability",
        help="Comma-separated GitHub issue labels",
    )
    parser.add_argument(
        "--report-name",
        default="secops_security_report.md",
        help="Report filename in the workspace directory",
    )
    parser.add_argument(
        "--remediate",
        action="store_true",
        help="Attempt to patch critical vulnerabilities and open PRs",
    )
    parser.add_argument(
        "--approve-prs",
        action="store_true",
        help="Create PRs from pending remediation approvals",
    )
    return parser.parse_args()


def run_secops_agent():
    print("== SHADI SecOps Autonomous Agent ==")
    args = parse_args()
    human_github = os.getenv("SHADI_HUMAN_GITHUB", "").strip()
    if args.approve_prs:
        from skills import approve_pending_prs, create_secops_session, get_secops_credentials, load_secops_config

        config_path, config = load_secops_config()
        store, session = create_secops_session()
        github_token, workspace, _, _ = get_secops_credentials(config, store, session)
        result = approve_pending_prs(config, github_token, workspace)
        print("Status: approved")
        print("Result:", result)
        return

    result = skill_collect_security_issues(
        labels=args.labels,
        report_name=args.report_name,
        provider=args.provider,
        remediate=args.remediate,
        create_prs=False,
        human_github_handle=human_github or None,
    )
    print("Status:", result.get("status"))
    print("Report:", result.get("report_path"))
    print("Dependabot alerts:", result.get("dependabot_alerts"))
    print("Labeled issues:", result.get("labeled_issues"))
    print("Repos:", ", ".join(result.get("repos", [])))
    if result.get("memory") is not None:
        print("Memory:", result.get("memory"))
    if result.get("human_did"):
        print("Human DID:", result.get("human_did"))


if __name__ == "__main__":
    run_secops_agent()
