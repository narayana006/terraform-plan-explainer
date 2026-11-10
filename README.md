# terraform-plan-explainer

Turn a Terraform plan into a plain-English summary that puts destructive and high-risk changes at the top, before you apply.

**Status:** working first version (0.1.0). The command-line tool reads plan JSON, groups changes, flags data-loss, IAM and network exposure risks, and sets an exit code you can gate on. The GitHub Action that posts the summary on pull requests is not built yet.

## Why

Terraform plans run to thousands of lines, and the one database being destroyed and recreated is easy to miss in review. This tool reads the machine-readable plan and tells you, in a few lines, what deserves a second look.

## Install

Requires Python 3.10 or newer. No dependencies outside the standard library.

```bash
pip install git+https://github.com/narayana006/terraform-plan-explainer
```

Or from a clone:

```bash
git clone https://github.com/narayana006/terraform-plan-explainer
cd terraform-plan-explainer
pip install -e .
```

## Quick start

The repository ships a sample plan, so you can try it without Terraform installed:

```bash
terraform-plan-explainer examples/plan.json
```

```text
10 resource changes: 3 to create, 3 to update, 2 to replace, 2 to destroy.

RISKS (8)
  [HIGH  ] aws_db_instance.orders
           data-loss: database will be REPLACED: destroyed first, then recreated (forced by change to: storage_encrypted); existing data does not carry over
  [HIGH  ] aws_iam_policy.ci_deploy
           iam: IAM policy allows every action (Action "*") on every resource
  [HIGH  ] aws_s3_bucket.legacy_exports
           data-loss: S3 bucket will be DESTROYED; its data is lost unless backed up elsewhere
  [HIGH  ] aws_security_group.bastion
           network: opens SSH port 22 to the internet (0.0.0.0/0)
  [MEDIUM] aws_dynamodb_table.sessions
           data-loss: deletion protection is being turned off (deletion_protection_enabled = false)
  [MEDIUM] aws_route53_record.old_api
           destructive: will be destroyed
  [MEDIUM] module.workers.aws_launch_template.worker
           destructive: will be replaced: new one is created first, then the old one is deleted (forced by change to: name_prefix)
  [LOW   ] aws_security_group.web
           network: opens web port 443 to the internet (0.0.0.0/0)

CHANGES
  Destroy (2)
      - aws_route53_record.old_api
      - aws_s3_bucket.legacy_exports
  Replace (2)
    -/+ aws_db_instance.orders
    -/+ module.workers.aws_launch_template.worker
  Update in place (3)
      ~ aws_dynamodb_table.sessions
      ~ aws_iam_role_policy.report_reader
      ~ aws_security_group.bastion
  Create (3)
      + aws_cloudwatch_metric_alarm.orders_cpu
      + aws_iam_policy.ci_deploy
      + aws_security_group.web

Verdict: STOP AND REVIEW. 4 high-risk findings; read the risks above before applying.
```

The command exits with status 1 here because the plan contains high-risk findings.

With a real plan:

```bash
terraform plan -out plan.out
terraform show -json plan.out | terraform-plan-explainer
```

## Usage

```text
terraform-plan-explainer [plan] [-f text|markdown|json] [--fail-on high|medium|low|never]
```

| Option | Meaning |
|---|---|
| `plan` | Path to the plan JSON. Omit it, or pass `-`, to read from stdin. |
| `-f`, `--format` | `text` (default), `markdown` (a table you can paste into a pull request) or `json`. |
| `--fail-on` | Lowest severity that makes the command exit 1. Default `high`. Use `never` to always exit 0 on a readable plan. |

Exit codes: `0` nothing at or above the `--fail-on` level, `1` risky findings, `2` unreadable or invalid input.

To block a pipeline on anything medium or worse:

```bash
terraform show -json plan.out | terraform-plan-explainer --fail-on medium
```

## What gets flagged

| Category | Rule | Severity |
|---|---|---|
| data-loss | Destroy or replace of a data-bearing resource (databases, buckets, volumes, tables, KMS keys, queues and similar across AWS, Google Cloud, Azure and Kubernetes) | high |
| data-loss | An update that switches off a safety net on such a resource: `deletion_protection`, `deletion_protection_enabled`, `skip_final_snapshot`, `force_destroy`, `backup_retention_period = 0` | medium |
| destructive | Destroy or replace of any other resource. Replacements list the attributes that force them. | medium |
| iam | Allow statement with `Action "*"` on `Resource "*"` | high |
| iam | Allow statement with a service wildcard such as `s3:*` (high for `iam`, `sts`, `kms`, `organizations`, `secretsmanager` on all resources) | medium / high |
| iam | Allow statement with `Principal "*"` and no `Condition` | high |
| iam | Attachment of `AdministratorAccess`, `IAMFullAccess` or `PowerUserAccess` | high |
| network | Ingress from `0.0.0.0/0` or `::/0`: all ports or a range covering SSH, RDP or a database port | high |
| network | Ingress from the internet on other ports; ports 80 and 443 alone | medium; low |
| network | `publicly_accessible = true`, public S3 bucket ACLs | high |
| network | Relaxed `aws_s3_bucket_public_access_block` | medium |

Network rules cover `aws_security_group`, `aws_security_group_rule`, `aws_vpc_security_group_ingress_rule`, `google_compute_firewall` and `azurerm_network_security_rule`.

For in-place updates, IAM and network findings are reported only when the change introduces them. A wildcard that was already there before the update is not reported again.

## Features

- [x] Reads `terraform show -json` plan output (file or stdin)
- [x] Groups changes by create, update, replace and destroy
- [x] Flags destructive changes, data-loss risks and IAM or network exposure
- [x] Plain-English summary for reviewers (text, Markdown or JSON) with an exit code
- [ ] GitHub Action that posts the summary on pull requests

## Limitations

- The rules are a fixed, built-in list. A resource type that is not in the data-bearing list is still reported when destroyed, but as medium rather than high.
- Values Terraform only knows after apply cannot be checked. A policy built from a computed ARN or an `aws_iam_policy_document` data source that is unknown at plan time is skipped.
- IAM checks read JSON policy documents found in attributes whose name contains `policy`. They do not evaluate conditions, `NotAction`, permission boundaries or SCPs.
- It reads plans, not state or HCL. Passing state JSON gives an error.
- Module moves, imports and output changes are not summarised.
- This is a review aid, not a policy engine. A clean summary does not mean the plan is safe.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## Contributing

Issues and pull requests are welcome. The most useful contributions are new risk rules with a short plan snippet that triggers them, and reports of false positives from real plans (with anything sensitive removed).

Built and maintained by [Narayana Vemburaj](https://github.com/narayana006).

## License

[MIT](LICENSE)
