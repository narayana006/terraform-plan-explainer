# Examples

`plan.json` is a hand-written plan in the `terraform show -json` format
(format_version 1.2). It contains no real account data. It mixes routine
changes with the kind that should stop a review: a database replacement, a
bucket deletion, SSH opened to the internet and an allow-everything IAM policy.

```bash
terraform-plan-explainer examples/plan.json
```
