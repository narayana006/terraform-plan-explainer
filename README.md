# terraform-plan-explainer

Turn a Terraform plan into a plain-English summary that calls out destructive and high-risk changes before you apply.

> **Project status: planning. There is no working code in this repository yet.**
> This README describes what the project will do. Nothing below can be installed or run today.
> Features are ticked off in the checklist as they are built.

## What it is

A command-line tool and GitHub Action.

**The problem it solves:** Terraform plans run to thousands of lines, and the one resource being destroyed and recreated is easy to miss in review.

## Who it is for

Engineers who review or apply Terraform changes.

## How it will work

1. You save a plan and pass its JSON output to the tool.
2. It sorts every change into create, update, replace or destroy and checks for data loss, permission and network exposure risks.
3. It prints a short summary with the risky changes at the top, or posts it on the pull request.

## Planned features

Unticked items are not built yet.

- [ ] Reads `terraform show -json` plan output
- [ ] Groups changes by create, update, replace and destroy
- [ ] Flags destructive changes, data-loss risks and IAM or network exposure
- [ ] Plain-English summary for reviewers
- [ ] GitHub Action that posts the summary on pull requests

## Planned usage

This is the intended interface, shown so you can judge the design. **It does not work yet**, and names may change before the first release.

```bash
terraform show -json plan.out | terraform-plan-explainer
```

## Contributing

Feedback on the design is the most useful contribution right now. Open an issue to suggest a feature, question an approach or describe your use case. Code contributions are welcome once the first version lands.

## License

[MIT](LICENSE)
