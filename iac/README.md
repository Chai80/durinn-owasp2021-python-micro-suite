# IaC benchmark cases

This folder contains **intentionally insecure** Terraform and Kubernetes examples for benchmarking IaC scanners.

## Ground-truth markers

Each file is wrapped in GT anchors (for example `# GT: IAC_TF_01_START` / `# GT: IAC_TF_01_END`) so your pipeline can map findings to known-bad regions.

## Recommended branch name

Create a dedicated branch (recommended: `iac-core-terraform-k8s`) and apply the IaC patch there so your normal "clean" branches stay clean.
