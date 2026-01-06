# Benchmark sets for durinn-owasp2021-python-micro-suite

This folder defines **machine-readable sets** of ground-truth (GT) vulnerability markers so you can benchmark multiple scanners consistently.

## Files

- `gt_catalog.yaml`
  - Generated catalog of every `# GT: <ID>_START` / `# GT: <ID>_END` block across the suite.
  - Includes: branch name, file, function, and approximate line ranges.

- `suite_sets.yaml`
  - Defines the benchmark sets you asked for:
    - **Core SAST intersection set**: high-signal static patterns that most scanners should catch.
    - **Extended set**: still-static issues, but more tool-dependent (differences are the point).
    - **Out-of-scope for SAST**: mostly business-logic/design/ops controls that SAST generally cannot prove.

  It also notes the non-SAST tracks:
    - **SCA**: dependency vulnerabilities (OWASP A06 branch).
    - **IaC**: planned branch name for Terraform/Kubernetes misconfigs.

## How to use these sets

When scoring results, treat each GT id as a unit. For example:

- **Core SAST** = `tracks.sast.core_sast_intersection.gt_ids`
- **Extended SAST** = `tracks.sast.extended_sast.gt_ids`
- Exclude **Out-of-scope for SAST** from SAST scoring so tools aren't penalized for problems they cannot detect statically.

## IaC track (recommended)

If you want an IaC benchmark that works across tools, create a dedicated branch (recommended name: `iac-core-terraform-k8s`)
that contains a few small Terraform and Kubernetes examples with GT markers in comments.

The suite sets file (`suite_sets.yaml`) already reserves this branch name so your pipeline can include it once created.
