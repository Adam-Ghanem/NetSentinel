# Container Image Security

NetSentinel treats the built runtime image as a release artifact that must be verified independently from source dependency checks.

## Pull-request gate

The `Container Security` workflow builds the reviewed Dockerfile and scans the resulting image with Trivy. The gate fails when a fixable `HIGH` or `CRITICAL` vulnerability is present. Unfixed findings remain visible in the generated report but do not block a merge, which keeps the policy actionable while preserving evidence.

The workflow also generates a CycloneDX SBOM for the final image. Both the vulnerability report and SBOM are uploaded as immutable workflow artifacts retained for 30 days.

## Evidence produced

Each workflow run publishes:

- `trivy-image-vulnerabilities.json` — machine-readable vulnerability results for the exact image built from the commit.
- `netsentinel-image-sbom.cdx.json` — CycloneDX inventory of operating-system and application packages in the image.

The artifact name includes the commit SHA so operators can associate evidence with the source revision.

## Response policy

When the gate fails:

1. Confirm that the finding affects the final runtime image rather than only a build stage.
2. Prefer a patched base-image digest or a reviewed dependency upgrade.
3. Rebuild and rerun the complete workflow; do not suppress a finding only to make CI green.
4. If no upstream fix exists, document the exposure, reachable code path, compensating controls, and review date before adding a narrowly scoped exception.
5. Rotate credentials immediately if a report or image ever contains secret material.

## Reproducibility

The scanner always analyzes `netsentinel:security-scan`, which is built inside the same workflow from the checked-out commit. The image receives the Git revision as OCI metadata. Reports must never be reused across commits or manually edited.

## Local verification

Install Trivy from its official distribution and run:

```bash
docker build --tag netsentinel:security-scan .
trivy image --config trivy.yaml --format json --output trivy-image-vulnerabilities.json netsentinel:security-scan
trivy image --format cyclonedx --output netsentinel-image-sbom.cdx.json netsentinel:security-scan
```

A local pass is useful before opening a pull request, but the GitHub Actions result remains the merge gate because it provides consistent runner and evidence handling.
