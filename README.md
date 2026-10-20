# pycoverity-scan-result-to-sarif

Converts Coverity `cov-format-errors --json-output-v7` results to SARIF 2.1.0 for GitHub code scanning. It also accepts Coverity-based Polaris results.

The converter requires Python 3.7 or later and has no runtime dependencies.

## Run locally

From this repository's root:

```sh
python -m pip install ./python
python -m coverity_sarif coverity-results.json coverity-results.sarif
```

## Use as a GitHub Action

```yaml
- name: Convert Coverity results to SARIF
  uses: your-org/pycoverity-scan-result-to-sarif@v1
  with:
    pipeline-results-json: coverity-results.json
    output-results-sarif: coverity-results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: coverity-results.sarif
```

Replace `your-org` with the GitHub owner of this repository. For Polaris, set `pipeline-results-json` to its Coverity JSON output.