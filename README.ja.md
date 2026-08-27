# Shenron

[English README](README.md)

Shenron は、過去の Web テレメトリを対象にした Rust 製の受動的な脅威ハンティングエンジンです。公開脅威インテリジェンスをローカルの観測証拠へ結び付け、レビュー可能な防御候補を作ることを目的としています。

Shenron はスキャン、exploit 実行、AWS 変更、AWS API 呼び出し、WAF ルールの自動適用、`terraform plan/apply`、OSSEC の再起動を行いません。すべてローカルの静的入力を扱う、レビュー前提のツールです。

## 対応する入力

- AWS WAF JSONL（`.gz` を含む）
- nginx Combined Log Format
- Apache Combined Log Format
- ローカルの Nuclei template / coverage report

すべての入力は source-neutral な `WebEvent` へ正規化されます。標準 nginx / Apache combined log にない JA3、JA4、任意 request header、WAF action、WAF label、request body を補完・推測することはありません。

## できること

- 小さく明示的な Sigma subset によるログ照合
- Nuclei CVE template の静的分析と detectability 評価
- `production inspect` によるテレメトリ可視性の確認
- `production hunt` による、検証済み Nuclei detection のローカル過去ログ照合
- CVE / template / request evidence の `production explain` 表示
- 防御 candidate の作成、historical replay、backend compatibility 確認
- COUNT 固定の AWS WAF JSON / Terraform rule fragment、または OSSEC 検知 XML の出力

## Quick start

```bash
cargo run --bin shenron -- scan \
  --input ./tests/fixtures/aws-waf/ \
  --format aws-waf \
  --rules ./tests/fixtures/rules/
```

finding は JSONL として標準出力へ出力されます。CSV が必要な場合は `--output findings.csv --output-format csv` を指定してください。事前に rule の対応状況を確認できます。

```bash
cargo run --bin shenron -- validate-rules --rules ./rules/
```

## Production hunt

```bash
shenron production inspect --input ./logs --format aws-waf

shenron production hunt \
  --input ./logs --format aws-waf \
  --nuclei-templates ./nuclei-templates \
  --nuclei-report ./coverage.json \
  --kev-report ./kev.json \
  --output ./private-hunt-results
```

`hunt` は private findings と、機微な request 値を含まない sanitized report を分離します。AWS WAF の finding は `explain` で `BLOCK` / `not-blocked` を絞り込めます。

```bash
shenron production explain \
  --findings ./private-hunt-results/private-findings.jsonl \
  --waf-outcome not-blocked \
  --show-evidence
```

`not-blocked` は、検知されたものの記録上 BLOCK されなかった request を表します。これは exploit 成功の証拠ではありません。nginx / Apache では WAF outcome 自体がないため、この分類は利用できません。

## Defensive candidate workflow

finding と防御条件は意図的に別のものです。candidate は防御仮説であり、AWS WAF / Terraform 向けの出力には、完全な backend 互換性、local historical replay、明示的な Web ACL priority が必要です。

```bash
# private finding から CVE / request pattern ごとに狭い candidate を作成します。
# AWS WAF では既に BLOCK された finding は自動的に除外します。
shenron candidate build \
  --from-findings ./private-hunt-results/private-findings.jsonl \
  --telemetry aws-waf --output ./candidates/

# candidate を選んで履歴ログ全体で replay します。元ファイルは上書きしません。
# coverage は source finding の request ID と実測イベントで算出し、ID がなければ未算出です。
shenron candidate replay \
  --candidate ./candidates/shenron-cve-202x-xxxxx-001.json \
  --input ./historical-logs --format aws-waf \
  --output ./candidates/candidate-replayed.json

# backend ごとの忠実な表現可否を確認します。
shenron candidate compatibility \
  --candidate ./candidates/candidate-replayed.json

# COUNT の AWS WAF Rule JSON と evidence sidecar を出力します。
shenron candidate export \
  --candidate ./candidates/candidate-replayed.json \
  --backend aws-waf-json --priority 100 \
  --output ./exports/candidate.aws-waf.json
```

`candidate compatibility`、`explain`、`export` は、指定しなければ candidate に記録された telemetry profile を使います。別 profile での互換性を意図して確認する場合だけ `--telemetry` を指定してください。

`aws-waf-json` と `terraform-aws-waf` は予防的 control の候補です。初期 action は必ず `COUNT` で、Shenron は deploy しません。`ossec` は nginx / Apache combined log の raw representation 向け検知 control であり、WAF rule でも request block 機能でもありません。

JA4 のように選択した telemetry/backend が忠実に表現できない条件は、削除して広いルールにするのではなく export を拒否します。token、secret、cookie、authorization 値らしき条件も export を拒否します。

## ドキュメント

- [Production hunting](docs/production-hunting.md)
- [Telemetry capabilities](docs/telemetry-capabilities.md)
- [Candidate model](docs/waf-candidate-model.md)
- [AWS WAF exporter](docs/exporters/aws-waf.md)
- [Terraform exporter](docs/exporters/terraform.md)
- [OSSEC exporter](docs/exporters/ossec.md)
- [Demo datasets](examples/README.md)

## 開発時の検証

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
make validate
```
