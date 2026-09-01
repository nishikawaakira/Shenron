# Shenron

[English README](README.md)

Shenron は、Web アクセスログを対象にした Rust 製の「受動的（パッシブ）な脅威ハンティング・エンジン」です。公開されている脅威インテリジェンス（Nuclei テンプレートや CISA KEV Catalog）を、自組織のログと突き合わせ、防御ルールの候補作成を支援します。

Shenron の解析本体 `shenron` は、ターゲットへのスキャン、エクスプロイトの実行、AWS の変更や AWS API の呼び出し、WAF ルールの自動適用、`terraform plan/apply`、OSSEC の再起動、解析中のネットワーク接続を一切行いません。ログ・検出結果・IP・リクエスト値などの顧客データを外部へ送信・アップロードする機能もありません。準備用の `shenron-lab nuclei update` だけは、明示的に実行した場合に公開 Nuclei テンプレートをダウンロードしますが、顧客データは送信しません。出力は必ず人間のレビューを前提とした「提案」であり、Shenron 自身が何かをデプロイすることはありません。

## 仕組み（アーキテクチャ概要）

一言でいうと、「公開CTI ＋ 自社のログ」をオフラインの解析パイプラインで照合し、確度を明示し、そのまま観測（COUNT）に使える WAF ルール案を作るツールです。公開 CTI の取得は準備用コマンドを明示的に実行した場合だけで、顧客データは外部へ送信しません。処理は次のようになっています。

```
入力ログ ─▶ パーサ ─▶ 共通イベント(WebEvent) ─▶ 照合エンジン ─▶ 検出結果 ─▶ 集計・トリアージ・スコアリング ─▶ 防御候補 / COUNT ルール
（AWS WAF /            （ソース非依存に          （Sigma もしくは            （private と                （IP・ASN・JA4 単位、          （人間がレビューして
  nginx / Apache）      正規化）                  Nuclei 由来のマッチャ）      sanitized を分離）          挙動スコア・評判付与）        適用）
```

1. **入力の正規化** — 形式の異なるログ（AWS WAF の JSON、nginx/Apache のアクセスログ）を、共通の内部形式 `WebEvent` に変換します。以降の処理はログ形式に依存しません。
2. **公開CTIの静的取り込み** — `shenron-lab nuclei update` を明示的に実行すると、公開 Nuclei テンプレートをローカル checkout へ取得できます。その後、YAML を静的解析し、「method・path・query・fragment・ヘッダ」というリクエスト条件だけを抽出します。テンプレートは実行せず、顧客データも送信しません。ペイロードを展開、多段リクエストやレスポンス確認が必要なものは False Positive を避けたいので理由を付けて対象外にします。
3. **照合（マッチング）** — 上記のマッチャをログの各 `WebEvent` に当て、CVE 関連のリクエストを検出します。Sigma の小さなサブセットによるルール照合も別系統で持っています。
4. **確度（fidelity）の明示** — 検出をそのまま信じさせず、2つのクリアな軸でラベル付けします。
   - **request-specificity**：`request-specific`（識別性の高い query/ヘッダ等まで一致）か、`response-unverified`（method と path だけ一致）か。
   - **path-distinctiveness**：`distinctive`（製品固有の特徴的なパス）か、`generic`（`/robots.txt` や `/login` のように誰でも叩く汎用パス）か。件数は除外せず、あくまでラベルとして付けます。
5. **トリアージ・スコアリング** — 接続元 IP・クライアント IP・JA4・（データセットがあれば）ASN 単位に集約し、観測された挙動から**挙動優先度スコア（behavior priority score）**を算出します。任意で、ローカルに用意した IP/ASN のレピュテーションデータセットや ASN 解決データを突き合わせて補足情報を付けられます（外部 API は叩きません）。
6. **防御候補と COUNT 出力** — 検出結果から防御条件の候補を作り、過去のログ全体に「もし有効だったら何件検知するか」をローカルでシミュレーションできます。書き出す WAF ルールは初期アクションが必ず `COUNT`（＝ブロックせず観測のみ）で、適用は人間が行います。

そして全体は **FIND → EXPLAIN → PIVOT → ACT → VALIDATE** というワークフローになっており、各段が下記のコマンドに対応します。

| 段階 | 目的 | 主なコマンド |
| --- | --- | --- |
| FIND | 既知の指標を過去ログから探す | `production hunt` |
| EXPLAIN / PIVOT | CVE/テンプレ・IP・JA4・ASN 単位で読み解く | `production explain` / `production ablation` |
| ACT | 防御条件の候補を作り COUNT で評価・出力 | `production count-hypotheses` / `candidate ...` |
| VALIDATE | コーパス全体で脅威カバレッジを測る | `production replay` |

**設計の柱**は、(1) テンプレを実行しない静的変換、(2) 確度を数値・ラベルで明示、(3) 入力を固定版（凍結スナップショット）にして SHA-256 で記録する再現性、(4) 「攻撃・悪用成功・侵害・攻撃者特定」を決して断定しないこと、の4点です。

## 対応する入力

- AWS WAF のログ（JSONL、`.gz` も可）
- nginx の Combined ログ
- Apache の Combined ログ、および vhost 付きログ（先頭の vhost はポート有無どちらも可）
- Nuclei テンプレート一式と、その検証結果（凍結レポート）
- CISA KEV スナップショット
- （任意）ローカルの IP/ASN 評判データセット、IP→ASN 解決データセット

すべての入力はソースに依存しない共通形式 `WebEvent` に正規化されます。

## できること

- 小さく明示的な Sigma サブセットによるログ照合
- Nuclei の CVE テンプレートの静的解析と、検知可能性（detectability）の評価
- `production inspect`：ログにどの情報が入っているか（可視性）を事前確認
- `production hunt`：検証済み Nuclei 検出条件を過去ログに照合（FIND）
- `production ablation`：URI-only から Nuclei IR・request-specific IR まで、条件の広さ別に一致件数（ボリューム）を比較
- `production replay`：ローカルの履歴コーパス全体に対し、既知検出の再観測カバレッジとその他の一致を、機微情報を含まない集計として算出
- `production count-hypotheses`：CVE ごとに「広い→狭い」WAF 条件を、ローカルの COUNT シミュレーションとして比較（推奨する条件を自動で選んだり、デプロイしたりはしません）
- `production explain`：CVE / テンプレート / リクエスト証拠の表示。既定では `response-unverified` かつ generic path の低確度ノイズを隠し、`--include-generic` で保存済みの全 finding を表示します。接続元・クライアント IP（`--show-source-ips`）、ローカル ASN データで解決した ASN（`--show-asn`）、JA4 フィンガープリント（`--show-fingerprints`）ごとの breadth/depth/時間窓トリアージと、観測挙動のみから算出する挙動優先度スコアを表示（悪性確率・攻撃成立・攻撃者特定の判定ではありません）。任意の IP/ASN レピュテーション付与は、凍結データセットだけを参照し外部照会をせず、第三者の意見として示します
- 防御候補（candidate）の作成、履歴での replay、バックエンド互換性の確認
- COUNT 固定の AWS WAF JSON / Terraform ルール断片、または OSSEC 検知 XML の出力

## クイックスタート

```bash
cargo run --bin shenron -- scan \
  --input ./tests/fixtures/aws-waf/ \
  --format aws-waf \
  --rules ./tests/fixtures/rules/
```

検出結果は JSONL として標準出力に出ます。CSV が必要なら `--output findings.csv --output-format csv` を指定してください。ルールが対応形式かどうかは事前に確認できます。

```bash
cargo run --bin shenron -- validate-rules --rules ./rules/
```

## Production hunt（本番ログのハンティング）

公開 Nuclei テンプレートを一度準備すれば、以後はログと形式だけで hunt を実行できます。

```bash
shenron-lab nuclei update
shenron production hunt --input ./logs --format apache
```

`nuclei update` は `SHENRON_DATA_DIR` があればその配下、なければ `$XDG_DATA_HOME/shenron`、さらに無ければ `~/.local/share/shenron` に `nuclei-templates/` と凍結済みの `nuclei-report.json` を保存します。`hunt`、`ablation`、`replay`、`count-hypotheses` は既定でこの場所を参照します。`hunt` の `--output` を省略した場合、`./private-results/hunt-<UTC日時>/` に private artifacts を出力します。従来どおり `--nuclei-templates`、`--nuclei-report`、`--kev-report`、`--output` で明示指定もできます。KEV は任意で、省略時は空集合として扱います。

`hunt` は、機微なリクエスト値を含む **private findings** と、それを含まない **sanitized（無害化済み）レポート**を分離して出力します。AWS WAF の検出結果は `explain` で `BLOCK` / `not-blocked` を絞り込めます。

```bash
shenron production explain \
  --findings ./private-hunt-results/private-findings.jsonl \
  --waf-outcome not-blocked \
  --show-evidence
```

`not-blocked` は「検出はされたが、記録上ブロックされなかった」リクエストを指します。これはエクスプロイト成功の証拠ではありません。nginx / Apache のログには WAF の判定自体が無いため、この分類は使えません。

`production ablation` は、URI-only から検証済み Nuclei IR までの間で一致件数を集計比較します。これは件数割合（ボリューム）の比較であって、精度（precision）・正解データ・攻撃や侵害の判定ではありません。詳細は [Detection-strategy ablation](docs/ablation.md) を参照してください。

`production explain` と sanitized レポートは、一致したパスを透明な `generic` / `distinctive` のトリアージ補助としてラベル付けします。一致を除外することはなく、精度・攻撃・悪用成功・侵害の判定でもありません。

## 防御候補（candidate）のワークフロー

検出結果と防御条件は、意図的に別物として扱います。candidate は「防御の仮説」であり、AWS WAF / Terraform 向けに書き出すには、完全なバックエンド互換性・ローカルでの履歴 replay・明示的な Web ACL の priority が必要です。

```bash
# private findings から、CVE / リクエストパターンごとに絞り込んだ候補を作成。
# AWS WAF では、既にブロック済みの検出は既定で除外します。
shenron candidate build \
  --from-findings ./private-hunt-results/private-findings.jsonl \
  --telemetry aws-waf --output ./candidates/

# 候補を選び、履歴ログ全体に対して replay。元ファイルは上書きしません。
# カバレッジは元の検出のリクエスト ID と実測イベントから算出し、ID が無ければ未算出（null）です。
shenron candidate replay \
  --candidate ./candidates/shenron-cve-202x-xxxxx-001.json \
  --input ./historical-logs --format aws-waf \
  --output ./candidates/candidate-replayed.json

# バックエンドごとに、条件を忠実に表現できるかを確認。
shenron candidate compatibility \
  --candidate ./candidates/candidate-replayed.json

# COUNT の AWS WAF ルール JSON と、証拠のサイドカーを出力。
shenron candidate export \
  --candidate ./candidates/candidate-replayed.json \
  --backend aws-waf-json --priority 100 \
  --output ./exports/candidate.aws-waf.json
```

`candidate compatibility` / `explain` / `export` は、指定しなければ候補に記録済みの telemetry profile を使います。別の profile での互換性を意図的に確認したいときだけ `--telemetry` を指定してください。

`aws-waf-json` と `terraform-aws-waf` は予防的な制御（control）の候補です。初期アクションは必ず `COUNT` で、Shenron はデプロイしません。`ossec` は nginx / Apache の Combined ログを対象にした検知ルール（XML）であり、WAF ルールでもリクエストをブロックする機能でもありません。

JA4 のように、選択した telemetry/backend では忠実に表現できない条件は、勝手に削って広いルールにするのではなく、export を拒否します。`Authorization`・`Cookie`・API キー等の秘匿ヘッダ名や、bearer/JWT らしき値を含む条件も export を拒否します。ただし `/oauth/token` のように URI に単語が含まれるだけでは拒否しません。

## ドキュメント

- [ケーススタディ（4データセットの実証）](docs/case-study.md)
- [Production hunting](docs/production-hunting.md)
- [Telemetry capabilities](docs/telemetry-capabilities.md)
- [Candidate model](docs/waf-candidate-model.md)
- [Historical replay coverage](docs/historical-replay.md)
- [COUNT hypothesis ladder](docs/count-hypotheses.md)
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
