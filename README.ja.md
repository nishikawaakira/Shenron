# Shenron

[English README](README.md)

Shenron は、Web アクセスログを対象にした Rust 製の「受動的（パッシブ）な脅威ハンティング・エンジン」です。公開されている脅威インテリジェンス（Nuclei テンプレートや CISA KEV Catalog）を、自組織のログと突き合わせ、防御ルールの候補作成を支援します。

Shenron の解析本体 `shenron` は、ターゲットへのスキャン、エクスプロイトの実行、AWS の変更や AWS API の呼び出し、WAF ルールの自動適用、`terraform plan/apply`、OSSEC の再起動、解析中のネットワーク接続を一切行いません。ログ・検出結果・IP・リクエスト値などの顧客データを外部へ送信・アップロードする機能もありません。準備用の `shenron-lab nuclei update` と `shenron-lab reputation update` は、明示的に実行した場合に公開インテリジェンスをダウンロードしますが、顧客データは送信しません。出力は必ず人間のレビューを前提とした「提案」であり、Shenron 自身が何かをデプロイすることはありません。

`shenron export --results-dir <run> --format stix|misp --output <file>` は、ログを再解析せず、既存 run をローカル CTI ファイルへ変換します。既定では sanitized 集計だけを扱い、`--include-observables` を明示した場合のみ private な観測 peer IP と URI パスを追加し、既定の marking は TLP:RED になります。ネットワーク送信は行わず、脅威アクター・campaign・攻撃・悪用・侵害・帰属を推定しません。詳細は [CTI export](docs/cti-export.md) を参照してください。

## 仕組み（アーキテクチャ概要）

一言でいうと、「公開CTI ＋ 自社のログ」をオフラインの解析パイプラインで照合し、確度を明示し、そのまま観測（COUNT）に使える WAF ルール案を作るツールです。公開 CTI の取得は準備用コマンドを明示的に実行した場合だけで、顧客データは外部へ送信しません。処理は次のようになっています。

```
入力ログ ─▶ パーサ ─▶ 共通イベント(WebEvent) ─▶ 照合エンジン ─▶ 検出結果 ─▶ 集計・トリアージ・スコアリング ─▶ 防御候補 / COUNT ルール
（AWS WAF /            （ソース非依存に          （Sigma もしくは            （private と                （IP・ASN・JA4 単位、          （人間がレビューして
  nginx / Apache）      正規化）                  Nuclei 由来のマッチャ）      sanitized を分離）          挙動スコア・評判付与）        適用）
```

1. **入力の正規化** — 形式の異なるログ（AWS WAF の JSON、nginx/Apache のアクセスログ）を、共通の内部形式 `WebEvent` に変換します。以降の処理はログ形式に依存しません。
2. **公開CTIの静的取り込み** — `shenron-lab nuclei update` を明示的に実行すると公開 Nuclei テンプレートを、`shenron-lab reputation update` を実行すると公開 IP レピュテーション／IPv4 ASN リストをローカルに取得できます。いずれも顧客データは送信しません。Nuclei テンプレートは静的解析し、「method・path・query・fragment・ヘッダ」というリクエスト条件だけを抽出します。ペイロードを展開、多段リクエストやレスポンス確認が必要なものは False Positive を避けたいので理由を付けて対象外にします。
3. **照合（マッチング）** — 上記のマッチャをログの各 `WebEvent` に当て、CVE 関連のリクエストを検出します。Sigma の小さなサブセットによるルール照合も別系統で持っています。
4. **確度（fidelity）の明示** — 検出をそのまま信じさせず、2つのクリアな軸でラベル付けします。
   - **request-specificity**：`request-specific`（識別性の高い query/ヘッダ等まで一致）か、`response-unverified`（method と path だけ一致）か。
   - **path-distinctiveness**：`distinctive`（製品固有の特徴的なパス）か、`generic`（`/robots.txt` や `/login` のように誰でも叩く汎用パス）か。件数は除外せず、あくまでラベルとして付けます。
5. **トリアージ・スコアリング** — 接続元 IP・クライアント IP・JA4・（データセットがあれば）ASN 単位に集約し、観測された挙動から**挙動優先度スコア（behavior priority score）**を算出します。`shenron-lab reputation update` で任意の公開 IP/ASN データをローカル準備でき、`explain` は外部 API を使わず参照します。
6. **防御候補と COUNT 出力** — 検出結果から防御条件の候補を作り、過去のログ全体に「もし有効だったら何件検知するか」をローカルでシミュレーションできます。書き出す WAF ルールは初期アクションが必ず `COUNT`（＝ブロックせず観測のみ）で、適用は人間が行います。

そして全体は **FIND → EXPLAIN → PIVOT → ACT → VALIDATE** というワークフローになっており、各段が下記のコマンドに対応します。

| 段階 | 目的 | 主なコマンド |
| --- | --- | --- |
| FIND | 既知の指標を過去ログから探す | `hunt` |
| EXPLAIN / PIVOT | CVE/テンプレ・IP・JA4・ASN 単位で読み解く | `explain` / `ablation` |
| ACT | 防御条件の候補を作り COUNT で評価・出力 | `count-hypotheses` / `candidate ...` |
| VALIDATE | コーパス全体で脅威カバレッジを測る | `replay` |

**設計の柱**は、(1) テンプレを実行しない静的変換、(2) 確度を数値・ラベルで明示、(3) 入力を固定版（凍結スナップショット）にして SHA-256 で記録する再現性、(4) 「攻撃・悪用成功・侵害・攻撃者特定」を決して断定しないこと、の4点です。

`hunt` は [申告属性と観測事実の整合性](docs/declared-observed-consistency.md) も決定論的にラベル付けします。参照データなし・テレメトリ非対応・観測値欠落は、それぞれ区別された `unavailable` であり不一致には数えません。申告値と観測値は private 成果物だけに保存し、結果から、なりすまし・自動化・攻撃・悪用・侵害・主体を断定しません。

## 対応する入力

- AWS WAF のログ（JSONL、`.gz` も可）
- nginx の Combined ログ
- Apache の Combined ログ（`--format apache` は標準 Combined と vhost 前置き Combined を行単位で自動判別。先頭の vhost はポート有無どちらも可。`--format apache-vhost` は vhost 前置きを厳格に要求）
- Nuclei テンプレート一式と、その検証結果（凍結レポート）
- CISA KEV スナップショット
- （任意）ローカルの IP/ASN 評判データセット、IP→ASN 解決データセット

すべての入力はソースに依存しない共通形式 `WebEvent` に正規化されます。

## できること

- 小さく明示的な Sigma サブセットによるログ照合
- Nuclei の CVE テンプレートの静的解析と、検知可能性（detectability）の評価
- `inspect`：ログにどの情報が入っているか（可視性）を事前確認
- `hunt`：検証済み Nuclei 検出条件を過去ログに照合（FIND）
- `ablation`：URI-only から Nuclei IR・request-specific IR まで、条件の広さ別に一致件数（ボリューム）を比較
- `replay`：ローカルの履歴コーパス全体に対し、既知検出の再観測カバレッジとその他の一致を、機微情報を含まない集計として算出
- `count-hypotheses`：CVE ごとに「広い→狭い」WAF 条件を、ローカルの COUNT シミュレーションとして比較（推奨する条件を自動で選んだり、デプロイしたりはしません）
- `concentration`：CTI 入力なしで、固定上限と上限超過件数を明示したリクエスト量分布を集計します。パスと観測した接続ピア IP は private artifact の `request-concentration.json` に分離し、sanitized 側には集計だけを残します。これは DoS・攻撃・悪用・侵害・攻撃者特定の判定ではありません。詳細は [Request concentration](docs/request-concentration.md) を参照してください。
- `concentration` は既定で 1分・10分・1時間・1日の決定論的なリクエスト率を同時に表示し、`--rate-window` で集合を変更できます。`explain` の `--triage-window` も繰り返しまたはカンマ区切りで複数指定できますが、windowed-burst の加点は窓数にかかわらず5点の一度だけです。
- private な entity triage では、`--sequence-window` で設定可能な bounded な[リクエスト順序](docs/request-sequences.md)と間隔も表示します。これは確認用の観測情報であり、自動化・攻撃・悪用・侵害・主体を判定するものではありません。
- `hunt --observation-store <PATH>` を明示した場合のみ、複数 run で再観測された network prefix と任意のローカル ASN を bounded・append-only な[private 観測メモリ](docs/observation-store.md)へ保存します。既定では無効で、同一所有者・運営者・主体を示すものではありません。
- `shenron-lab generate --profile volumetric-concentration`：実ログを共有せずに分散した量的集中の形状を再現できる、決定論的な 40,000 リクエストの合成コーパスを生成します。実在の攻撃・攻撃者・campaign・脆弱性・DoS を表すものではありません。詳細は [Synthetic corpus](docs/synthetic-corpus.md) を参照してください。
- `concentration --path /example/path --show-source-ips`：特定の正規化済みパスに対する観測接続ピアごとのリクエスト件数を private 側で確認できます。`--path-prefix /example` はそのパス以下（サブツリー）をまとめて分析し、配下の個別パス（`--show-paths`）とアクセス元ピアを一覧表示します。`--source-ip <IP>` は逆向きで、カンマ区切りまたはフラグの繰り返しによって 1 件以上の IP を指定でき、それらの観測ピアが送った URI パスの union を表示します。複数 IP の場合、`--show-source-ips` は IP ごとの private なリクエスト件数内訳も表示します。選択したパス、IP、内訳は private artifact のみに保存し、sanitized 側は集計だけを残します。これは集中状況の文脈であり、観測 peer は攻撃者特定ではありません。
- 同じ private フォーカス表示では、IP 単位の行を残したままネットワークプレフィックス単位にも集約します（IPv4 は既定 `/24`、IPv6 は既定 `/48`、`--ipv4-group-prefix` / `--ipv6-group-prefix` で変更可能）。プレフィックスの共有は所有者・運用主体・行為者の共有を意味しません。
- ローカル ASN データセットがある場合は `--asn-dataset <PATH>` を追加すると、IP／プレフィックス表示と並べて private な ASN 集約を表示し、未解決 peer も件数で開示します。ASN は経路上のグループにすぎず、単一運用者・帰属・DoS・攻撃・悪用を示すものではありません。ASN 番号と組織名は sanitized 出力に入りません。
- `hunt --input <logs> --report`：ログ解析と同じ run 内の private HTML レポート生成を一度に行います。既存の hunt / concentration run は `hunt --results-dir <run-dir> --lang ja` で生ログを再解析せず再レンダリングでき、`--report <path>` で既定の `<run-dir>/report.html` を上書きできます。パス・IP の棒グラフ、分刻み時系列（集計された HTTP ステータスクラス 1xx〜5xx の5本の折れ線を含む）、hunt triage に加え、観測 CVE ごとに一致した Nuclei テンプレート ID とカタログ宣言 severity を一覧表示します。ステータスクラスの分系列は集計件数だけを含み、private な concentration artifact のみに保存して sanitized 出力へはコピーしません。この公開 CTI の ID は sanitized の CVE 集計にも決定論的な `template_ids` として保存され、顧客のリクエスト値は追加しません。CVE severity は Nuclei `info.severity`、Sigma severity 集計は Sigma `level` に由来し、Shenron による影響・悪用・侵害・悪性・帰属の判定ではありません。両方の時系列を CSS だけでホバーでき、ステータス表示では UTC の分と全クラスの件数を確認できます。テンプレート ID は公開 GitHub コード検索へのリンクですが、レポートを開くだけでは通信せず、クリック時にも公開 ID だけを送信して private 値は送りません。生のパスと IP を含む private 成果物であり、JavaScript や自動取得される外部リソースは使いません。DoS・攻撃・悪用・侵害・悪性確率・攻撃者特定の判定ではありません。詳細は [Private offline HTML report](docs/html-report.md) を参照してください。
- `compare`：2つのローカル凍結 run artifact を差分比較します。`hunt --baseline <prior-run>` では新しい hunt 後に同じ比較を出力します。CVE の差分と集計は sanitized 側、first-seen entity とパス/IP 詳細は private 側に分離されます。first-seen や elevated-volume は悪性・攻撃・侵害・攻撃者特定の判定ではありません。詳細は [Temporal comparison](docs/temporal-comparison.md) を参照してください。
- `hunt`：毎回、集計のみの `triage-summary.json` と、優先順付き private `triage-view.json` も出力します。IP 等の private 値を標準出力に表示するには `--show-triage`（必要なら `--limit`）を指定します。この順序は人間が先に確認するためのトリアージであり、脅威の重大度・悪性確率ではありません。first-seen は「新規なので要確認」であって悪性の断定ではありません。
- `explain`：CVE / テンプレート / リクエスト証拠の表示。既定では `response-unverified` かつ generic path の低確度ノイズを隠し、`--include-generic` で保存済みの全 finding を表示します。これは**表示フィルタのみ**で、一覧表示を変えるだけであり、トリアージのグルーピングやスコアリングには影響しません（グルーピング/スコアは常に全 finding を対象にします）。そのため、distinctive な探索1件と generic 複数件を混ぜた送信元も breadth 判定に達します。接続元・クライアント IP（`--show-source-ips`）、ローカル ASN データで解決した ASN（`--show-asn`）、JA4 フィンガープリント（`--show-fingerprints`）ごとの breadth/depth/時間窓トリアージと、観測挙動のみから算出する挙動優先度スコアを表示します。スコアは generic path の反復による深さを意図的に抑え、distinctive path の一致へ小さな寄与を与え、合計はその finding のテレメトリ・プロファイルが到達可能な最大値で正規化します（WAF 判定のない combined ログが構造的に低く出るのを防ぎます）。ただし悪性確率・攻撃成立・攻撃者特定の判定ではありません。`shenron-lab reputation update` で準備されたローカル IP/ASN データは既定で自動参照し、明示指定のデータセットは引き続き優先します。レピュテーションは外部照会をせず、第三者の意見として示します。`--output-format json`（任意で `--output <PATH>`）を付けると、スコア・スコア内訳・トリアージ根拠・グルーピングを機械可読の `EXPLAIN_PRIVATE_TRIAGE` レポートとして出力します（テキストと同一の `--show-*` プライバシーゲートを尊重）
- 防御候補（candidate）の作成、履歴での replay、バックエンド互換性の確認
- COUNT 固定の AWS WAF JSON / Terraform ルール断片、または OSSEC 検知 XML の出力

## ビルド済みバイナリ

タグ付きリリースでは、Linux（`x86_64`/`aarch64`、glibc および静的 musl）、macOS
（Intel / Apple Silicon）、Windows（`x86_64`）向けの `shenron` と `shenron-lab`
バイナリを [Releases](../../releases) ページで配布します。各アーカイブには
`.sha256` チェックサムが付き、ライセンスと README を同梱します。リリースを作成
するには、バージョンタグを push すると `Release` ワークフローがビルドして成果物を
添付します:

```bash
git tag v0.1.0
git push origin v0.1.0
```

ソースからのビルドには stable の Rust ツールチェインが必要です。リリースビルドは
`cargo build --release --bin shenron --bin shenron-lab` です。

## クイックスタート

```bash
cargo run --bin shenron -- scan \
  --input ./tests/fixtures/aws-waf/ \
  --rules ./tests/fixtures/rules/
```

検出結果は JSONL として標準出力に出ます。CSV が必要なら `--output findings.csv --output-format csv` を指定してください。ルールが対応形式かどうかは事前に確認できます。

```bash
cargo run --bin shenron -- validate-rules --rules ./rules/
```

## Production hunt（本番ログのハンティング）

公開 Nuclei テンプレート、CISA KEV、IP レピュテーション、ASN、公開クローラーレンジを一度準備すれば、安全に識別できるログは入力だけで hunt を実行できます。

```bash
shenron-lab setup
shenron hunt --input ./waf-logs
```

追記・ローテーションされるログの日次運用では、`--input` にログディレクトリを指定し、
`--since 24h` と `--baseline-latest ./private-results` を組み合わせられます。
Shenron はディレクトリツリーと gzip ローテーションを読み、解決した移動窓の境界を記録し、
ソート可能なディレクトリ名から直近の有効 run を選びます。窓自体の厳密な再現が必要な場合は
`--from/--to` を明示してください。

ログ入力コマンドの既定は `--format auto` です。AWS WAF JSON と vhost 前置き Apache Combined は自動識別します。標準 nginx Combined と標準 Apache Combined は構造が同一で安全に区別できないため、その場合だけ `--format nginx` または `--format apache` を指定してください。`--format apache` は標準行と vhost 前置き行の両方を受け付け、`--format apache-vhost` は vhost 前置きを厳格に要求します。

`setup` は `SHENRON_DATA_DIR` があればその配下、なければ `$XDG_DATA_HOME/shenron`、さらに無ければ `~/.local/share/shenron` に `nuclei-templates/`、凍結済みの `nuclei-report.json`、CISA KEV の `known_exploited_vulnerabilities.json`、凍結結合結果の `kev-report.json`、provenance を持つ `kev-manifest.json`、任意の `reputation.jsonl`、`asn-ranges.tsv`、`bot-ranges.json` を保存します。`hunt`、`ablation`、`replay`、`count-hypotheses` は既定でこの場所を参照します。`hunt` の `--output` を省略した場合、`./private-results/hunt-<UTC日時>/` に private artifacts を出力します。従来どおり `--nuclei-templates`、`--nuclei-report`、`--kev-report`、`--output` で明示指定もできます。`--kev-report` 省略時は準備済みの既定レポートがあれば参照し、無ければ空集合として扱います。`setup --skip-kev` で KEV 準備だけを省略できます。

個別の公開入力だけを更新したい場合は、従来どおり `shenron-lab nuclei update`、`shenron-lab reputation update`、`shenron-lab bot-ranges update` も使えます。`setup` が取得するのは公開インテリジェンスだけで、顧客データを送信しません。

レピュテーション／ASN の各公開ソースは独立に取得を試みます。一部が失敗しても取得・変換できたレコードは保持し、失敗したソースと理由を `reputation-manifest.json` に記録したうえで非ゼロ終了します。

凍結済み bot-range snapshot がある場合、hunt は自己申告された bot User-Agent と運営者の公開レンジをオフライン照合し、レンジ内外の集計を sanitized 出力へ、レンジ外の観測 peer IP を private `bot-range-observations.json` へ保存します。snapshot が無ければ注記してスキップし、CVE/Sigma 指標は変えません。レンジ外という観測は、レンジの古さ・欠落、中継、自由に設定できる User-Agent の影響を受けるため、なりすまし・攻撃・悪用・帰属の判定ではありません。詳細は [Published bot ranges](docs/published-bot-ranges.md) を参照してください。

`hunt` は CVE 主体の Nuclei パスに加えて、汎用的な **Sigma** 検出パスを**既定で ON**にして同一ストリームで実行します。CVE テンプレートに対応しない汎用 TTP（例：`.env` などの機密ファイル探索）を拾えます。ルールは `--rules <DIR>` か準備済みの `<data-dir>/sigma-rules` から読み込み、`--no-sigma` で無効化できます。`shenron-lab setup` が Shenron 対応の同梱パックをそこへ配置するので、追加設定なしで動きます。さらに `setup --sigma-source <git-url>` で外部ソース（例：SigmaHQ）の `rules/web` も取得できます。Sigma の finding は `source` フィールドを持ち、CVE 指標とは別に集計され、`candidate build` には入りません（候補は CVE / Nuclei-IR 主体のまま）。詳細は [Sigma detection inside hunt](docs/sigma-in-hunt.md) を参照。

同梱の秘密・設定ファイル探索ルールでは、記録された応答が 2xx の一致を人手確認の最優先として強調し、private HTML レポートに証跡を一覧表示します。他の一致を除外するものではなく、2xx はファイル内容の開示・攻撃・悪用・侵害を証明しません。ステータスが取得できない場合は確認不可のままで、成功扱いにはしません。

`hunt` は、機微なリクエスト値を含む **private findings** と、それを含まない **sanitized（無害化済み）レポート**を分離して出力します。AWS WAF の検出結果は `explain` で `BLOCK` / `not-blocked` を絞り込めます。

```bash
shenron explain \
  --findings ./private-hunt-results/private-findings.jsonl \
  --waf-outcome not-blocked \
  --show-evidence
```

`not-blocked` は「検出はされたが、記録上ブロックされなかった」リクエストを指します。これはエクスプロイト成功の証拠ではありません。nginx / Apache のログには WAF の判定自体が無いため、この分類は使えません。

`ablation` は、URI-only から検証済み Nuclei IR までの間で一致件数を集計比較します。これは件数割合（ボリューム）の比較であって、精度（precision）・正解データ・攻撃や侵害の判定ではありません。詳細は [Detection-strategy ablation](docs/ablation.md) を参照してください。

`explain` のサマリはリクエストの method/path 単位で CVE とテンプレートを束ねるため、同一パスに複数の CVE が割り当たる場合も1項目で確認できます。`explain` と sanitized レポートは、一致したパスを透明な `generic` / `distinctive` のトリアージ補助としてラベル付けします。一致を除外することはなく、精度・攻撃・悪用成功・侵害の判定でもありません。

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

## ライセンス

Shenron は GNU Affero General Public License v3.0（`AGPL-3.0-only`）で提供されます。
これは [Hayabusa](https://github.com/Yamato-Security/hayabusa) に合わせたものです。
全文は [LICENSE](LICENSE) を参照してください。AGPL のため、ネットワーク越しに本ソフトウェアの
機能を利用者へ提供する場合は、その利用者に対応するソースコードを提供する義務が生じます
（AGPL 第13条）。

Copyright (C) 2026 Akira Nishikawa
