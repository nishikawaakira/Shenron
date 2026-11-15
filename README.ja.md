# Shenron

[English README](README.md)

非一致リクエストも確認する `context`、原本の行参照、スコープ付き判定と再レビュー期限、比較条件の開示、複数 run の基準値比較、`candidate evaluate` の使い方は [Investigation workflow](docs/investigation-workflow.md) を参照してください。すべて明示指定のローカルレビュー機能であり、自動判定は行わず、既定の動作も変更しません。

Shenron は、Web アクセスログを対象にした Rust 製の「受動的（パッシブ）な脅威ハンティング・エンジン」です。公開されている脅威インテリジェンス（Nuclei テンプレートや CISA KEV Catalog）を、自組織のログと突き合わせ、防御ルールの候補作成を支援します。

単一バイナリ `shenron` の解析コマンドは既定ではネットワーク接続せず、ターゲットへのスキャン、エクスプロイトの実行、AWS の変更や AWS API の呼び出し、WAF ルールの自動適用、`terraform plan/apply`、OSSEC の再起動を行いません。ログ・検出結果・IP・リクエスト値などの生の顧客データを外部へ送信・アップロードしません。ネットワークを使うのは、明示的に実行した `setup` / `nuclei update` / `kev` / `reputation update` / `bot-ranges update` と、`SHENRON_SLACK_WEBHOOK` を設定した hunt 完了後通知だけです。取得コマンドは公開インテリジェンスのダウンロードだけを行い、Slack 通知は sanitized 集計だけを送り、生 IP・パス・ホスト・ヘッダー・ログ値・private findings は含みません。出力は必ず人間のレビューを前提とした「提案」であり、Shenron 自身が何かをデプロイすることはありません。

`shenron export --results-dir <run> --format stix|misp --output <file>` は、ログを再解析せず、既存 run をローカル CTI ファイルへ変換します。既定では sanitized 集計だけを扱い、`--include-observables` を明示した場合のみ private な観測 peer IP と URI パスを追加し、既定の marking は TLP:RED になります。ネットワーク送信は行わず、脅威アクター・campaign・攻撃・悪用・侵害・帰属を推定しません。詳細は [CTI export](docs/cti-export.md) を参照してください。

## 仕組み（アーキテクチャ概要）

一言でいうと、「公開CTI ＋ 自社のログ」をオフラインの解析パイプラインで照合し、確度を明示し、そのまま観測（COUNT）に使える WAF ルール案を作るツールです。公開 CTI の取得は準備用コマンドを明示的に実行した場合だけで、顧客データは外部へ送信しません。処理は次のようになっています。

```
入力ログ ─▶ パーサ ─▶ 共通イベント(WebEvent) ─▶ 照合エンジン ─▶ 検出結果 ─▶ 集計・トリアージ・スコアリング ─▶ 防御候補 / COUNT ルール
（AWS WAF /            （ソース非依存に          （Sigma もしくは            （private と                （IP・ASN・JA4 単位、          （人間がレビューして
  nginx / Apache）      正規化）                  Nuclei 由来のマッチャ）      sanitized を分離）          挙動スコア・評判付与）        適用）
```

1. **入力の正規化** — 形式の異なるログ（AWS WAF の JSON、nginx/Apache のアクセスログ）を、共通の内部形式 `WebEvent` に変換します。以降の処理はログ形式に依存しません。
2. **公開CTIの静的取り込み** — `shenron nuclei update` を明示的に実行すると公開 Nuclei テンプレートを、`shenron reputation update` を実行すると公開 IP レピュテーション／IPv4 ASN リストをローカルに取得できます。いずれも顧客データは送信しません。Nuclei テンプレートは静的解析し、「method・path・query・fragment・ヘッダ」というリクエスト条件だけを抽出します。ペイロードを展開、多段リクエストやレスポンス確認が必要なものは False Positive を避けたいので理由を付けて対象外にします。
3. **照合（マッチング）** — 上記のマッチャをログの各 `WebEvent` に当て、CVE 関連のリクエストを検出します。Sigma の小さなサブセットによるルール照合も別系統で持っています。
4. **確度（fidelity）の明示** — 検出をそのまま信じさせず、2つのクリアな軸でラベル付けします。
   - **request-specificity**：`request-specific`（識別性の高い query/ヘッダ等まで一致）か、`response-unverified`（method と path だけ一致）か。
   - **path-distinctiveness**：`distinctive`（製品固有の特徴的なパス）か、`generic`（`/robots.txt` や `/login` のように誰でも叩く汎用パス）か。件数は除外せず、あくまでラベルとして付けます。
5. **トリアージ・スコアリング** — 接続元 IP・クライアント IP・JA4・（データセットがあれば）ASN 単位に集約し、観測された挙動から**挙動優先度スコア（behavior priority score）**を算出します。`shenron reputation update` で任意の公開 IP/ASN データをローカル準備でき、`explain` は外部 API を使わず参照します。
6. **防御候補と COUNT 出力** — 検出結果から防御条件の候補を作り、過去のログ全体に「もし有効だったら何件検知するか」をローカルでシミュレーションできます。書き出す WAF ルールは初期アクションが必ず `COUNT`（＝ブロックせず観測のみ）で、適用は人間が行います。

そして全体は **FIND → EXPLAIN → PIVOT → ACT → VALIDATE** というワークフローになっており、各段が下記のコマンドに対応します。

| 段階 | 目的 | 主なコマンド |
| --- | --- | --- |
| FIND | 既知の指標を過去ログから探す | `hunt` |
| EXPLAIN / PIVOT | CVE/テンプレ・IP・JA4・ASN 単位で読み解く | `explain` / `ablation` |
| ACT | 防御条件の候補を作り COUNT で評価・出力 | `count-hypotheses` / `candidate ...` |
| VALIDATE | コーパス全体で脅威カバレッジを測る | `replay` |

**設計の柱**は、(1) テンプレを実行しない静的変換、(2) 確度を数値・ラベルで明示、(3) 入力を固定版（凍結スナップショット）にして SHA-256 で記録する再現性、(4) 「攻撃・悪用成功・侵害・攻撃者特定」を決して断定しないこと、の4点です。

`hunt` は [申告属性と観測事実の整合性](docs/declared-observed-consistency.md) も決定論的にラベル付けします。参照データなし・テレメトリ非対応・観測値欠落は、それぞれ区別された集計 `unavailable` であり不一致には数えません。申告値と観測値を保持する個別レコードは上限付きの不一致だけを private 成果物に保存し、結果から、なりすまし・自動化・攻撃・悪用・侵害・主体を断定しません。

成果物のタイムスタンプは UTC の RFC 3339 値として保存し続けます。hunt・`explain`・HTML 時系列の人間向け表示には UTC を明示し、ホスト OS の暗黙タイムゾーンは使用しません。

## 対応する入力

- ALB アクセスログ（`--format alb`）：リクエスト URL 由来のホスト、接続元とポート、応答、TLS、trace ID を共通形式に正規化します。処理時間の合成や WAF action の推定はしません。
- CloudFront 標準ログのレガシー TSV（`--format cloudfront`）：列順はファイルごとの `#Fields:` から取得し、ヘッダーなしの場合は既定順の使用を private manifest に記録します。UA／Referer は1回だけデコードし、Cookie は raw を含めて保持しません。検証済み client IP は `--trusted-proxy` の明示設定時だけ利用します。JSON／Parquet などの新形式は対象外です。

ALB と、先頭が `#Version: 1.0`・`#Fields:` の2行で始まる CloudFront は `--format auto` でも判別します。ヘッダーなしの CloudFront は明示指定が必要です。詳細は [Production hunting](docs/production-hunting.md#alb-and-legacy-cloudfront-inputs) を参照してください。

- AWS WAF のログ（JSONL、`.gz` も可）
- nginx の Combined ログ
- nginx の本文付き拡張ログ（`--format nginx-postdata` を明示指定。Combined の後に Content-Type・TLS protocol・cipher・request duration・`postdata[<body>]` が必要で、`--format auto` の検出対象外）。`response-sizes` の本文依存の解析にはこの形式を使います。既存の解析コマンドでは標準 Combined も引き続き利用できます。詳細は [Response-size observations](docs/response-sizes.md) を参照してください。
- Apache の Combined ログ（`--format apache` は標準 Combined と vhost 前置き Combined を行単位で自動判別。先頭の vhost はポート有無どちらも可。`--format apache-vhost` は vhost 前置きを厳格に要求）
- Nuclei テンプレート一式と、その検証結果（凍結レポート）
- CISA KEV スナップショット
- （任意）ローカルの IP/ASN 評判データセット、IP→ASN 解決データセット

すべての入力はソースに依存しない共通形式 `WebEvent` に正規化されます。

ログのディレクトリ探索では、形式ごとの対応拡張子に加えて、拡張子なしと数字だけの拡張子を持つローテーション済みログも読みます。ディレクトリ内の隠しファイル・隠しディレクトリ・非対応拡張子・シンボリックリンクは読み飛ばし、件数と理由を開示します（`context` はシンボリックリンクでエラー）。隠しディレクトリは中を走査せず1件と数えます。入力として直接指定したディレクトリは隠しディレクトリでも走査し、直接指定したファイルは拡張子にかかわらず読みます。拡張子なしのログ以外のファイルも解析対象になるため、ログ専用のディレクトリを推奨します。gzip は拡張子でなく magic bytes で判定し、連結された全メンバーを読みます。読み飛ばしたパスは private の provenance にだけ残します。新たに読み込み対象になったファイルは、一致する provenance が既に index にない限り、`--processed-index` では未処理として扱われます。詳細は [Production hunting](docs/production-hunting.md) を参照してください。

## できること

- `rare-success`：少数の送信元だけに成功ステータスが観測されたパスと、探索の形の後に成功ステータスが観測された前後関係を、1回のオフライン読み込みで集計します。ID テンプレートと探索条件は既存処理を共有します。成功は設定したステータスクラスだけを意味し、アプリケーションの結果や因果関係の判定ではありません。管理画面や正規の連携も同じ形になります。既定の表示と sanitized 成果物は集計だけで、パスと送信元はそれぞれ明示指定時だけ表示します。詳細は [Rare response-status patterns](docs/rare-success.md) を参照してください。
- `ioc`：運用者が渡した TSV／限定した STIX 2.1 指標をローカルの履歴ログへ遡及照合します。IP／CIDR は索引で照合し、観測 peer と検証済み client の一致を別集計、有効期間外の一致も残します。既定の標準出力と `sanitized-ioc.json` は件数だけで、値・ラベル・指標ファイルの情報・上限付き証跡は private に分離し、外部送信しません。一致は攻撃・侵害・意図・帰属・同一運営主体の判定ではなく、CDN・NAT・共有クラウドの IP は無関係な利用者とも一致し得ます。詳細は [IOC observations](docs/ioc.md) を参照してください。

- 小さく明示的な Sigma サブセットによるログ照合
- Nuclei の CVE テンプレートの静的解析と、検知可能性（detectability）の評価
- `hunt`：検証済み Nuclei 検出条件を過去ログに照合し、全件のフィールド可用性・解析品質・時刻カバレッジも生値なしの集計として表示（FIND）
- `request-anomalies`：エンコードの形と標準でないリクエスト行を、最大2回のバイトデコードで計測します。Combined の救済はこのコマンドだけで行い、`hunt` などの parser・結果は変えません。既定の標準出力と `sanitized-request-anomalies.json` は集計のみで、例は `--show-examples`、送信元は `--show-source-ips` で明示表示します。文字列の形や 2xx は、攻撃・悪用の成立・侵害の判定ではありません。詳細は [Request spelling observations](docs/request-anomalies.md) を参照してください。
- `probe-sources`：Nuclei・Sigma の finding に依存せず、接続元ごとのパスの幅、オフラインのパスカタログとの一致、応答ステータス、選択したコーパス内で 2xx が観測されなかったパスの割合を上限付きで計数します。設定可能な確認条件とその充足状況を示し、`probe-shaped` は人が確認する優先度のための観測ラベルです。攻撃・侵害・悪意・攻撃者特定の判定でも、遮断の推奨でもありません。CDN・LB・NAT・プロキシ、正規の監視・診断・クローラーも同じ形になり得ます。既定の標準出力と `sanitized-research.json` は集計だけで、個別の接続元は `--show-source-ips`、例示パスは追加の `--show-paths` で表示します。User-Agent 値は private 成果物だけに保存します。詳細は [Probe-source request shapes](docs/probe-sources.md) を参照してください。
- `identifier-access`：送信元・メソッド・ホスト・テンプレート・ID 位置ごとに、数値／UUID の ID だけが異なるリクエストを上限付きで集計し、ID の種類数、ステータス／サイズの観測、同じ peer の別エントリからの先行書き込みを記録します。`--method GET --method HEAD` などでメソッドを明示的に絞れます。`content`／`rejected` はステータスとサイズに基づく観測であり、攻撃・認可の欠陥・情報開示の判定ではありません。標準出力は集計と測定値の表で、送信元は `--show-source-ips`、テンプレート等は `--show-paths` で表示します。ID 値を含む `identifier-access.json` と、集計だけの `sanitized-identifier-access.json` を分離します。詳細は [Identifier-access observations](docs/identifier-access.md) を参照してください。
- `response-sizes` / `production response-sizes`：`--format nginx-postdata` の本文付きログで、送信バイト数の差を補正した応答サイズから、対応する対照と読み出しの長さ候補を比較します。1文字ずつの読み出しは試した文字位置として別集計し、長さとは扱いません。`fit_rate` は HEX で包んだ読み出しの偶奇だけを検査します。ゼロは空文字列と NULL を区別せず、負の候補値も NULL と断定しません。内容の復元や情報開示の判定は行いません。既定の標準出力と `sanitized-response-sizes.json` は集計だけで、送信元は `--show-source-ips`、式は `--show-expressions` で明示表示します。式・ホスト・証跡は private の `response-sizes.json` に保存します。詳細は [Response-size observations](docs/response-sizes.md) を参照してください。
- `context`：Nuclei／Sigma に一致しないものも含め、指定した観測 peer のリクエストを確認します。`--from`／`--to` は片側だけでも省略しても使え、既定の標準出力は件数と保持した記録の UTC 期間（`earliest_retained`／`latest_retained`）です。既定の保持上限は `--max-records 10000` で、省略件数を開示します。private な各記録は `--show-request`、クエリと Referer は追加の `--show-query` で表示します。保持期間は省略された記録を含む全期間ではありません。詳細は [Investigation workflow](docs/investigation-workflow.md) を参照してください。
- `ablation`：URI-only から Nuclei IR・request-specific IR まで、条件の広さ別に一致件数（ボリューム）を比較
- `replay`：ローカルの履歴コーパス全体に対し、既知検出の再観測カバレッジとその他の一致を、機微情報を含まない集計として算出
- `count-hypotheses`：CVE ごとに「広い→狭い」WAF 条件を、ローカルの COUNT シミュレーションとして比較（推奨する条件を自動で選んだり、デプロイしたりはしません）
- `concentration`：CTI 入力なしで、異なる観測送信元 IP あたりのリクエスト数を含む、固定上限と上限超過件数を明示したリクエスト量分布を集計します。パスと観測した接続ピア IP は private artifact の `request-concentration.json` に分離し、sanitized 側には集計だけを残します。これは DoS・攻撃・悪用・侵害・攻撃者特定の判定ではありません。詳細は [Request concentration](docs/request-concentration.md) を参照してください。
- `concentration` は、クエリ文字列や値を出力せず、パスごとのクエリ付与件数と保持したクエリ／キーの distinct 数も測定します。private HTML レポートでは上位の観測接続ピアごとに 1xx〜5xx の応答ステータスを積み上げグラフで表示し、sanitized 側には集計クエリ件数だけを残して IP は含めません。これは人手確認用のリクエスト／応答形状であり、キャッシュ回避・DoS・攻撃・悪用・侵害・帰属の分類ではありません。
- `concentration` は既定で 1分・10分・1時間・1日の決定論的なリクエスト率を同時に表示し、`--rate-window` で集合を変更できます。`explain` の `--triage-window` も繰り返しまたはカンマ区切りで複数指定できますが、windowed-burst の加点は窓数にかかわらず5点の一度だけです。
- private な entity triage では、`--sequence-window` で設定可能な bounded な[リクエスト順序](docs/request-sequences.md)と間隔も表示します。これは確認用の観測情報であり、自動化・攻撃・悪用・侵害・主体を判定するものではありません。
- `hunt --observation-store <PATH>` を明示した場合のみ、複数 run で再観測された network prefix と任意のローカル ASN を bounded・append-only な[private 観測メモリ](docs/observation-store.md)へ保存します。既定では無効で、同一所有者・運営者・主体を示すものではありません。
- `shenron generate --profile volumetric-concentration`：実ログを共有せずに分散した量的集中の形状を再現できる、決定論的な 40,000 リクエストの合成コーパスを生成します。実在の攻撃・攻撃者・campaign・脆弱性・DoS を表すものではありません。詳細は [Synthetic corpus](docs/synthetic-corpus.md) を参照してください。
- `concentration --path /example/path --show-source-ips`：特定の正規化済みパスに対する観測接続ピアごとのリクエスト件数を private 側で確認できます。`--path-prefix /example` はそのパス以下（サブツリー）をまとめて分析し、配下の個別パス（`--show-paths`）とアクセス元ピアを一覧表示します。`--source-ip <IP>` は逆向きで、カンマ区切りまたはフラグの繰り返しによって 1 件以上の IP を指定でき、それらの観測ピアが送った URI パスの union を表示します。複数 IP の場合、`--show-source-ips` は IP ごとの private なリクエスト件数内訳も表示します。選択したパス、IP、内訳は private artifact のみに保存し、sanitized 側は集計だけを残します。これは集中状況の文脈であり、観測 peer は攻撃者特定ではありません。
- 同じ private フォーカス表示では、IP 単位の行を残したままネットワークプレフィックス単位にも集約します（IPv4 は既定 `/24`、IPv6 は既定 `/48`、`--ipv4-group-prefix` / `--ipv6-group-prefix` で変更可能）。プレフィックスの共有は所有者・運用主体・行為者の共有を意味しません。
- ローカル ASN データセットがある場合は `--asn-dataset <PATH>` を追加すると、IP／プレフィックス表示と並べて private な ASN 集約を表示し、未解決 peer も件数で開示します。ASN は経路上のグループにすぎず、単一運用者・帰属・DoS・攻撃・悪用を示すものではありません。ASN 番号と組織名は sanitized 出力に入りません。
- `concentration` / `daily` の `--source-prefix-bits`（IPv4）／`--source-prefix-bits-v6`（IPv6）は、フォーカスとは独立したコーパス全体の接頭辞別集計を有効にします。片方の指定で両ファミリを有効にし、未指定側は `/24`／`/48` を使います。private の `source_prefixes` に要求数・記録された応答バイト数・送信元数・1送信元あたりの最大要求数・ステータス分布を出し、ローカル ASN データがあれば複数 ASN の内訳と未解決件数も併記します。使ったデータセットのパス・SHA-256・件数・明示／既定・用途は private manifest に記録します。既定の `asn-ranges.tsv` は IPv4 専用で、IPv6 も解決するには対応するローカル CSV を指定します。接頭辞の共有や ASN は、所有者・運営主体・協調・攻撃の判定ではありません。`daily` ではこの指定に `--output` が必要で、sanitized 成果物は opt-in しても変わりません。
- 同じ接頭辞別集計では、クエリを除いた `distinct_uri_paths` と `uri_paths_requested_once` も正確に数えます。既定の上限は `--max-paths-per-source-prefix` が 5,000、`--max-source-prefix-path-pairs` と `--max-source-prefix-paths` が各 10,000,000 です。省略件数と保持数を private 側に開示し、省略のあった接頭辞では1回だけのパス数を出しません。これらは巡回の形の観測であり、自動化・スクレイピング・攻撃の判定ではありません。上限・メモリ・再実行の目安は [Request concentration](docs/request-concentration.md) を参照してください。
- IP の照合では IPv4-mapped IPv6 を IPv4 として扱い、同じアドレスの表記違いを内部でまとめます。公開 bot レンジ・アドレス集合・`context`・ASN／レピュテーション・接頭辞集計・first-seen などが対象で、表示の生のキーは各機能の規約どおり保持します。first-seen はアドレスごとに1件ですが、triage の `first_seen_entities` は印の付いた生表記の行数なので異なり得ます。過去の observation store のキーは移行せず、mapped 形式だった peer の再出現履歴が新しく始まる場合があります。アドレス集合の候補 replay も mapped peer を含むログでは一致件数が増え得ます。詳細は [Temporal comparison](docs/temporal-comparison.md) と [Observation memory](docs/observation-store.md) を参照してください。
- `hunt --input <logs> --output <run-dir> --report`：ログ解析と同じ run 内の private HTML レポート生成を一度に行います。既存の hunt / concentration run は `hunt --results-dir <run-dir> --lang ja` で生ログを再解析せず再レンダリングでき、`--report <path>` で既定の `<run-dir>/report.html` を上書きできます。パス・IP の棒グラフ、分刻み時系列（集計された HTTP ステータスクラス 1xx〜5xx の5本の折れ線を含む）、hunt triage に加え、観測 CVE ごとに一致した Nuclei テンプレート ID とカタログ宣言 severity を一覧表示します。ステータスクラスの分系列は集計件数だけを含み、private な concentration artifact のみに保存して sanitized 出力へはコピーしません。この公開 CTI の ID は sanitized の CVE 集計にも決定論的な `template_ids` として保存され、顧客のリクエスト値は追加しません。CVE severity は Nuclei `info.severity`、Sigma severity 集計は Sigma `level` に由来し、Shenron による影響・悪用・侵害・悪性・帰属の判定ではありません。両方の時系列を CSS だけでホバーでき、ステータス表示では UTC の分と全クラスの件数を確認できます。テンプレート ID は公開 GitHub コード検索へのリンクですが、レポートを開くだけでは通信せず、クリック時にも公開 ID だけを送信して private 値は送りません。生のパスと IP を含む private 成果物であり、JavaScript や自動取得される外部リソースは使いません。DoS・攻撃・悪用・侵害・悪性確率・攻撃者特定の判定ではありません。詳細は [Private offline HTML report](docs/html-report.md) を参照してください。
- `compare`：2つのローカル凍結 run artifact を差分比較します。`hunt --baseline <prior-run>` では新しい hunt 後に同じ比較を出力します。CVE の差分と集計は sanitized 側、first-seen entity とパス/IP 詳細は private 側に分離されます。first-seen や elevated-volume は悪性・攻撃・侵害・攻撃者特定の判定ではありません。詳細は [Temporal comparison](docs/temporal-comparison.md) を参照してください。
- `hunt --output <DIR>`：集計のみの `triage-summary.json` と、優先順付き private `triage-view.json` も出力します。IP 等の private 値を標準出力に表示するには `--show-triage`（必要なら `--limit`）を指定します。この順序は人間が先に確認するためのトリアージであり、脅威の重大度・悪性確率ではありません。first-seen は「新規なので要確認」であって悪性の断定ではありません。
- Slack 通知は環境変数だけで opt-in できます。`SHENRON_SLACK_WEBHOOK` を成果物保存モードで設定すると、hunt 完了後に severity 別件数、CVE・KEV・Sigma、秘密ファイル 2xx、集中度、任意の baseline 差分、ローカル成果物パスからなる sanitized 集計を1件送ります。`--output` なしの stdout-only モードでは run ディレクトリが無いため Slack を明示的にスキップします。通知経路は生 IP・パス・ホスト・ヘッダー・ログ値・`private-findings.jsonl` を読み込まず送信しません。`SHENRON_SLACK_MIN_SEVERITY=info|low|medium|high|critical` を指定すると、そのカタログ severity 以上、または KEV／秘密ファイル 2xx がある run だけに絞れます。システムの `curl` が必要ですが、送信はベストエフォートであり失敗しても完了済み hunt は失敗しません。Severity は元カタログの宣言値で、攻撃・悪用・侵害・主体の判定ではありません。
- `explain`：CVE / テンプレート / リクエスト証拠の表示。既定では `response-unverified` かつ generic path の低確度ノイズを隠し、`--include-generic` で保存済みの全 finding を表示します。これは**表示フィルタのみ**で、一覧表示を変えるだけであり、トリアージのグルーピングやスコアリングには影響しません（グルーピング/スコアは常に全 finding を対象にします）。そのため、distinctive な探索1件と generic 複数件を混ぜた送信元も breadth 判定に達します。接続元・クライアント IP（`--show-source-ips`）、ローカル ASN データで解決した ASN（`--show-asn`）、JA4 フィンガープリント（`--show-fingerprints`）ごとの breadth/depth/時間窓トリアージと、観測挙動のみから算出する挙動優先度スコアを表示します。スコアは generic path の反復による深さを意図的に抑え、distinctive path の一致へ小さな寄与を与え、合計はその finding のテレメトリ・プロファイルが到達可能な最大値で正規化します（WAF 判定のない combined ログが構造的に低く出るのを防ぎます）。ただし悪性確率・攻撃成立・攻撃者特定の判定ではありません。`shenron reputation update` で準備されたローカル IP/ASN データは既定で自動参照し、明示指定のデータセットは引き続き優先します。レピュテーションは外部照会をせず、第三者の意見として示します。`--output-format json`（任意で `--output <PATH>`）を付けると、スコア・スコア内訳・トリアージ根拠・グルーピングを機械可読の `EXPLAIN_PRIVATE_TRIAGE` レポートとして出力します（テキストと同一の `--show-*` プライバシーゲートを尊重）
- 防御候補（candidate）の作成、履歴での replay、バックエンド互換性の確認
- COUNT 固定の AWS WAF JSON / Terraform ルール断片、または OSSEC 検知 XML の出力

## コマンド一覧

Shenron は**単一バイナリ**です。準備系コマンドだけが公開インテリジェンスを
ダウンロードし、それ以外はローカル解析（post-hunt Slack 通知を明示的に有効化した
場合を除きオフライン）です。

| コマンド | 用途 |
| --- | --- |
| `setup` | 公開 CTI を一括でダウンロード・凍結（Nuclei テンプレ・CISA KEV・reputation・ASN・同梱 Sigma パック・bot レンジ） |
| `nuclei update` / `kev` / `reputation update` / `bot-ranges update` | 特定の公開入力だけを個別更新 |
| `hunt` | 唯一の検知入口。Nuclei(CVE)＋Sigma を1パスで照合し、入力フィールド可用性・parse 品質・時刻カバレッジも集計表示。`--output <DIR>` で private/sanitized の全成果物、`--output` 無しなら findings を stdout のみ。`--no-nuclei` は setup 不要の Sigma のみ。`--since` / `--baseline-latest` / `--report` / `--observation-store` で運用を形作る |
| `explain` | run の private findings を 接続元/クライアント IP・ASN・JA4 単位でトリアージ（挙動優先度スコア・リクエスト列・時間窓レート） |
| `concentration` | CTI なしのリクエスト量分布。`--path` / `--path-prefix` / `--source-ip` でフォーカス |
| `rare-success` | 少数の送信元に成功ステータスが観測されたパスと、先行する探索の形を上限付きで計数。既定は集計のみで、因果関係やセキュリティ上の結論は導きません |
| `request-anomalies` | エンコードの形とリクエスト行の種類を上限付きで計測。専用の Combined 救済は他コマンドへ影響せず、攻撃・悪用・侵害を断定しません |
| `ioc` | 運用者のローカル指標を履歴ログへ照合し、上限付き private 証跡と集計だけの sanitized 出力を作成。侵害・帰属の判定ではありません |
| `probe-sources` | オフラインのパスカタログと上限付きの接続元別リクエスト形状を観測し、人手確認の条件・根拠を表示。攻撃の判定や遮断の推奨ではありません |
| `identifier-access` | 送信元ごとの ID 変化、ステータス／サイズ、先行書き込みの参照を上限付きで計数。認可の欠陥・情報開示の判定ではありません |
| `response-sizes` / `production response-sizes` | `--format nginx-postdata` を明示して送信量補正後の応答サイズと文字位置を観測。内容の復元・情報開示の判定ではありません |
| `context` | 非一致も含む指定 peer の記録を、任意の UTC 範囲で確認。件数・保持期間が既定で、個別記録は opt-in |
| `daily` | 軽量なリクエスト量・応答結果サマリ。nginx 499 と時間窓の極値を分離表示し、既定では成果物なし、監視向け JSON に対応 |
| `trend` | 明示指定した private URI パスを既存 run 成果物間で追跡（生ログの再処理なし） |
| `compare` | 2つの run ディレクトリを差分比較（first-seen・volume 上昇・新規 CVE） |
| `candidate build` / `replay` / `evaluate` / `compatibility` / `explain` / `export` | private findings から候補を作成し、履歴 replay・独立コーパス評価・互換性確認を経て、レビュー前提の **COUNT のみ** WAF ルールへ。攻撃・悪用成立の確定ではありません |
| `disposition read` / `set` | スコープ・再レビュー期限を含む、人が記録した private なレビュー状態を参照・追記 |
| `observation-store read` / `compact` | private な再観測メモリを参照し、新しいファイルへ明示的に整理。生ログの再解析・帰属の判定ではありません |
| `export` | run を sanitized な STIX 2.1 / MISP ファイルに変換（ファイル出力のみ・TLP 付き） |
| `replay` / `ablation` / `count-hypotheses` | カバレッジ・検知戦略の計測 |
| `validate-rules` | 手持ちの Sigma ルールが対応サブセットに入るか確認 |
| `generate` / `validate` / `measure` / `minimum-telemetry` | 合成コーパス・検証用ツール（開発/研究向け） |

### 使い分け

- **手早く・setup 不要・stdout に findings** → `shenron hunt --input <logs> --format <fmt> --rules <dir> --no-nuclei`
- **日次のフル hunt＋レポート＋前回差分** → `shenron hunt --input <log-dir> --since 24h --baseline-latest ./private-results --output ./private-results/hunt-<UTC> --report --lang ja`
- **ローテーションログの軽量計測** → `shenron daily --input <log-dir> --processed-index <private-index.json>`（集計は今回処理分のみ、スキップ件数を表示）
- **run を深掘り** → `shenron explain …` / `shenron concentration …`
- **防御ルールを出す** → `shenron candidate build → replay → export`
- **結果を共有** → `shenron export`（sanitized な STIX/MISP）

日次運用の手順と各ステップの理由は
[日次ハンティング runbook](docs/daily-hunting-runbook.md) にあります。

## ビルド済みバイナリ

タグ付きリリースでは、Linux（`x86_64`/`aarch64`、glibc および静的 musl）、macOS
（Intel / Apple Silicon）、Windows（`x86_64`）向けの単一 `shenron`
バイナリを [Releases](../../releases) ページで配布します。各アーカイブには
`.sha256` チェックサムが付き、ライセンスと README を同梱します。リリースを作成
するには、バージョンタグを push すると `Release` ワークフローがビルドして成果物を
添付します:

```bash
git tag v0.1.0
git push origin v0.1.0
```

ソースからのビルドには stable の Rust ツールチェインが必要です。リリースビルドは
`cargo build --release --bin shenron` です。

## クイックスタート

```bash
cargo run --bin shenron -- hunt \
  --input ./tests/fixtures/aws-waf/ \
  --rules ./tests/fixtures/rules/ \
  --no-nuclei
```

`hunt` が検出の唯一の入口です。`--output` を省略すると、生の IP・パス・ホスト・リクエスト証跡を含み得る private findings だけを JSONL で標準出力へ出し、要約と警告は標準エラーへ出します。このモードではファイルを作りません。CSV は `--output-format csv > findings.csv` で保存できます。`--no-nuclei` なら setup 不要の Sigma-only、`--no-sigma` なら Nuclei-only で動作し、両方を同時に無効化することはできません。Sigma ルールの対応状況を確認する `validate-rules` は引き続き利用できます。

```bash
cargo run --bin shenron -- validate-rules --rules ./rules/
```

## Production hunt（本番ログのハンティング）

公開 Nuclei テンプレート、CISA KEV、IP レピュテーション、ASN、公開クローラーレンジを一度準備すれば、安全に識別できるログは入力だけで hunt を実行できます。**最小構成は次の2コマンドだけ**で、format・rules・output の指定は不要です。

```bash
shenron setup
shenron hunt --input ./waf-logs
```

`setup` が既定のデータディレクトリを用意し、`hunt` はそこから Nuclei・KEV・同梱 Sigma パック・bot-range を自動で参照します。AWS WAF JSON は自動判別されるため `--format` は不要です。`--output` を省略すると、生の IP・パス・ホスト・リクエスト証跡を含み得る private findings を JSONL で標準出力へ流し、要約（入力フィールド可用性・解析品質・時刻カバレッジを含む）は標準エラーへ出します。標準出力のストリームは保護された場所にだけリダイレクトしてください。

`--output` を付けると full run artifacts（private + sanitized）を保存し、`--report`・`--baseline-latest`・Slack 通知も有効になります。

```bash
shenron hunt --input ./waf-logs --output ./private-results/hunt-20260905T000000Z
```

追記・ローテーションされるログの日次運用では、`--input` にログディレクトリを指定し、
ソート可能な明示的 `--output` run ディレクトリ、`--since 24h`、
`--baseline-latest ./private-results` を組み合わせられます。
Shenron はディレクトリツリーと gzip ローテーションを読み、解決した移動窓の境界を記録し、
ソート可能なディレクトリ名から直近の有効 run を選びます。窓自体の厳密な再現が必要な場合は
`--from/--to` を明示してください。

ログ入力コマンドの既定は `--format auto` です。AWS WAF JSON、ALB、ヘッダー付きレガシー CloudFront と vhost 前置き Apache Combined は自動識別します。標準 nginx Combined と標準 Apache Combined は構造が同一で安全に区別できないため、その場合だけ `--format nginx` または `--format apache` を指定してください。`--format apache` は標準行と vhost 前置き行の両方を受け付け、`--format apache-vhost` は vhost 前置きを厳格に要求します。

`setup` は `SHENRON_DATA_DIR` があればその配下、なければ `$XDG_DATA_HOME/shenron`、さらに無ければ `~/.local/share/shenron` に `nuclei-templates/`、凍結済みの `nuclei-report.json`、CISA KEV の `known_exploited_vulnerabilities.json`、凍結結合結果の `kev-report.json`、provenance を持つ `kev-manifest.json`、任意の `reputation.jsonl`、`asn-ranges.tsv`、`bot-ranges.json` を保存します。`hunt`、`ablation`、`replay`、`count-hypotheses` は既定でこの場所を参照します。`hunt --output <DIR>` は従来どおり full run artifacts をそのディレクトリへ保存します。`--output` を省略すると run ディレクトリやファイルは作らず、private findings だけを標準出力へ出します（`--output-format jsonl|csv`）。`--report`、`--baseline`、`--baseline-latest`、`--observation-store` は `--output` が必須です。従来どおり `--nuclei-templates`、`--nuclei-report`、`--kev-report` で明示指定もできます。`--kev-report` 省略時は準備済みの既定レポートがあれば参照し、無ければ空集合として扱います。`setup --skip-kev` で KEV 準備だけを省略できます。

個別の公開入力だけを更新したい場合は、従来どおり `shenron nuclei update`、`shenron reputation update`、`shenron bot-ranges update` も使えます。`setup` が取得するのは公開インテリジェンスだけで、顧客データを送信しません。

レピュテーション／ASN の各公開ソースは独立に取得を試みます。一部が失敗しても取得・変換できたレコードは保持し、失敗したソースと理由を `reputation-manifest.json` に記録したうえで非ゼロ終了します。

凍結済み bot-range snapshot がある場合、hunt は自己申告された bot User-Agent と運営者の公開レンジをオフライン照合し、レンジ内外の集計を sanitized 出力へ、レンジ外の観測 peer IP を private `bot-range-observations.json` へ保存します。snapshot が無ければ注記してスキップし、CVE/Sigma 指標は変えません。レンジ外という観測は、レンジの古さ・欠落、中継、自由に設定できる User-Agent の影響を受けるため、なりすまし・攻撃・悪用・帰属の判定ではありません。詳細は [Published bot ranges](docs/published-bot-ranges.md) を参照してください。

`hunt` は CVE 主体の Nuclei パスに加えて、汎用的な **Sigma** 検出パスを**既定で ON**にして同一ストリームで実行します。CVE テンプレートに対応しない汎用 TTP（例：`.env` などの機密ファイル探索）を拾えます。ルールは `--rules <DIR>` か準備済みの `<data-dir>/sigma-rules` から読み込み、`--no-sigma` で無効化できます。`shenron setup` が Shenron 対応の同梱パックをそこへ配置するので、追加設定なしで動きます。さらに `setup --sigma-source <git-url>` で外部ソース（例：SigmaHQ）の `rules/web` も取得できます。Sigma の finding は `source` フィールドを持ち、CVE 指標とは別に集計されます。`candidate build` では既定で除外され、明示的な `--include-sigma-ttp --rules <DIR>` の場合だけ、忠実に変換できるルール由来リテラルから CVE 候補とは別の replay 必須クラスを生成します。CVE の証拠ではなく、出力は引き続き COUNT のみです。詳細は [Sigma detection inside hunt](docs/sigma-in-hunt.md) を参照。

同梱 Sigma パックは秘密／設定ファイル、バージョン管理、管理／actuator エンドポイントに加え、AI 開発ツールの設定パスも対象に含みます。いずれも要求パスへの一致であり、ファイルの存在・内容の取得・侵害を確定するものではありません。

Nuclei の変換可否は共通の汎用パス判定に揃えられています。既存の凍結レポートへ反映するには `shenron nuclei update` を再実行してください。traversal の形やクエリ／ヘッダー条件は引き続き取り込み対象になり得ます。検知可能性は攻撃・悪用・脆弱な製品の存在の判定ではありません。詳細は [Nuclei detectability](docs/nuclei-detectability.md) を参照してください。

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

- [IOC observations](docs/ioc.md)

- [ケーススタディ（4データセットの実証）](docs/case-study.md)
- [Production hunting](docs/production-hunting.md)
- [Telemetry capabilities](docs/telemetry-capabilities.md)
- [Investigation workflow](docs/investigation-workflow.md)
- [Threat-hunting workflow](docs/threat-hunting-workflow.md)
- [Daily-hunting runbook](docs/daily-hunting-runbook.md)
- [Analyst dispositions](docs/analyst-dispositions.md)
- [Request spelling observations](docs/request-anomalies.md)
- [Rare response-status patterns](docs/rare-success.md)
- [Probe-source request shapes](docs/probe-sources.md)
- [Identifier-access observations](docs/identifier-access.md)
- [Response-size observations](docs/response-sizes.md)
- [Request concentration](docs/request-concentration.md)
- [Temporal comparison](docs/temporal-comparison.md)
- [Observation memory](docs/observation-store.md)
- [Request sequences](docs/request-sequences.md)
- [Private offline HTML report](docs/html-report.md)
- [Declared/observed consistency](docs/declared-observed-consistency.md)
- [Published bot ranges](docs/published-bot-ranges.md)
- [CTI export](docs/cti-export.md)
- [Nuclei detectability](docs/nuclei-detectability.md)
- [Nuclei test generation](docs/nuclei-test-generation.md)
- [Sigma support](docs/sigma-support.md)
- [Sigma detection inside hunt](docs/sigma-in-hunt.md)
- [Validation](docs/validation.md)
- [Synthetic corpus](docs/synthetic-corpus.md)
- [Architecture](docs/architecture.md)
- [KEV coverage](docs/kev-coverage.md)
- [Minimum telemetry](docs/minimum-telemetry.md)
- [AWS WAF schema](docs/aws-waf-schema.md)
- [Detection-strategy ablation](docs/ablation.md)
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
