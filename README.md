# HTTP Capture and Log Tools

本リポジトリは、ローカル/既存のPCAPからHTTPのリクエスト/レスポンスを抽出し、
Apache Combined形式に近いアクセスログ（拡張付き）を生成するためのツール群です。
テスト用のFlaskサーバーも同梱しています。

## 依存関係
- Python 3.8+
- tshark（Wireshark CLI）
- tcpdump（パケットキャプチャ用）
- Flask（テストサーバ用）、curl（トラフィック生成用）

インストール例（Ubuntu/Debian）:
- `sudo apt-get install -y tcpdump tshark`
- `python3 -m pip install flask`

## クイックスタート
1) テストサーバ起動（デフォルト: `:8080`）
- `python3 test/test-server.py`

2) 別ターミナルでテストトラフィック送信
- 例: `curl -sS -H 'Content-Type: application/json' -d '{"user":"alice","password":"p@ss"}' http://localhost:8080/api/orders`
- または `bash test/send-to-test-server.sh`

3) キャプチャコマンドを作成（実行は手動）
- `./start_tcpdump.sh -i lo -p 8080 -o http_capture.pcap`
  - スクリプトは tcpdump コマンドを表示するだけで実行しません。必要に応じて `sudo` を付けて表示されたコマンドを手動で実行してください。
  - 直接実行する場合の例: `sudo tcpdump -i lo -s 0 -U -w http_capture.pcap port 8080`

4) アクセスログを生成
- 単一PCAP: `python3 extract_http_log.py -i http_capture.pcap -o access.log --decode-port 8080 --no-ct-filter`
- ローテーションしたPCAPをまとめて変換:
  - `for f in http_capture-*.pcap; do python3 extract_http_log.py -i "$f" -o - --decode-port 8080 --no-ct-filter >> access.log; done`


## 使用例

```bash
python3 test/test-server.py
./start_tcpdump.sh -i lo -p 8080 -C 5 -W 3 -o http_capture.pcap   # コマンドのみ表示
sudo tcpdump -i lo -s 0 -U -C 5 -W 3 -w http_capture.pcap port 8080
bash test/send-to-test-server.sh  -p 8080 -c 4
python3 extract_http_log.py -i http_capture.pcap -o ./output/access.log --decode-port 8080
```

## ログフォーマット
`extract_http_log.py` は、Apache Combined形式に送受IP:PortとボディJSON（リクエスト/レスポンス）を付与した行を出力します。

- 形式:
  - `%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i" src_ip:src_port dst_ip:dst_port <REQ_JSON> <RES_JSON>`
- 例:
  - `127.0.0.1 - - [31/Aug/2025:01:27:15 +0000] "POST /api/orders HTTP/1.1" 201 37 "-" "curl/8.5.0" 127.0.0.1:43286 127.0.0.1:8080 {"user":"alice","password":"******"} {"order_id":7441,"result":"created"}`

補足:
- %>s は対応レスポンスのステータス。%b は `Content-Length` 優先、なければ本文から推定。
- `<REQ_JSON>` と `<RES_JSON>` は単一行JSON。本文がJSONでない場合はJSON文字列として出力。
- `password`/`token` 等の秘匿キーは自動マスクされます（`MASK_KEYS` 参照）。
- ペアリングは `tcp.stream` 単位でFIFO。非標準ポートは `--decode-port <port>` を指定してください。

## スクリプトの使い方
- `start_tcpdump.sh`（キャプチャコマンドの表示のみ）
  - 目的: 指定IF/ポートのHTTPトラフィックを保存するための `tcpdump` コマンドを生成して表示します。
  - 主なオプション:
    - `-i` インタフェース（例: `lo`。デフォルト: `lo`）
    - `-p` ポート（例: `8080`。デフォルト: `8080`）
    - `-o` 出力PCAPパス（例: `http_capture.pcap`。デフォルト: `http_capture.pcap`）
    - ローテーション（tcpdump 連携）: `-C <MB>` サイズ、`-G <秒>` 時間、`-W <世代数>` 世代管理
      - `-G` 指定で `-o` に時刻パターン（%Y 等）が無い場合、自動で `name-%Y%m%d-%H%M%S.ext` を提示
  - 動作:
    - スクリプトはコマンドを「表示するだけ」で実行しません。必要に応じて `sudo` を付け、表示されたコマンドを手動で実行してください。
  - 注意: 環境によっては `tcpdump` に `sudo` が必要です。

- 直接抽出
  - リクエスト+レスポンスを1行にまとめたApache拡張ログを出力:
    - `python3 extract_http_log.py -i input.pcap -o access.log --decode-port 8080`

## テストサーバ
- `python3 test/test-server.py` で `0.0.0.0:8080` に起動。
- `POST /api/orders` はランダムなステータス（200/201/400/401/500）とJSON本文を返します。

## 運用上の注意
- PCAPにPIIなどの秘匿情報が含まれないよう配慮してください。
- TLS（HTTPS）は対象外です。平文HTTPを `--decode-port` で指定してデコードします。
- 大きなPCAPでは `tshark` の処理に時間がかかります。必要に応じてフィルタを活用してください。

## トラブルシュート
- `tshark` が見つからない: パッケージマネージャでインストールしてください。
- ログのMETHOD/URLが `-` になる: レスポンス側からは取得できない場合があります。`extract_http_log.py` の出力（Apache拡張）を使用してください。
- 期待するポートがHTTPと認識されない: `--decode-port <port>` を付けてください。
