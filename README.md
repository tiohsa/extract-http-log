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
- `python3 test-server.py`

2) 別ターミナルでテストトラフィック送信
- 例: `curl -sS -H 'Content-Type: application/json' -d '{"user":"alice","password":"p@ss"}' http://localhost:8080/api/orders`
- または `bash send-to-test-server.sh`（存在する場合）

3) キャプチャとログ生成（ワンコマンド）
- `bash start_tcpdump.sh -i lo -p 8080 -o http_capture.pcap -a access.log`
  - Ctrl-Cで停止、または `-t <秒>` で自動停止
  - 実行後、`access.log` にアクセスログが生成されます

4) 既存のPCAPから直接ログを生成（キャプチャ済みの場合）
- `python3 extract_http_log.py -i http_capture.pcap -o access.log --decode-port 8080 --no-ct-filter`


## 使用例

```bash
python3 test-server.py
sudo ./start_tcpdump.sh -i lo -p 8080
bash send-to-test-server.sh  -p 8080 -c 4
python3 extract_http_log.py -i http_capture.pcap -o ./output/req_res.log --decode-port 8080
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
- `start_tcpdump.sh`
  - `-i` インタフェース（例: `lo`）
  - `-p` ポート（例: `8080`）
  - `-t` 秒数（任意。指定しない場合はCtrl-Cで停止）
  - `-o` 出力PCAPパス（例: `http_capture.pcap`）
  - `-a` アクセスログ出力（例: `access.log`）
  - 注意: 環境によっては `tcpdump` に `sudo` が必要です。

- 直接抽出
  - リクエスト+レスポンスを1行にまとめたApache拡張ログを出力:
    - `python3 extract_http_log.py -i input.pcap -o access.log --decode-port 8080`
  - レスポンスのみのログ（参考。STATUS/METHOD/URLと本文を単一行JSONで出力）:
    - `python3 extract_http_responses.py -i input.pcap -o responses.log --decode-port 8080`

## テストサーバ
- `python3 test-server.py` で `0.0.0.0:8080` に起動。
- `POST /api/orders` はランダムなステータス（200/201/400/401/500）とJSON本文を返します。

## 運用上の注意
- PCAPにPIIなどの秘匿情報が含まれないよう配慮してください。
- TLS（HTTPS）は対象外です。平文HTTPを `--decode-port` で指定してデコードします。
- 大きなPCAPでは `tshark` の処理に時間がかかります。必要に応じてフィルタを活用してください。

## トラブルシュート
- `tshark` が見つからない: パッケージマネージャでインストールしてください。
- ログのMETHOD/URLが `-` になる: レスポンス側からは取得できない場合があります。`extract_http_log.py` の出力（Apache拡張）が推奨です。
- 期待するポートがHTTPと認識されない: `--decode-port <port>` を付けてください。
