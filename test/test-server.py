"""
簡易テスト用のHTTPサーバー（Flask）

目的:
- ローカルでHTTPトラフィックを生成し、pcapキャプチャや抽出スクリプトの検証に使う。

エンドポイント:
- POST /api/orders
  - リクエスト: JSON（例: {"user": "alice", "password": "p@ss"}）
  - レスポンス: 事前定義の候補からランダムで選択（200/201/400/401/500）
  - 用途: さまざまなステータスや本文を意図的に混在させ、ログ/抽出の網羅性を確認する。

起動方法:
- python3 test-server.py  # 既定で0.0.0.0:8080で起動
  - 8080以外のポートを使う場合は `app.run(port=XXXX)` を変更。
  - systemdやDocker等の常駐化は不要（手動起動で十分）。

注意:
- このサーバーは学習/検証用途であり、本番用途を想定していない。
- レスポンスはランダムのため、同一入力でも結果が変わる。
"""

from flask import Flask, request, jsonify
import random

app = Flask(__name__)

@app.route("/api/orders", methods=["POST"])
def orders():
    # JSONボディを取得する。Content-Typeが不正でも強制的にJSON解釈を試みる
    # （テスト用途のため厳密なバリデーションは行わない）
    try:
        data = request.get_json(force=True)  # JSONリクエストを取得
    except Exception:
        return jsonify({"error": "invalid json"}), 400

    # レスポンス候補（ステータスコード, JSON本文）
    responses = [
        (200, {"result": "ok", "id": random.randint(1000, 9999)}),
        (201, {"result": "created", "order_id": random.randint(1000, 9999)}),
        (400, {"error": "bad request"}),
        (401, {"error": "unauthorized"}),
        (500, {"error": "internal server error"}),
    ]

    # 1件ランダムに選択して返却（テストの多様性を担保）
    status, body = random.choice(responses)
    return jsonify(body), status

if __name__ == "__main__":
    # ポート80で受けたい場合はroot権限が必要。通常はポート5000/8080で実行推奨
    app.run(host="0.0.0.0", port=8080)
