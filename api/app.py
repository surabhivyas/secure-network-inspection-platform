from flask import Flask, jsonify
import subprocess
import json

app = Flask(__name__)

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok"
    })

@app.route("/run-inspection", methods=["POST"])
def run_inspection():

    result = subprocess.run(
        ["./src/inspection_engine"],
        capture_output=True,
        text=True
    )

    with open("./inspection_results.json", "r") as f:
        results = json.load(f)
    return jsonify(results)

if __name__ == "__main__":
    app.run(debug=True, port=5000)
