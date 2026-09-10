
from flask import Flask, render_template, jsonify, request
from analyzer import analyze_traffic, analyze_pcap
import os

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze")
def analyze():

    try:

        print("Starting sample traffic analysis...")

        results = analyze_traffic(20)

        alerts = sum(
            1 for packet in results
            if packet.get("alert", False)
        )

        print(
            f"Analysis completed. "
            f"Packets found: {len(results)}"
        )

        print(f"Security alerts: {alerts}")

        return jsonify({
            "success": True,
            "packets": results,
            "total": len(results),
            "alerts": alerts
        })

    except Exception as error:

        print("ERROR:", error)

        return jsonify({
            "success": False,
            "error": str(error)
        }), 500


@app.route("/upload", methods=["POST"])
def upload_file():

    try:

        if "file" not in request.files:

            return jsonify({
                "success": False,
                "error": "No file uploaded."
            }), 400

        file = request.files["file"]

        if file.filename == "":

            return jsonify({
                "success": False,
                "error": "No file selected."
            }), 400

        if not file.filename.lower().endswith(
            (".pcap", ".pcapng")
        ):

            return jsonify({
                "success": False,
                "error": (
                    "Only PCAP and PCAPNG files "
                    "are supported."
                )
            }), 400

        file_path = os.path.join(
            app.config["UPLOAD_FOLDER"],
            file.filename
        )

        file.save(file_path)

        print(
            f"PCAP file uploaded: {file.filename}"
        )

        results = analyze_pcap(file_path)

        alerts = sum(
            1 for packet in results
            if packet.get("alert", False)
        )

        print(
            f"PCAP analysis completed. "
            f"Packets found: {len(results)}"
        )

        print(f"Security alerts: {alerts}")

        return jsonify({
            "success": True,
            "filename": file.filename,
            "packets": results,
            "total": len(results),
            "alerts": alerts,
            "message": "PCAP analyzed successfully."
        })

    except Exception as error:

        print("PCAP ERROR:", error)

        return jsonify({
            "success": False,
            "error": str(error)
        }), 500


if __name__ == "__main__":
    app.run(debug=True)

