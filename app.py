from flask import Flask, render_template, request
import csv
import json
import os

app = Flask(__name__)

UPLOAD_FOLDER = "."
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload():

    file = request.files["sbom_file"]

    if file.filename == "":
        return "No file selected"

    filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
    file.save(filepath)

    # -----------------------
    # Load JSON Files
    # -----------------------

    with open("applications.json", "r") as f:
        applications = json.load(f)

    with open("vulnerability_db.json", "r") as f:
        vulnerability_db = json.load(f)

    with open("license_rules.json", "r") as f:
        license_rules = json.load(f)

    with open("transitive_dependencies.json", "r") as f:
        transitive = json.load(f)

    libraries = []

    total = 0
    critical = 0
    outdated = 0
    license_conflict = 0
    safe = 0

    # -----------------------
    # Read SBOM CSV
    # -----------------------

    with open(filepath, newline="", encoding="utf-8") as csvfile:

        reader = csv.DictReader(csvfile)

        for row in reader:

            total += 1

            risk = "Safe"

            # -----------------------
            # Vulnerability Check
            # -----------------------

            for vuln in vulnerability_db:

                if row["library"].lower() == vuln["library"].lower():

                    if row["version"] in vuln["affected_versions"]:

                        risk = "Critical"

                        break

            # -----------------------
            # License Check
            # -----------------------

            if risk == "Safe":

                for rule in license_rules:

                    if row["license"] == rule["license"]:

                        if rule["compatible_with_proprietary"] == False:

                            risk = "License Conflict"

                        break

            # -----------------------
            # Outdated Check
            # -----------------------

            if risk == "Safe":

                try:

                    year = int(row["last_updated"][:4])

                    if year < 2023:

                        risk = "Outdated"

                except:

                    pass

            # -----------------------
            # Count Risks
            # -----------------------

            if risk == "Critical":
                critical += 1

            elif risk == "License Conflict":
                license_conflict += 1

            elif risk == "Outdated":
                outdated += 1

            else:
                safe += 1

            row["Risk"] = risk

            libraries.append(row)

    overall_score = 100 - (
        critical * 30 +
        license_conflict * 20 +
        outdated * 10
    )

    if overall_score < 0:
        overall_score = 0

    return render_template(
        "report.html",
        libraries=libraries,
        total=total,
        critical=critical,
        outdated=outdated,
        license_conflict=license_conflict,
        safe=safe,
        score=overall_score
    )


if __name__ == "__main__":
    app.run(debug=True)