import os
import requests
import yaml
from collections import defaultdict

GITHUB_API_BASE = "https://api.github.com/repos/cilium/tetragon/contents/examples/"
RAW_BASE = "https://raw.githubusercontent.com/cilium/tetragon/main/examples/"
TARGET_PATHS = ["policylibrary", "tracingpolicy"]

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

HEADERS = {
    "Accept": "application/vnd.github.v3+json",
}
if GITHUB_TOKEN:
    HEADERS["Authorization"] = f"token {GITHUB_TOKEN}"

def get_yaml_files_from_github(path):
    """
    Scarica ricorsivamente tutti i file YAML dal repository GitHub a partire dal percorso dato.
    """
    file_urls = []

    def _crawl(current_path):
        url = f"{GITHUB_API_BASE}{current_path}"
        response = requests.get(url, headers=HEADERS)
        if response.status_code != 200:
            print(f"⚠️ Errore nell'accesso a {url}")
            return

        items = response.json()
        for item in items:
            if item["type"] == "file" and item["name"].endswith(".yaml"):
                raw_url = RAW_BASE + item["path"].replace("examples/", "")
                file_urls.append(raw_url)
            elif item["type"] == "dir":
                _crawl(item["path"].replace("examples/", ""))

    _crawl(path)
    return file_urls

def parse_kprobes(yaml_url):
    try:
        response = requests.get(yaml_url)
        data = yaml.safe_load(response.text)
    except Exception as e:
        print(f"⚠️ Errore parsing {yaml_url}: {e}")
        return []

    if not data or "spec" not in data or "kprobes" not in data["spec"]:
        return []

    entries = []
    for probe in data["spec"]["kprobes"]:
        entries.append({
            "Call": probe.get("call", ""),
            "Syscall": probe.get("syscall", ""),
            "Return": probe.get("return", ""),
            "Args": str(probe.get("args", [])),
            "ReturnArg": str(probe.get("returnArg", "")),
            "Selectors": str(probe.get("selectors", [])),
            "SourceFile": os.path.basename(yaml_url)
        })
    return entries

def rules_to_dataframe(rules):
    call_counter = defaultdict(int)
    table_data = []

    for rule in rules:
        call_counter[rule.get("Call", "")] += 1
        table_data.append(rule)

    return table_data, call_counter

def generate_html_file(entries, call_counter, filename, with_stats=True):
    rules_html = "\n".join(
        f"<tr><td>{e['Call']}</td><td>{e['Syscall']}</td><td>{e['Return']}</td>"
        f"<td>{e['Args']}</td><td>{e['ReturnArg']}</td><td>{e['Selectors']}</td>"
        f"<td>{e['SourceFile']}</td></tr>"
        for e in entries
    )
    calls_html = "\n".join(
        f"<tr><td>{call}</td><td>{count}</td></tr>" for call, count in call_counter.items()
    ) if with_stats else ""

    full_html = f"""<html>
    <head>
      <title>Tetragon Rules Viewer</title>
      <link rel="stylesheet" href="https://cdn.datatables.net/1.13.4/css/jquery.dataTables.css">
      <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
      <script src="https://cdn.datatables.net/1.13.4/js/jquery.dataTables.min.js"></script>
      <script>
        $(document).ready(function() {{
            $('#rulesTable').DataTable({{ "pageLength": 20 }});
            {'$("#callsTable").DataTable({pageLength: 10});' if with_stats else ""}
        }});
      </script>
    </head>
    <body>
      <h2>📋 Tetragon Rules Viewer</h2>
      {f'<h3>📊 Call Statistics</h3><table id="callsTable"><thead><tr><th>Call</th><th>Count</th></tr></thead><tbody>{calls_html}</tbody></table>' if with_stats else ""}
      <h3>🔎 Tetragon Rules</h3>
      <table id="rulesTable" class="display">
        <thead><tr>
            <th>Call</th><th>Syscall</th><th>Return</th><th>Args</th>
            <th>ReturnArg</th><th>Selectors</th><th>SourceFile</th>
        </tr></thead>
        <tbody>{rules_html}</tbody>
      </table>
    </body>
    </html>"""

    with open(filename, "w") as f:
        f.write(full_html)
    print(f"✅ Generato: {filename}")

# --- MAIN ---
all_rules = []
for path in TARGET_PATHS:
    print(f"🔍 Scanning: {path}")
    yaml_files = get_yaml_files_from_github(path)
    for file_url in yaml_files:
        print(f"📄 Parsing: {file_url}")
        entries = parse_kprobes(file_url)
        all_rules.extend(entries)

entries, call_counter = rules_to_dataframe(all_rules)
generate_html_file(entries, call_counter, "tetragon_rules_with_stats.html", with_stats=True)
generate_html_file(entries, call_counter, "tetragon_rules.html", with_stats=False)

print("✅ Completato!")

