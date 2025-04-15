import requests
import yaml
import pandas as pd
from collections import defaultdict

def load_rules_from_urls(urls):
    all_rules = []
    for url in urls:
        raw_url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        response = requests.get(raw_url)
        response.raise_for_status()
        data = yaml.safe_load(response.text)
        rules = [item for item in data if 'rule' in item]
        all_rules.extend(rules)
    return all_rules

def rules_to_dataframe(rules):
    tag_counter = defaultdict(int)
    table_data = []

    for rule in rules:
        tags = rule.get("tags", [])
        for tag in tags:
            tag_counter[tag] += 1
        table_data.append({
            "Rule": rule.get("rule"),
            "Description": rule.get("desc", ""),
            "Tags": ", ".join(tags),
            "Source": rule.get("source", ""),
            "Priority": rule.get("priority", ""),
        })

    df_rules = pd.DataFrame(table_data)
    df_tags = pd.DataFrame([{"Tag": k, "Count": v} for k, v in tag_counter.items()])
    return df_rules, df_tags

def generate_html_file(df_rules, df_tags, filename, with_stats=True):
    rules_html = df_rules.to_html(index=False, escape=False, classes="display", table_id="falcoTable")
    tags_html = df_tags.to_html(index=False, escape=False, classes="display", table_id="tagTable") if with_stats else ""

    full_html = f"""
    <html>
    <head>
      <title>Falco Rules Viewer</title>
      <link rel="stylesheet" type="text/css"
        href="https://cdn.datatables.net/1.13.4/css/jquery.dataTables.css">
      <script type="text/javascript"
        src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
      <script type="text/javascript"
        src="https://cdn.datatables.net/1.13.4/js/jquery.dataTables.min.js"></script>
      <script>
        $(document).ready(function() {{
            $('#falcoTable').DataTable({{
                "pageLength": 20
            }});
            {'$("#tagTable").DataTable({"pageLength": 10});' if with_stats else ""}
        }});
      </script>
    </head>
    <body>
      <h2>📋 Falco Rules Viewer</h2>
      {'<h3>📊 Tag Statistics</h3>' + tags_html if with_stats else ""}
      <h3>🔎 Falco Rules</h3>
      {rules_html}
    </body>
    </html>
    """

    with open(filename, "w") as f:
        f.write(full_html)
    print(f"✅ Generato: {filename}")

# --- URLS delle rule ---
url_main = "https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml"
url_sandbox = "https://github.com/falcosecurity/rules/blob/main/rules/falco-sandbox_rules.yaml"
url_incubating = "https://github.com/falcosecurity/rules/blob/main/rules/falco-incubating_rules.yaml"

# --- Solo regole principali ---
main_rules = load_rules_from_urls([url_main])
df_main, tags_main = rules_to_dataframe(main_rules)

generate_html_file(df_main, tags_main, "falco_rules_with_stats.html", with_stats=True)
generate_html_file(df_main, tags_main, "falco_rules.html", with_stats=False)

# --- Tutte le regole combinate ---
all_rules = load_rules_from_urls([url_main, url_sandbox, url_incubating])
df_all, tags_all = rules_to_dataframe(all_rules)

generate_html_file(df_all, tags_all, "falco_rules_complete_with_stats.html", with_stats=True)
generate_html_file(df_all, tags_all, "falco_rules_complete.html", with_stats=False)

