import requests
import yaml
import pandas as pd
from collections import defaultdict

def get_yaml_file_urls():
    api_url = "https://api.github.com/repos/CloudDefenseAI/falco_extended_rules/contents/rules"
    response = requests.get(api_url)
    response.raise_for_status()
    contents = response.json()
    yaml_files = [item['download_url'] for item in contents if item['name'].endswith('.yaml')]
    return yaml_files

def load_rules_from_urls(urls):
    all_rules = []
    for url in urls:
        response = requests.get(url)
        response.raise_for_status()
        data = yaml.safe_load(response.text)
        if isinstance(data, list):
            rules = [item for item in data if isinstance(item, dict) and 'rule' in item]
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

def generate_html_file(df_rules, df_tags, filename):
    rules_html = df_rules.to_html(index=False, escape=False, classes="display", table_id="falcoTable")
    tags_html = df_tags.to_html(index=False, escape=False, classes="display", table_id="tagTable")

    full_html = f"""
    <html>
    <head>
      <title>Falco Extended Rules Viewer</title>
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
            $('#tagTable').DataTable({{
                "pageLength": 10
            }});
        }});
      </script>
    </head>
    <body>
      <h2>📋 Falco Extended Rules Viewer</h2>
      <h3>📊 Tag Statistics</h3>
      {tags_html}
      <h3>🔎 Falco Rules</h3>
      {rules_html}
    </body>
    </html>
    """

    with open(filename, "w") as f:
        f.write(full_html)
    print(f"✅ Generato: {filename}")

if __name__ == "__main__":
    yaml_urls = get_yaml_file_urls()
    rules = load_rules_from_urls(yaml_urls)
    df_rules, df_tags = rules_to_dataframe(rules)
    generate_html_file(df_rules, df_tags, "falco_extended_rules_with_stats.html")

