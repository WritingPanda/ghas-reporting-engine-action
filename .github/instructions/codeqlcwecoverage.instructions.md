# CodeQL CWE Coverage

Source: https://codeql.github.com/codeql-query-help/full-cwe/ (extracted snapshot)

The full dataset (4,766 rows) is stored as a CSV for easier consumption and diffing:

`codeql_cwe_coverage.csv`

Columns:
- CWE
- Language
- Query id
- Query name

Sample (first 10 rows):

| **CWE** | **Language** | **Query id** | **Query name** |
| --- | --- | --- | --- |
| CWE-11 | C# | cs/web/debug-binary | Creating an ASP.NET debug binary may reveal sensitive information |
| CWE-12 | C# | cs/web/missing-global-error-handler | Missing global error handler |
| CWE-13 | C# | cs/password-in-configuration | Password in configuration file |
| CWE-14 | C/C++ | cpp/memset-may-be-deleted | Call tomemsetmay be deleted |
| CWE-20 | GitHub Actions | actions/composite-action-sinks | Composite Action Sinks |
| CWE-20 | GitHub Actions | actions/composite-action-sources | Composite Action Sources |
| CWE-20 | GitHub Actions | actions/composite-action-summaries | Composite Action Summaries |
| CWE-20 | GitHub Actions | actions/reusable-workflow-sinks | Reusable Workflow Sinks |
| CWE-20 | GitHub Actions | actions/reusable-workflow-sources | Reusable Workflow Sources |
| CWE-20 | GitHub Actions | actions/reusable-workflow-summaries | Reusable Workflows Summaries |

For analysis you can load the CSV (example Python/Pandas):

```python
import pandas as pd
df = pd.read_csv('.github/instructions/codeql_cwe_coverage.csv')
print(df.head())
```

## Per-language counts

| Language | Query rows |
| --- | ---: |
| Java/Kotlin | 1162 |
| JavaScript/TypeScript | 852 |
| C/C++ | 804 |
| C# | 511 |
| Python | 452 |
| Ruby | 308 |
| Go | 298 |
| Swift | 153 |
| GitHub Actions | 141 |
| Rust | 85 |
| **Total** | **4766** |

## Regeneration script

Script to (re)fetch the CodeQL CWE coverage page, parse the table, update the CSV, and refresh the language counts in this markdown. Requires Python 3 and `beautifulsoup4`.

Save as `scripts/update_codeql_cwe_coverage.py` (create folder if needed):

```python
#!/usr/bin/env python3
import requests, csv, re, sys, collections, pathlib
from bs4 import BeautifulSoup

URL = "https://codeql.github.com/codeql-query-help/full-cwe/"
CSV_PATH = pathlib.Path('.github/instructions/codeql_cwe_coverage.csv')
MD_PATH = pathlib.Path('.github/instructions/codeqlcwecoverage.instructions.md')

def fetch_html(url: str) -> str:
	r = requests.get(url, timeout=60)
	r.raise_for_status()
	return r.text

def parse_rows(html: str):
	soup = BeautifulSoup(html, 'html.parser')
	table = soup.find('table')
	if not table:
		raise SystemExit('Could not locate table in HTML.')
	header = [th.get_text(strip=True) for th in table.find('tr').find_all('th')]
	# Normalize header names exactly as we use them
	mapping = {h:i for i,h in enumerate(header)}
	out_rows = []
	for tr in table.find_all('tr')[1:]:
		tds = tr.find_all(['td','th'])
		if len(tds) < 4:
			continue
		vals = [td.get_text(separator=' ', strip=True) for td in tds]
		# Expected order: CWE, Language, Query id, Query name
		row = [vals[mapping.get('CWE',0)],
			   vals[mapping.get('Language',1)],
			   vals[mapping.get('Query id',2)],
			   vals[mapping.get('Query name',3)]]
		out_rows.append(row)
	return out_rows

def write_csv(rows):
	CSV_PATH.parent.mkdir(parents=True, exist_ok=True)
	with CSV_PATH.open('w', newline='', encoding='utf-8') as f:
		w = csv.writer(f)
		w.writerow(['CWE','Language','Query id','Query name'])
		w.writerows(rows)

def summarize(rows):
	c = collections.Counter(r[1] for r in rows)
	return c

def update_markdown(counter):
	if not MD_PATH.exists():
		print('Markdown file not found, skipping update of counts.', file=sys.stderr)
		return
	text = MD_PATH.read_text(encoding='utf-8')
	# Replace counts table between markers (add markers if not present)
	start_marker = '## Per-language counts\n\n| Language | Query rows |'
	if start_marker not in text:
		print('Counts section not found; leave markdown as-is.', file=sys.stderr)
		return
	# Build new table
	lines = ["| Language | Query rows |","| --- | ---: |"]
	for lang,count in counter.most_common():
		lines.append(f"| {lang} | {count} |")
	total = sum(counter.values())
	lines.append(f"| **Total** | **{total}** |")
	# Regex to swap old table block
	import re
	new_table = '\n'.join(lines)
	text = re.sub(r"## Per-language counts\n\n\| Language \| Query rows \|[\s\S]*?## Regeneration script",
				  f"## Per-language counts\n\n{new_table}\n\n## Regeneration script",
				  text, count=1)
	MD_PATH.write_text(text, encoding='utf-8')

def main():
	html = fetch_html(URL)
	rows = parse_rows(html)
	if not rows:
		raise SystemExit('No rows parsed.')
	write_csv(rows)
	counter = summarize(rows)
	update_markdown(counter)
	print(f'Wrote {len(rows)} rows to {CSV_PATH}')
	for lang,count in counter.most_common():
		print(f'{lang}: {count}')
	print(f'Total: {sum(counter.values())}')

if __name__ == '__main__':
	main()
```

Install dependencies (one-time):

```bash
pip install beautifulsoup4 requests
```

Run regeneration:

```bash
python scripts/update_codeql_cwe_coverage.py
```



