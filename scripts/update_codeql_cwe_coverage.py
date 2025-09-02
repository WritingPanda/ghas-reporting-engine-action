#!/usr/bin/env python3
"""Regenerate CodeQL CWE coverage CSV and update per-language counts in markdown.

Usage:
  python scripts/update_codeql_cwe_coverage.py

Requires:
  pip install requests beautifulsoup4
"""
from __future__ import annotations
import requests, csv, re, sys, collections, pathlib
from bs4 import BeautifulSoup

URL = "https://codeql.github.com/codeql-query-help/full-cwe/"
CSV_PATH = pathlib.Path('.github/instructions/codeql_cwe_coverage.csv')
MD_PATH = pathlib.Path('.github/instructions/codeqlcwecoverage.instructions.md')

def fetch_html(url: str) -> str:
    r = requests.get(url, timeout=60)
    r.raise_for_status()
    return r.text

def parse_rows(html: str) -> list[list[str]]:
    soup = BeautifulSoup(html, 'html.parser')
    table = soup.find('table')
    if not table:
        raise SystemExit('Could not locate table in HTML.')
    header = [th.get_text(strip=True) for th in table.find('tr').find_all('th')]
    mapping = {h:i for i,h in enumerate(header)}
    out_rows = []
    for tr in table.find_all('tr')[1:]:
        tds = tr.find_all(['td','th'])
        if len(tds) < 4:
            continue
        vals = [td.get_text(separator=' ', strip=True) for td in tds]
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
    return collections.Counter(r[1] for r in rows)

def update_markdown(counter):
    if not MD_PATH.exists():
        print('Markdown file not found, skipping update of counts.', file=sys.stderr)
        return
    text = MD_PATH.read_text(encoding='utf-8')
    start_marker = '## Per-language counts\n\n| Language | Query rows |'
    if start_marker not in text:
        print('Counts section not found; leave markdown as-is.', file=sys.stderr)
        return
    lines = ["| Language | Query rows |","| --- | ---: |"]
    for lang,count in counter.most_common():
        lines.append(f"| {lang} | {count} |")
    total = sum(counter.values())
    lines.append(f"| **Total** | **{total}** |")
    new_table = '\n'.join(lines)
    text = re.sub(r"## Per-language counts\n\n\| Language \| Query rows \|[\s\S]*?## Regeneration script",f"## Per-language counts\n\n{new_table}\n\n## Regeneration script",text,count=1)
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
