#!/usr/bin/env python3
import json, sys, os, datetime
from jinja2 import Template
import pdfkit

TEMPLATE = """
<html>
<head><meta charset="utf-8"><title>Scan Report</title></head>
<body>
<h1>Web App Scan Report</h1>
<p>Target: {{target}}</p>
<p>Scan date: {{date}}</p>
<h2>Executive summary</h2>
<ul>
{% for sev,items in summary.items() %}
<li><b>{{sev}}</b>: {{items}} issue(s)</li>
{% endfor %}
</ul>

<h2>Findings</h2>
{% for p in pages %}
  <h3>{{p.url}} (status {{p.status}})</h3>
  {% if p.issues %}
    <ul>
    {% for i in p.issues %}
      <li><b>{{i.type}}</b> - {{i.message}}</li>
    {% endfor %}
    </ul>
  {% else %}
    <p>No issues detected (passive checks).</p>
  {% endif %}
{% endfor %}
<hr>
<p>Notes: This report contains only passive & safe checks. For deeper active testing use OWASP ZAP or an authorised penetration test.</p>
</body>
</html>
"""

def score_issue(issue):
    t = issue.get("type","")
    if t == "missing_csrf_token":
        return "High"
    if t == "possible_reflection":
        return "Medium"
    return "Low"

def generate(infile, target, outfile_html="report.html", outfile_pdf=None):
    data = json.load(open(infile))
    pages = data.get("pages",[])
    summary = {"Critical":0,"High":0,"Medium":0,"Low":0}
    for p in pages:
        for i in p.get("issues",[]):
            sev = score_issue(i)
            summary[sev] = summary.get(sev,0)+1
    rendered = Template(TEMPLATE).render(target=target,date=str(datetime.datetime.utcnow()),pages=pages,summary=summary)
    with open(outfile_html,"w",encoding="utf-8") as f:
        f.write(rendered)
    if outfile_pdf:
        pdfkit.from_file(outfile_html, outfile_pdf)
    print("Report generated:", outfile_html, outfile_pdf)

if __name__=="__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("jsonfile")
    parser.add_argument("--target", required=True)
    parser.add_argument("--pdf", help="output pdf path")
    args = parser.parse_args()
    generate(args.jsonfile, args.target, outfile_html="report.html", outfile_pdf=args.pdf)
