import csv, os

base = r'C:\Users\Admin\Documents\GitHub\environment_1\threat-lens-ai\backend\data'
raw = os.path.join(base, 'unmodified_raw')
ds = r'C:\Users\Admin\Documents\GitHub\environment_1\data_science\data\raw'

# IP comparison
with open(os.path.join(base, '4_malicious_ips.csv'), encoding='utf-8') as f:
    w_rows = list(csv.DictReader(f))
with open(os.path.join(raw, '4_malicious_ips.csv'), encoding='utf-8') as f:
    r_rows = list(csv.DictReader(f))

w_ips = {r['IP'] for r in w_rows}
r_ips = {r['IP'] for r in r_rows}

print('=== IP DATA QUALITY ===')
print(f'working: {len(w_ips)} IPs, raw: {len(r_ips)} IPs')
added = w_ips - r_ips
missing = r_ips - w_ips
print(f'enriched IPs (added): {sorted(added)}')
print(f'missing IPs: {sorted(missing)[:5]}')

w_has_tor = [c for c in w_rows[0].keys() if 'tor' in c.lower()]
r_has_tor = [c for c in r_rows[0].keys() if 'tor' in c.lower()]
print(f'Tor column in working: {w_has_tor}')
print(f'Tor column in raw: {r_has_tor}')

print()

# CVE column naming
with open(os.path.join(base, '2_cve_vulnerabilities.csv'), encoding='utf-8') as f:
    ch = next(csv.reader(f))
print('=== CVE DATA QUALITY ===')
print(f'columns: {ch}')
title_ok = all(c[0].isupper() and '_' in c for c in ch if c != 'cveID')
print(f'Title_Case convention: {"OK" if title_ok else "FAIL - uses camelCase"}')

print()

# OTX comparison
with open(os.path.join(base, '1_otx_threat_intel.csv'), encoding='utf-8') as f:
    w_otx = list(csv.DictReader(f))
with open(os.path.join(raw, '1_otx_threat_intel.csv'), encoding='utf-8') as f:
    r_otx = list(csv.DictReader(f))

w_ids = {r['Pulse_ID'] for r in w_otx}
r_ids = {r['Pulse_ID'] for r in r_otx}
print('=== OTX DATA QUALITY ===')
print(f'working: {len(w_ids)}, raw: {len(r_ids)}')
print(f'missing from working: {len(r_ids - w_ids)}')
print(f'sample missing: {sorted(r_ids - w_ids)[:3]}')
print(f'extra in working (synced): {len(w_ids - r_ids)}')

print()

# Domain comparison
with open(os.path.join(base, '3_malicious_domains.csv'), encoding='utf-8') as f:
    w_dom = list(csv.DictReader(f))
with open(os.path.join(raw, '3_malicious_domains.csv'), encoding='utf-8') as f:
    r_dom = list(csv.DictReader(f))
w_d = {r['Domain'] for r in w_dom}
r_d = {r['Domain'] for r in r_dom}
print('=== DOMAIN DATA QUALITY ===')
print(f'working: {len(w_d)}, raw: {len(r_d)}')
print(f'missing from working: {r_d - w_d}')
print(f'extra in working: {w_d - r_d}')

# Verify data_science snake_case convention
print()
print('=== DATA SCIENCE CONVENTION ===')
for f in ['4_malicious_ips.csv', '3_malicious_domains.csv', '2_cve_vulnerabilities.csv', '1_otx_threat_intel.csv']:
    with open(os.path.join(ds, f), encoding='utf-8') as fh:
        h = next(csv.reader(fh))
    snake = all(c == c.lower().replace(' ', '_') and '_' in c for c in h)
    print(f'  {f}: snake_case={snake}  first_cols={h[:3]}')
