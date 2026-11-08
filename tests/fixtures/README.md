# Test fixtures

Sample events used by the unit tests in `tests/`.
Each fixture is built from the public AWS / OCSF documentation, not from
real customer data. Replace or extend them with sanitized real events
when available.

## Layout

```
tests/fixtures/
  <logtype>/                 # same name as the section in aws.ini
    <case>.json              # raw input, exactly as es-loader reads it
    <case>.expected.json     # optional: expected index name / ECS fields
```

- `<logtype>` must match a section of
  `source/lambda/es_loader/aws.ini` (for example `cloudtrail`,
  `vpcflowlogs`, `guardduty`, `securityhub`, `securitylake`).
- `<case>` describes what the sample covers (for example
  `basic`, `findings_imported_v2`, `vpcflow_v5`).
- Keep one log type per directory so a branch that adds a log type only
  adds files and does not conflict with other branches.

## Loading a fixture

```python
from conftest import load_fixture

def test_cloudtrail_basic(parse_json_log):
    raw = load_fixture('cloudtrail/basic.json')
    docs = parse_json_log(raw, 'cloudtrail', 'AWSLogs/111122223333/CloudTrail/')
    assert docs[0]['index'].startswith('log-aws-cloudtrail-')
```

`parse_json_log` (in `tests/conftest.py`) runs the real `create_logconfig`,
`FileFormatJson` and `siem.LogParser` without connecting to OpenSearch.

## Rules for adding samples

- Use documentation-reserved values only:
  account `111122223333`, IPs from `192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`, domains under `example.com`.
- Never commit real account IDs, ARNs, access keys, user names or IPs.
- Put the documentation URL the sample is based on in the test docstring.
- Assert only the fields the test is about (index name, key ECS fields), so
  unrelated schema changes do not break the test.
