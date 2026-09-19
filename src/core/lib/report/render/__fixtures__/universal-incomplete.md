## Outbound Traffic Report

> ⚠️ **This report is incomplete**, so the tables below are not a full record of this run.
> Either the logs don't begin where a real run does, or one carries a line that cannot be
> read. A missing beginning was either removed or rotated out by traffic heavy enough to
> fill the 100 MB of log kept, which takes a few hundred thousand requests.

### ✅ Allowed Hosts

| Host | Rule | Count |
| --- | --- | ---: |
| a.example.com:443 | HTTPS | 3 |
| b.example.com:80 | HTTP | 1 |

### 🚫 Blocked Hosts

| Host | Rule | Reason | Count |
| --- | --- | --- | ---: |
| bad.example.com:443 | HTTPS | https-not-allowed | 2 |

<sub>*Note: HTTP rules are based on the Host header, HTTPS rules on SNI, and IP rules on the destination IP address.*</sub>

*Reported by [buildcage/docker](https://github.com/buildcage/docker)*
