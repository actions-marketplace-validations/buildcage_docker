## Outbound Traffic Report

### ✅ Allowed Hosts

| Host | Rule | Count |
| --- | --- | ---: |
| a.example.com:443 | HTTPS | 3 |
| b.example.com:80 | HTTP | 1 |

### 🚫 Blocked Hosts

| Host | Rule | Reason | Count | Expected |
| --- | --- | --- | ---: | :---: |
| bad.example.com:443 | HTTPS | https-not-allowed | 2 |  |
| a.sury.org:443 | HTTPS | https-not-allowed | 1 | ✅ |
| b.sury.org:443 | HTTPS | https-not-allowed | 1 | ✅ |

### ⚠️ Failed Connections

| Host | Rule | Reason | Count |
| --- | --- | --- | ---: |
| c.example.com:443 | HTTPS | dns-failed | 1 |

<sub>*Note: no rule refused these; the connection itself did not complete, so no rule can change the outcome and none of them fails the step.*</sub>

<sub>*Note: HTTP rules are based on the Host header, HTTPS rules on SNI, and IP rules on the destination IP address.*</sub>

*Reported by [buildcage/docker](https://github.com/buildcage/docker)*
