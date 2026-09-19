## Outbound Traffic Report

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
