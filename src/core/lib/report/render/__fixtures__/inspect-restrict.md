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

<details>
<summary>💬 Communication details</summary>

```
✅ 00:05.000: GET https://a.example.com/pkg.json -> 200 (1.0KB)
🚫 00:07.000: GET https://bad.example.com/payload -> https-not-allowed
🚫 00:08.000: DNS A unresolvable.example.net -> dns-not-allowed
⚠️ 00:09.123: HTTPS untrusted-ca.example.com:443 -> client-aborted
```

</details>

*Reported by [buildcage/docker](https://github.com/buildcage/docker)*
