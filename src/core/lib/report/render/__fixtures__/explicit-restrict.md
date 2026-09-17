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

* **✅ Allowed Urls**

   * \[2/3\] RUN curl https://a.example.com/

      (00:00:00Z · duration 1.000s)

      ```
      - GET https://a.example.com/ -> 200
      ```

* **🚫 Blocked Urls**

   - (00:00:02Z) https://bad.example.com/

</details>

*Reported by [buildcage/docker](https://github.com/buildcage/docker)*
