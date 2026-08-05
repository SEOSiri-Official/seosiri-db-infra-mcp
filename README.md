# seosiri-db-infra-mcp

> 📖 **Official Architecture & Documentation:** [SEOSiri Database Infrastructure Guide](https://www.seosiri.com/2026/08/seosiri-db-infra-mcp.html) | [Central MCP Directory](https://www.seosiri.com/2026/07/seosiri-mcp-servers.html)

An open-source, local-first Model Context Protocol (MCP) server for **Secure Live Database Querying, Schema Inspection, AWS S3 Security Audits, and Cloudflare Infrastructure Control**.

---

## 💖 Sponsorship, B2B Custom Solutions & Attribution

### 👨‍💻 Lead Architect & Attribution
Designed and engineered by **[Momenul Ahmad](https://github.com/MOBILEPHONE)**, Lead Architect and Founder of **[SEOSiri](https://seosiri.com)**.

---

## 🚀 Capabilities & Tools (10 Production Tools)

* **`execute_readonly_postgres_query`**: Executes parameterized read-only SQL queries with SELECT-only validation.
* **`inspect_database_schema_tree`**: Extracts table schemas, column data types, and indexes.
* **`audit_aws_s3_bucket_security`**: Inspects AWS S3 bucket policies, encryption, and public-access block flags.
* **`check_cloudflare_worker_deployment_status`**: Audits Cloudflare Workers deployment states and routes.
* **`mask_sensitive_query_columns`**: Applies dynamic column-level PII/PHI masking to query result sets.
* **`enforce_query_timeout_guardrails`**: Configures query execution timeouts to prevent table locks.
* **`export_query_parquet_buffer`**: Formats database query results into columnar Parquet buffers.
* **`sanitize_database_input_payload`**: Strips SQL mutation attempts (`DROP`, `DELETE`, `UPDATE`).
* **`get_live_db_throughput_metrics`**: Monitors system health and connection metrics.
* **`get_db_server_specifications`**: Returns protocol specs and capability matrices.

---

## 🛠️ Quickstart

### Installation
```bash
pip install -e .
```

### Run Tests
```bash
pytest tests/test_db_infra.py
```

---

## 🔌 Claude Desktop / Cursor Configuration

Add this block to your `claude_desktop_config.json` or Cursor settings file:

```json
{
  "mcpServers": {
    "seosiri-db-infra-mcp": {
      "command": "python",
      "args": ["-m", "seosiri_db_infra_mcp"]
    }
  }
}
```

---

## 📄 License

Distributed under the MIT License. See [LICENSE](https://github.com/SEOSiri-Official/seosiri-db-infra-mcp/blob/main/LICENSE) for more information.
