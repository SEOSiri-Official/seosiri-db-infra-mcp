# tests/test_db_infra.py
import json
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.main_server import (
    execute_readonly_postgres_query,
    inspect_database_schema_tree,
    audit_aws_s3_bucket_security,
    check_cloudflare_worker_deployment_status,
    mask_sensitive_query_columns,
    enforce_query_timeout_guardrails,
    export_query_parquet_buffer,
    sanitize_database_input_payload,
    get_live_db_throughput_metrics,
    get_db_server_specifications
)


def test_1_readonly_query_success():
    res = json.loads(execute_readonly_postgres_query("SELECT * FROM users"))
    assert res["status"] == "SUCCESS"
    assert res["rows_returned"] == 2


def test_2_mutating_query_rejected():
    res = json.loads(execute_readonly_postgres_query("DROP TABLE users"))
    assert res["status"] == "REJECTED"


def test_3_schema_inspection():
    res = json.loads(inspect_database_schema_tree("users"))
    assert res["status"] == "SCHEMA_INSPECTED"
    assert "users" in res["schema_tree"]


def test_4_s3_security_audit():
    res = json.loads(audit_aws_s3_bucket_security("seosiri-data-lake-prod"))
    assert res["status"] == "AUDITED"
    assert res["security_policy"]["public_access_block"] == "ENABLED"


def test_5_cloudflare_worker_status():
    res = json.loads(check_cloudflare_worker_deployment_status("seosiri-db-infra-mcp"))
    assert res["status"] == "ACTIVE"


def test_6_pii_column_masking():
    data = json.dumps([{"id": 1, "email": "user@seosiri.com", "status": "ACTIVE"}])
    res = json.loads(mask_sensitive_query_columns(data, "email"))
    assert res["status"] == "MASKED"
    assert res["data"][0]["email"] == "[REDACTED_PII]"


def test_7_timeout_guardrails():
    res = json.loads(enforce_query_timeout_guardrails(5.0))
    assert res["status"] == "GUARDRAIL_CONFIGURED"


def test_8_parquet_export():
    data = json.dumps([{"id": 1, "val": "A"}])
    res = json.loads(export_query_parquet_buffer(data))
    assert res["status"] == "PARQUET_BUFFER_GENERATED"


def test_9_sql_sanitizer():
    res = json.loads(sanitize_database_input_payload("SELECT * FROM users -- comment"))
    assert res["status"] == "SANITIZED"
    assert res["is_safe_select"] is True


def test_10_throughput_and_specs():
    res1 = json.loads(get_live_db_throughput_metrics())
    assert res1["status"] == "HEALTHY"

    res2 = json.loads(get_db_server_specifications())
    assert res2["total_tools"] == 10