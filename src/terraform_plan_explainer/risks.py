"""Rule-based risk checks over parsed plan changes."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterator

from .plan import Change

SEVERITIES = ("high", "medium", "low")

# Resource types that hold data which cannot be recreated by re-applying.
DATA_BEARING = {
    "aws_db_instance": "database",
    "aws_rds_cluster": "database cluster",
    "aws_rds_cluster_instance": "database instance",
    "aws_dynamodb_table": "DynamoDB table",
    "aws_s3_bucket": "S3 bucket",
    "aws_ebs_volume": "EBS volume",
    "aws_efs_file_system": "EFS file system",
    "aws_elasticache_cluster": "cache cluster",
    "aws_elasticache_replication_group": "cache replication group",
    "aws_redshift_cluster": "Redshift cluster",
    "aws_opensearch_domain": "OpenSearch domain",
    "aws_elasticsearch_domain": "Elasticsearch domain",
    "aws_docdb_cluster": "DocumentDB cluster",
    "aws_neptune_cluster": "Neptune cluster",
    "aws_kinesis_stream": "Kinesis stream",
    "aws_sqs_queue": "SQS queue",
    "aws_kms_key": "KMS key",
    "aws_secretsmanager_secret": "secret",
    "aws_backup_vault": "backup vault",
    "aws_cloudwatch_log_group": "log group",
    "google_sql_database_instance": "Cloud SQL instance",
    "google_sql_database": "Cloud SQL database",
    "google_storage_bucket": "GCS bucket",
    "google_bigquery_dataset": "BigQuery dataset",
    "google_bigquery_table": "BigQuery table",
    "google_compute_disk": "persistent disk",
    "google_kms_crypto_key": "KMS key",
    "google_spanner_database": "Spanner database",
    "azurerm_storage_account": "storage account",
    "azurerm_storage_container": "storage container",
    "azurerm_managed_disk": "managed disk",
    "azurerm_mssql_database": "SQL database",
    "azurerm_mssql_server": "SQL server",
    "azurerm_postgresql_flexible_server": "PostgreSQL server",
    "azurerm_mysql_flexible_server": "MySQL server",
    "azurerm_cosmosdb_account": "Cosmos DB account",
    "azurerm_key_vault": "key vault",
    "kubernetes_persistent_volume_claim": "persistent volume claim",
    "kubernetes_namespace": "namespace",
}

# (attribute, risky value, explanation) for safety nets being switched off.
GUARD_RAILS = (
    ("deletion_protection", False, "deletion protection is being turned off"),
    ("deletion_protection_enabled", False, "deletion protection is being turned off"),
    ("skip_final_snapshot", True, "no final snapshot will be taken on deletion"),
    ("force_destroy", True, "force_destroy lets Terraform delete it even when it holds data"),
    ("backup_retention_period", 0, "automated backups are being disabled"),
)

SENSITIVE_PORTS = {
    22: "SSH", 23: "Telnet", 3389: "RDP", 1433: "SQL Server", 1521: "Oracle",
    3306: "MySQL", 5432: "PostgreSQL", 5439: "Redshift", 6379: "Redis",
    9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB", 2379: "etcd",
    5984: "CouchDB", 9092: "Kafka",
}
WEB_PORTS = {80, 443}
OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
SENSITIVE_IAM_SERVICES = {"iam", "sts", "kms", "organizations", "secretsmanager"}
ADMIN_POLICY_SUFFIXES = (":policy/AdministratorAccess", ":policy/IAMFullAccess", ":policy/PowerUserAccess")


@dataclass(frozen=True)
class Finding:
    severity: str  # one of SEVERITIES
    category: str  # data-loss | destructive | iam | network
    address: str
    message: str


def _as_list(value: Any) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


# --- destructive changes and data loss -------------------------------------

def _destructive(c: Change) -> Iterator[tuple[str, str, str]]:
    label = DATA_BEARING.get(c.type)
    if c.kind == "destroy":
        if label:
            yield "high", "data-loss", f"{label} will be DESTROYED; its data is lost unless backed up elsewhere"
        else:
            yield "medium", "destructive", "will be destroyed"
    elif c.kind == "replace":
        why = f" (forced by change to: {', '.join(c.replace_paths)})" if c.replace_paths else ""
        order = "new one is created first, then the old one is deleted" if c.create_before_destroy \
            else "destroyed first, then recreated"
        if label:
            yield "high", "data-loss", f"{label} will be REPLACED: {order}{why}; existing data does not carry over"
        else:
            yield "medium", "destructive", f"will be replaced: {order}{why}"
    elif c.kind == "update" and label:
        for attr, risky, text in GUARD_RAILS:
            if attr in c.after and c.after[attr] == risky and c.before.get(attr) != risky \
                    and type(c.after[attr]) is type(risky):
                yield "medium", "data-loss", f"{text} ({attr} = {json.dumps(risky)})"


# --- IAM --------------------------------------------------------------------

def _policy_documents(value: Any, key: str = "") -> Iterator[dict]:
    """Find JSON policy documents embedded as strings under *policy* attributes."""
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _policy_documents(v, k)
    elif isinstance(value, list):
        for v in value:
            yield from _policy_documents(v, key)
    elif isinstance(value, str) and "policy" in key.lower() and value.lstrip().startswith("{"):
        try:
            doc = json.loads(value)
        except json.JSONDecodeError:
            return
        if isinstance(doc, dict) and "Statement" in doc:
            yield doc


def _principal_is_anyone(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        return any("*" in _as_list(v) for v in principal.values())
    return False


def _statement_findings(stmt: dict) -> Iterator[tuple[str, str]]:
    if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
        return
    actions = [a for a in _as_list(stmt.get("Action")) if isinstance(a, str)]
    all_resources = "*" in _as_list(stmt.get("Resource"))
    scope = "every resource" if all_resources else "the listed resources"

    if any(a in ("*", "*:*") for a in actions):
        yield ("high" if all_resources else "medium",
               f"IAM policy allows every action (Action \"*\") on {scope}")
    else:
        for a in actions:
            if a.endswith(":*"):
                service = a.split(":", 1)[0]
                sev = "high" if service.lower() in SENSITIVE_IAM_SERVICES and all_resources else "medium"
                yield sev, f"IAM policy allows all {service} actions (\"{a}\") on {scope}"

    if _principal_is_anyone(stmt.get("Principal")) and not stmt.get("Condition"):
        yield "high", "policy trusts any principal (Principal \"*\") with no Condition"


def _iam(values: dict) -> Iterator[tuple[str, str, str]]:
    for doc in _policy_documents(values):
        for stmt in _as_list(doc.get("Statement")):
            for sev, msg in _statement_findings(stmt):
                yield sev, "iam", msg
    arn = values.get("policy_arn")
    if isinstance(arn, str) and arn.endswith(ADMIN_POLICY_SUFFIXES):
        yield "high", "iam", f"attaches the broad managed policy {arn.rsplit('/', 1)[-1]}"


# --- network exposure -------------------------------------------------------

def _port_range(rule: dict, lo_key: str = "from_port", hi_key: str = "to_port") -> tuple[int, int] | None:
    """Return (low, high), or None when the rule covers all ports."""
    proto = str(rule.get("protocol", rule.get("ip_protocol", ""))).lower()
    lo, hi = rule.get(lo_key), rule.get(hi_key)
    if proto in ("-1", "all") or lo is None or hi is None:
        return None
    try:
        lo, hi = int(lo), int(hi)
    except (TypeError, ValueError):
        return None
    if (lo, hi) in ((0, 0), (0, 65535), (-1, -1)):
        return None
    return lo, hi


def _exposure(ports: tuple[int, int] | None, cidr: str) -> tuple[str, str, str]:
    if ports is None:
        return "high", "network", f"opens ALL ports to the internet ({cidr})"
    lo, hi = ports
    shown = str(lo) if lo == hi else f"{lo}-{hi}"
    named = sorted(f"{name} {p}" for p, name in SENSITIVE_PORTS.items() if lo <= p <= hi)
    if named:
        extra = "" if lo == hi else f" (includes {', '.join(named)})"
        label = f"{named[0].rsplit(' ', 1)[0]} port {shown}" if lo == hi else f"ports {shown}"
        return "high", "network", f"opens {label} to the internet ({cidr}){extra}"
    if lo == hi and lo in WEB_PORTS:
        return "low", "network", f"opens web port {shown} to the internet ({cidr})"
    return "medium", "network", f"opens port{'' if lo == hi else 's'} {shown} to the internet ({cidr})"


def _open_cidrs(*values: Any) -> list[str]:
    return [c for v in values for c in _as_list(v) if c in OPEN_CIDRS]


def _parse_port_spec(spec: Any) -> tuple[int, int] | None:
    text = str(spec)
    if text in ("*", "", "None"):
        return None
    try:
        lo, _, hi = text.partition("-")
        return int(lo), int(hi or lo)
    except ValueError:
        return None


def _network(c_type: str, v: dict) -> Iterator[tuple[str, str, str]]:
    if c_type in ("aws_security_group", "aws_default_security_group"):
        for rule in _as_list(v.get("ingress")):
            if isinstance(rule, dict):
                for cidr in _open_cidrs(rule.get("cidr_blocks"), rule.get("ipv6_cidr_blocks")):
                    yield _exposure(_port_range(rule), cidr)
    elif c_type == "aws_security_group_rule":
        if v.get("type") == "ingress":
            for cidr in _open_cidrs(v.get("cidr_blocks"), v.get("ipv6_cidr_blocks")):
                yield _exposure(_port_range(v), cidr)
    elif c_type == "aws_vpc_security_group_ingress_rule":
        for cidr in _open_cidrs(v.get("cidr_ipv4"), v.get("cidr_ipv6")):
            yield _exposure(_port_range(v), cidr)
    elif c_type == "google_compute_firewall":
        if str(v.get("direction") or "INGRESS").upper() == "INGRESS" and not v.get("disabled"):
            for cidr in _open_cidrs(v.get("source_ranges")):
                for allow in _as_list(v.get("allow")):
                    ports = _as_list(allow.get("ports")) if isinstance(allow, dict) else []
                    if not ports:
                        yield _exposure(None, cidr)
                    for spec in ports:
                        yield _exposure(_parse_port_spec(spec), cidr)
    elif c_type == "azurerm_network_security_rule":
        source = str(v.get("source_address_prefix", ""))
        if (str(v.get("direction", "")).lower() == "inbound"
                and str(v.get("access", "")).lower() == "allow"
                and source.lower() in ("*", "0.0.0.0/0", "internet", "any")):
            yield _exposure(_parse_port_spec(v.get("destination_port_range", "*")), source)

    if v.get("publicly_accessible") is True:
        yield "high", "network", "will be publicly accessible (publicly_accessible = true)"
    if c_type in ("aws_s3_bucket", "aws_s3_bucket_acl") and v.get("acl") in ("public-read", "public-read-write"):
        yield "high", "network", f"bucket ACL is {v['acl']}"
    if c_type == "aws_s3_bucket_public_access_block":
        off = [k for k in ("block_public_acls", "block_public_policy",
                           "ignore_public_acls", "restrict_public_buckets") if v.get(k) is False]
        if off:
            yield "medium", "network", f"S3 public access block is relaxed ({', '.join(off)} = false)"


# --- entry point ------------------------------------------------------------

def _config_findings(c_type: str, values: dict) -> set[tuple[str, str, str]]:
    return set(_iam(values)) | set(_network(c_type, values))


def assess(changes: list[Change]) -> list[Finding]:
    """Return findings sorted by severity, then address.

    IAM and network checks only report what a change *introduces*: a risky
    setting that was already present before an update is not reported again.
    """
    findings: list[Finding] = []
    for c in changes:
        found = set(_destructive(c))
        if c.kind != "destroy":
            new = _config_findings(c.type, c.after)
            if c.kind == "update":
                new -= _config_findings(c.type, c.before)
            found |= new
        findings.extend(Finding(sev, cat, c.address, msg) for sev, cat, msg in found)
    findings.sort(key=lambda f: (SEVERITIES.index(f.severity), f.address, f.message))
    return findings
