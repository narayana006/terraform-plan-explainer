import io
import json
from pathlib import Path

import pytest

from terraform_plan_explainer import cli
from terraform_plan_explainer.plan import PlanError, group_by_kind, parse_plan
from terraform_plan_explainer.render import render_json, render_markdown, render_text
from terraform_plan_explainer.risks import assess

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "plan.json"


def make_plan(*resources):
    return json.dumps({"format_version": "1.2", "resource_changes": list(resources)})


def res(address, actions, before=None, after=None, **change_extra):
    rtype = address.split(".")[-2]
    return {
        "address": address, "mode": "managed", "type": rtype, "name": address.split(".")[-1],
        "change": {"actions": actions, "before": before, "after": after, **change_extra},
    }


def findings_for(*resources):
    return assess(parse_plan(make_plan(*resources)))


def policy(*statements):
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


# --- parsing ----------------------------------------------------------------

def test_actions_map_to_kinds_and_noops_are_dropped():
    changes = parse_plan(make_plan(
        res("null_resource.a", ["create"], None, {}),
        res("null_resource.b", ["update"], {}, {}),
        res("null_resource.c", ["delete", "create"], {}, {}),
        res("null_resource.d", ["create", "delete"], {}, {}),
        res("null_resource.e", ["delete"], {}, None),
        res("null_resource.f", ["no-op"], {}, {}),
        res("null_resource.g", ["read"], {}, {}),
    ))
    assert {c.address.split(".")[1]: c.kind for c in changes} == {
        "a": "create", "b": "update", "c": "replace", "d": "replace", "e": "destroy"}
    assert [c.create_before_destroy for c in changes if c.kind == "replace"] == [False, True]


def test_data_sources_are_ignored():
    r = res("data.aws_ami.x", ["read"], None, {})
    r["mode"] = "data"
    assert parse_plan(make_plan(r)) == []


def test_empty_plan_has_no_changes():
    changes = parse_plan('{"format_version": "1.2"}')
    assert changes == []
    assert "No changes" in render_text(changes, [])


@pytest.mark.parametrize("text, fragment", [
    ("not json", "not valid JSON"),
    ("[]", "format_version"),
    ('{"format_version": "1.0", "values": {}}', "state JSON"),
])
def test_bad_input_raises_plan_error(text, fragment):
    with pytest.raises(PlanError, match=fragment):
        parse_plan(text)


def test_group_by_kind_sorts_addresses():
    groups = group_by_kind(parse_plan(make_plan(
        res("null_resource.z", ["create"], None, {}), res("null_resource.a", ["create"], None, {}))))
    assert [c.address for c in groups["create"]] == ["null_resource.a", "null_resource.z"]


# --- destructive / data loss ------------------------------------------------

def test_destroying_a_database_is_high_data_loss():
    (f,) = findings_for(res("aws_db_instance.main", ["delete"], {"identifier": "x"}, None))
    assert (f.severity, f.category) == ("high", "data-loss")


def test_destroying_a_stateless_resource_is_medium():
    (f,) = findings_for(res("aws_route53_record.x", ["delete"], {}, None))
    assert (f.severity, f.category) == ("medium", "destructive")


def test_replace_reports_the_attributes_that_force_it():
    (f,) = findings_for(res("aws_ebs_volume.data", ["delete", "create"], {}, {},
                            replace_paths=[["availability_zone"], ["tags", "x"], ["list", 0]]))
    assert f.severity == "high"
    assert "availability_zone, tags.x, list[0]" in f.message


def test_turning_off_deletion_protection_is_flagged_only_when_it_changes():
    changed = findings_for(res("aws_db_instance.a", ["update"],
                               {"deletion_protection": True}, {"deletion_protection": False}))
    unchanged = findings_for(res("aws_db_instance.a", ["update"],
                                 {"deletion_protection": False}, {"deletion_protection": False}))
    assert [f.severity for f in changed] == ["medium"]
    assert unchanged == []


def test_plain_create_and_update_have_no_findings():
    assert findings_for(
        res("aws_instance.a", ["create"], None, {"instance_type": "t3.micro"}),
        res("aws_db_instance.b", ["update"], {"instance_class": "a"}, {"instance_class": "b"}),
    ) == []


# --- IAM --------------------------------------------------------------------

def test_star_action_on_star_resource_is_high():
    (f,) = findings_for(res("aws_iam_policy.p", ["create"], None,
                            {"policy": policy({"Effect": "Allow", "Action": "*", "Resource": "*"})}))
    assert (f.severity, f.category) == ("high", "iam")


def test_service_wildcard_is_medium_and_iam_wildcard_is_high():
    found = findings_for(res("aws_iam_policy.p", ["create"], None, {"policy": policy(
        {"Effect": "Allow", "Action": ["s3:*", "iam:*"], "Resource": "*"})}))
    assert {(f.severity, f.message.split('"')[1]) for f in found} == {("medium", "s3:*"), ("high", "iam:*")}


def test_deny_statements_and_scoped_actions_are_not_flagged():
    assert findings_for(res("aws_iam_policy.p", ["create"], None, {"policy": policy(
        {"Effect": "Deny", "Action": "*", "Resource": "*"},
        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::b/*"})})) == []


def test_public_principal_flagged_unless_conditioned():
    open_stmt = {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}
    guarded = dict(open_stmt, Condition={"StringEquals": {"sts:ExternalId": "abc"}})
    assert [f.severity for f in findings_for(
        res("aws_iam_role.r", ["create"], None, {"assume_role_policy": policy(open_stmt)}))] == ["high"]
    assert findings_for(
        res("aws_iam_role.r", ["create"], None, {"assume_role_policy": policy(guarded)})) == []


def test_nested_inline_policy_and_admin_attachment():
    found = findings_for(
        res("aws_iam_role.r", ["create"], None, {"inline_policy": [
            {"name": "x", "policy": policy({"Effect": "Allow", "Action": "*", "Resource": "*"})}]}),
        res("aws_iam_role_policy_attachment.a", ["create"], None,
            {"role": "r", "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}),
    )
    assert [f.severity for f in found] == ["high", "high"]
    assert "AdministratorAccess" in found[1].message


def test_existing_wildcard_is_not_reported_again_on_update():
    doc = policy({"Effect": "Allow", "Action": "*", "Resource": "*"})
    assert findings_for(res("aws_iam_policy.p", ["update"],
                            {"policy": doc, "description": "a"}, {"policy": doc, "description": "b"})) == []


def test_malformed_policy_string_is_ignored():
    assert findings_for(res("aws_iam_policy.p", ["create"], None, {"policy": "{not json"})) == []


# --- network ----------------------------------------------------------------

def ingress(lo, hi, cidr="0.0.0.0/0", protocol="tcp"):
    return {"from_port": lo, "to_port": hi, "protocol": protocol, "cidr_blocks": [cidr]}


@pytest.mark.parametrize("rule, severity, fragment", [
    (ingress(22, 22), "high", "SSH port 22"),
    (ingress(0, 0, protocol="-1"), "high", "ALL ports"),
    (ingress(5000, 6000), "high", "PostgreSQL 5432"),
    (ingress(8080, 8080), "medium", "port 8080"),
    (ingress(443, 443), "low", "web port 443"),
])
def test_security_group_open_to_world(rule, severity, fragment):
    (f,) = findings_for(res("aws_security_group.sg", ["create"], None, {"ingress": [rule]}))
    assert f.severity == severity and f.category == "network"
    assert fragment in f.message


def test_private_cidr_and_egress_are_not_flagged():
    assert findings_for(
        res("aws_security_group.sg", ["create"], None,
            {"ingress": [ingress(22, 22, cidr="10.0.0.0/8")], "egress": [ingress(0, 0, protocol="-1")]}),
        res("aws_security_group_rule.out", ["create"], None, dict(ingress(22, 22), type="egress")),
    ) == []


def test_other_network_resource_types():
    found = findings_for(
        res("aws_security_group_rule.r", ["create"], None, dict(ingress(3389, 3389), type="ingress")),
        res("aws_vpc_security_group_ingress_rule.v", ["create"], None,
            {"cidr_ipv6": "::/0", "from_port": 3306, "to_port": 3306, "ip_protocol": "tcp"}),
        res("google_compute_firewall.g", ["create"], None,
            {"source_ranges": ["0.0.0.0/0"], "allow": [{"protocol": "tcp", "ports": ["22", "8000-8100"]}]}),
        res("azurerm_network_security_rule.z", ["create"], None,
            {"direction": "Inbound", "access": "Allow", "source_address_prefix": "*",
             "destination_port_range": "3389"}),
        res("aws_db_instance.d", ["create"], None, {"publicly_accessible": True}),
        res("aws_s3_bucket_public_access_block.b", ["create"], None,
            {"block_public_acls": False, "block_public_policy": True}),
    )
    by_addr = {}
    for f in found:
        by_addr.setdefault(f.address.split(".")[0], []).append(f.severity)
    assert by_addr == {
        "aws_security_group_rule": ["high"], "aws_vpc_security_group_ingress_rule": ["high"],
        "google_compute_firewall": ["high", "medium"], "azurerm_network_security_rule": ["high"],
        "aws_db_instance": ["high"], "aws_s3_bucket_public_access_block": ["medium"],
    }


def test_findings_sorted_high_first():
    found = findings_for(
        res("aws_security_group.a", ["create"], None, {"ingress": [ingress(443, 443)]}),
        res("aws_route53_record.b", ["delete"], {}, None),
        res("aws_s3_bucket.c", ["delete"], {}, None),
    )
    assert [f.severity for f in found] == ["high", "medium", "low"]


# --- rendering and CLI --------------------------------------------------------

def test_example_plan_renders_in_every_format():
    changes = parse_plan(EXAMPLE.read_text())
    findings = assess(changes)
    text = render_text(changes, findings)
    assert text.startswith("10 resource changes: 3 to create, 3 to update, 2 to replace, 2 to destroy.")
    assert text.index("RISKS") < text.index("CHANGES") < text.index("Verdict: STOP AND REVIEW")
    assert "| **HIGH** | `aws_db_instance.orders` |" in render_markdown(changes, findings)
    doc = json.loads(render_json(changes, findings))
    assert doc["counts"] == {"destroy": 2, "replace": 2, "update": 3, "create": 3}
    assert sum(f["severity"] == "high" for f in doc["findings"]) == 4


def test_cli_exit_codes(capsys, tmp_path):
    assert cli.main([str(EXAMPLE)]) == 1
    assert cli.main([str(EXAMPLE), "--fail-on", "never"]) == 0
    safe = tmp_path / "safe.json"
    safe.write_text(make_plan(res("aws_route53_record.x", ["delete"], {}, None)))
    assert cli.main([str(safe)]) == 0
    assert cli.main([str(safe), "--fail-on", "medium"]) == 1
    capsys.readouterr()
    assert cli.main([str(tmp_path / "missing.json")]) == 2
    bad = tmp_path / "bad.json"
    bad.write_text("oops")
    assert cli.main([str(bad)]) == 2
    assert "not valid JSON" in capsys.readouterr().err


def test_cli_reads_stdin(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(EXAMPLE.read_text()))
    assert cli.main([]) == 1
    assert "aws_s3_bucket.legacy_exports" in capsys.readouterr().out
