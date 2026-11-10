import pytest
from storage.models import FirewallRule
from core.rules_engine import RulesEngine
from utils.validators import validate_rule_dict, is_valid_ip, is_valid_port_range

def test_priority_wins():
    rules=[FirewallRule(name="allow all", action="ALLOW", priority=100),
           FirewallRule(name="block 443", action="BLOCK", protocol="TCP", remote_port="443", priority=10)]
    assert RulesEngine.evaluate(rules, direction="OUTBOUND", protocol="TCP", remote_port=443)=="BLOCK"
    assert RulesEngine.evaluate(rules, direction="OUTBOUND", protocol="TCP", remote_port=80)=="ALLOW"

def test_ip_cidr_match():
    rules=[FirewallRule(name="block subnet", action="BLOCK", remote_ip="192.168.1.0/24", priority=5)]
    assert RulesEngine.evaluate(rules, direction="OUTBOUND", protocol="TCP", remote_ip="192.168.1.42")=="BLOCK"
    assert RulesEngine.evaluate(rules, direction="OUTBOUND", protocol="TCP", remote_ip="10.0.0.1")=="ALLOW"

def test_conflict_detection():
    existing=[FirewallRule(name="allow https", action="ALLOW", protocol="TCP", remote_port="443", priority=20)]
    new=FirewallRule(name="block https", action="BLOCK", protocol="TCP", remote_port="443", priority=10)
    assert len(RulesEngine.find_conflicts(existing, new))==1
    # Same action as the existing rule -> no conflict (was BLOCK in the old
    # test, which IS opposite to the existing ALLOW and therefore IS a conflict).
    same=FirewallRule(name="allow https 2", action="ALLOW", protocol="TCP", remote_port="443")
    assert RulesEngine.find_conflicts(existing, same)==[]

def test_validation_rejects_bad():
    # 999.1.1.1 IS invalid — the validator must flag it (old test asserted the opposite).
    assert any("IP" in e for e in validate_rule_dict({"name":"x","direction":"OUTBOUND","action":"BLOCK","protocol":"TCP","local_port":"","remote_port":"","remote_ip":"999.1.1.1","profile":"BOTH","priority":10}))
    errs=validate_rule_dict({"name":"x","direction":"OUTBOUND","action":"BLOCK","protocol":"TCP","local_port":"99999","remote_port":"","remote_ip":"999.1.1.1","profile":"BOTH","priority":10})
    assert any("port" in e.lower() for e in errs) and any("IP" in e for e in errs)
    assert is_valid_ip("1.2.3.4") and not is_valid_ip("999.1.1.1")
    assert is_valid_port_range("8000-8100") and not is_valid_port_range("8100-8000")
