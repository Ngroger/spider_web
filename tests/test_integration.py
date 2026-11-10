import tempfile, pathlib
from app.application import Application
from app.config import Config

def test_full_flow_block_app_and_log():
    tmp=pathlib.Path(tempfile.mkdtemp())
    app=Application(db_path=tmp/"t.db", config=Config(path=tmp/"c.json"))
    try:
        # block an app -> rule exists -> engine evaluates BLOCK
        from core.rules_engine import RulesEngine
        rule=RulesEngine.rule_for_app_block("EvilApp", "C:\\evil.exe")
        app.rules.create(rule)
        assert RulesEngine.evaluate(app.rules.list(), direction="OUTBOUND", protocol="TCP",
                                    remote_port=443, app_path="C:\\evil.exe")=="BLOCK"
        # incident response turns shield on
        assert "ON" in app.incident_response()
        assert app.firewall.get_state().emergency_shield is True
        # log + export shape
        app.logger.log("CONNECTION","LOW", application_name="EvilApp", decision="BLOCKED", details="test")
        assert len(app.events.list(limit=5))>=1
    finally:
        app.stop()
