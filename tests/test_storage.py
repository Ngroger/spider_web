import tempfile, pathlib
from app.config import Config
from app.application import Application
from storage.models import FirewallRule

def test_app_creates_db_and_rules(tmp_path):
    app=Application(db_path=tmp_path/"t.db", config=Config(path=tmp_path/"c.json"))
    assert app.rules.list()
    r=FirewallRule(name="Test block", action="BLOCK", remote_ip="203.0.113.1")
    app.rules.create(r)
    assert app.rules.get(r.id).name=="Test block"
    app.events.list()
    ev=app.logger.log("CONNECTION","LOW", application_name="test.exe", decision="ALLOWED", details="ok")
    assert ev.id
    assert any(e.id==ev.id for e in app.events.list(limit=10))
    app.stop()
