"""CRUD for firewall rules + audit via event log."""
from __future__ import annotations
from storage.models import FirewallRule
from storage.database import Database
from utils.formatting import now_iso

class RuleRepository:
    def __init__(self, db: Database): self.db=db
    def _row_to_rule(self, r) -> FirewallRule:
        return FirewallRule(
            id=r["id"], name=r["name"], origin_application_path=r["origin_application_path"],
            related_process_paths=Database.loads(r["related_process_paths"]),
            direction=r["direction"], action=r["action"], protocol=r["protocol"],
            local_port=r["local_port"], remote_port=r["remote_port"], remote_ip=r["remote_ip"],
            profile=r["profile"], priority=r["priority"], enabled=bool(r["enabled"]),
            created_at=r["created_at"], updated_at=r["updated_at"])
    def list(self, enabled_only=False) -> list[FirewallRule]:
        sql="SELECT * FROM firewall_rules ORDER BY priority ASC, created_at DESC"
        if enabled_only: sql="SELECT * FROM firewall_rules WHERE enabled=1 ORDER BY priority ASC, created_at DESC"
        return [self._row_to_rule(r) for r in self.db.query(sql)]
    def get(self, rule_id: str):
        rows=self.db.query("SELECT * FROM firewall_rules WHERE id=?", (rule_id,))
        return self._row_to_rule(rows[0]) if rows else None
    def create(self, rule: FirewallRule) -> FirewallRule:
        rule.updated_at=now_iso()
        self.db.execute("""INSERT INTO firewall_rules
          (id,name,origin_application_path,related_process_paths,direction,action,protocol,
           local_port,remote_port,remote_ip,profile,priority,enabled,created_at,updated_at)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
          (rule.id, rule.name, rule.origin_application_path, Database.dumps(rule.related_process_paths),
           rule.direction, rule.action, rule.protocol, rule.local_port, rule.remote_port,
           rule.remote_ip, rule.profile, rule.priority, int(rule.enabled), rule.created_at, rule.updated_at))
        return rule
    def update(self, rule: FirewallRule) -> FirewallRule:
        rule.updated_at=now_iso()
        self.db.execute("""UPDATE firewall_rules SET name=?, origin_application_path=?, related_process_paths=?,
          direction=?, action=?, protocol=?, local_port=?, remote_port=?, remote_ip=?, profile=?,
          priority=?, enabled=?, updated_at=? WHERE id=?""",
          (rule.name, rule.origin_application_path, Database.dumps(rule.related_process_paths),
           rule.direction, rule.action, rule.protocol, rule.local_port, rule.remote_port,
           rule.remote_ip, rule.profile, rule.priority, int(rule.enabled), rule.updated_at, rule.id))
        return rule
    def delete(self, rule_id: str): self.db.execute("DELETE FROM firewall_rules WHERE id=?", (rule_id,))
    def set_enabled(self, rule_id: str, enabled: bool):
        self.db.execute("UPDATE firewall_rules SET enabled=?, updated_at=? WHERE id=?", (int(enabled), now_iso(), rule_id))
