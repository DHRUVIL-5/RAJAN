import os
import tempfile
from core.scope import ScopeEnforcer
from core.task_tree import TaskTree, Task
from core.config import Config
from core.memory import Memory
from core.exporter import Exporter

assert ScopeEnforcer("example.com").is_in_scope("example.com")
assert not ScopeEnforcer("example.com").is_in_scope("sub.example.com")
assert ScopeEnforcer("example.com", "*.example.com").is_in_scope("sub.example.com")
assert not ScopeEnforcer("example.com").is_in_scope("https://example.com.evil.test")

tree = TaskTree("example.com")
a = Task(1, "a", "web")
b = Task(2, "b", "web", depends_on=[1])
tree.tasks = [a, b]
tree.mark_failed(a, "failed")
assert tree.get_next_task() is None
assert b.status == "skipped"
assert tree.add_dynamic_task("b", "web") is None
assert tree.add_dynamic_task("bad", "banana") is None

cfg = Config()
try:
    cfg.set()
except ValueError:
    pass
else:
    raise AssertionError("empty Config.set() must fail")

with tempfile.TemporaryDirectory() as d:
    db = os.path.join(d, "db.sqlite")
    old = Exporter.__init__
    m = Memory(db)
    sid = m.create_session("../../evil/target:443")
    fname = Exporter(m, sid)._base_filename()
    assert os.path.dirname(fname) == "reports"
    assert ".." not in os.path.basename(fname)
    m.close()

print("targeted regression checks passed")
