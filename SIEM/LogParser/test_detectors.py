from datetime import datetime, timedelta

from log_ingestor.event import Event
from log_ingestor.detectors.rules import Rule, RuleSet, Threshold
from log_ingestor.detectors.engine import DetectionEngine


def _failed_login(ts, ip="1.1.1.1", user="root"):
    return Event(
        timestamp=ts,
        severity="WARNING",
        source_ip=ip,
        username=user,
        event_type="failed_login",
        message="failed login",
        raw="...",
    )


def test_simple_match_rule_fires_per_event():
    rs = RuleSet(rules=[Rule(
        id="failed_root", name="Failed root", severity="MEDIUM",
        match={"event_type": "failed_login", "username": "root"},
    )])
    engine = DetectionEngine(rs)
    base = datetime(2025, 1, 1, 12, 0, 0)
    alerts = list(engine.feed([
        _failed_login(base),
        _failed_login(base + timedelta(seconds=1), user="alice"),
        _failed_login(base + timedelta(seconds=2)),
    ]))
    assert len(alerts) == 2
    assert all(a.rule_id == "failed_root" for a in alerts)


def test_threshold_rule_fires_once_at_threshold():
    rs = RuleSet(rules=[Rule(
        id="brute", name="Brute force", severity="HIGH",
        match={"event_type": "failed_login"},
        threshold=Threshold(count=5, window_seconds=300, group_by=["source_ip"]),
    )])
    engine = DetectionEngine(rs)
    base = datetime(2025, 1, 1, 12, 0, 0)
    alerts = []
    for i in range(7):
        alerts.extend(engine.process(_failed_login(base + timedelta(seconds=i))))
    # Fires once at the 5th event, then debounced for the same group
    assert len(alerts) == 1
    assert alerts[0].rule_id == "brute"
    assert len(alerts[0].triggering_events) >= 5


def test_threshold_window_eviction():
    rs = RuleSet(rules=[Rule(
        id="brute", name="Brute force", severity="HIGH",
        match={"event_type": "failed_login"},
        threshold=Threshold(count=3, window_seconds=10, group_by=["source_ip"]),
    )])
    engine = DetectionEngine(rs)
    base = datetime(2025, 1, 1, 12, 0, 0)
    # 2 events, then a long gap, then 2 more — should NOT fire (never 3 inside 10s)
    events = [
        _failed_login(base),
        _failed_login(base + timedelta(seconds=1)),
        _failed_login(base + timedelta(seconds=60)),
        _failed_login(base + timedelta(seconds=61)),
    ]
    alerts = list(engine.feed(events))
    assert alerts == []


def test_threshold_groups_isolated_by_key():
    rs = RuleSet(rules=[Rule(
        id="brute", name="Brute force", severity="HIGH",
        match={"event_type": "failed_login"},
        threshold=Threshold(count=3, window_seconds=300, group_by=["source_ip"]),
    )])
    engine = DetectionEngine(rs)
    base = datetime(2025, 1, 1, 12, 0, 0)
    events = []
    for ip in ("1.1.1.1", "2.2.2.2"):
        for i in range(3):
            events.append(_failed_login(base + timedelta(seconds=i), ip=ip))
    alerts = list(engine.feed(events))
    # One alert per source IP
    assert len(alerts) == 2
    assert {a.group_key["source_ip"] for a in alerts} == {"1.1.1.1", "2.2.2.2"}


def test_message_contains_match():
    rs = RuleSet(rules=[Rule(
        id="contains", name="Contains test", severity="LOW",
        match={"message_contains": ["unauthorized"]},
    )])
    engine = DetectionEngine(rs)
    ev = Event(timestamp=datetime(2025, 1, 1), message="Unauthorized access attempt", raw="...")
    alerts = list(engine.process(ev))
    assert len(alerts) == 1


def test_severity_list_match():
    rs = RuleSet(rules=[Rule(
        id="critsev", name="Critical or error", severity="HIGH",
        match={"severity": ["ERROR", "CRITICAL"]},
    )])
    engine = DetectionEngine(rs)
    e1 = Event(timestamp=datetime(2025, 1, 1), severity="INFO", raw="...")
    e2 = Event(timestamp=datetime(2025, 1, 1), severity="CRITICAL", raw="...")
    alerts = list(engine.feed([e1, e2]))
    assert len(alerts) == 1
    assert alerts[0].rule_id == "critsev"
