from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class RuleFilter:
    rule_type: str
    field_name: str
    condition: str
    value: str
    imported: bool = False
    group_id: str | None = None
    group_relation: str | None = None
    group_name: str | None = None


@dataclass
class EventConfig:
    event_id: int
    event_name: str
    rules: List[RuleFilter] = field(default_factory=list)


class SysmonConfig:
    def __init__(self) -> None:
        self.events: Dict[int, EventConfig] = {}

    def get_or_create_event(self, event_id: int, event_name: str) -> EventConfig:
        if event_id not in self.events:
            self.events[event_id] = EventConfig(
                event_id=event_id,
                event_name=event_name,
            )
        return self.events[event_id]
