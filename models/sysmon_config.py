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

    def clone(self) -> "RuleFilter":
        return RuleFilter(
            rule_type=self.rule_type,
            field_name=self.field_name,
            condition=self.condition,
            value=self.value,
            imported=self.imported,
            group_id=self.group_id,
            group_relation=self.group_relation,
            group_name=self.group_name,
        )


@dataclass
class EventConfig:
    event_id: int
    event_name: str
    rules: List[RuleFilter] = field(default_factory=list)

    def clone(self) -> "EventConfig":
        return EventConfig(
            event_id=self.event_id,
            event_name=self.event_name,
            rules=[rule.clone() for rule in self.rules],
        )


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

    def clone(self) -> "SysmonConfig":
        clone = SysmonConfig()
        clone.events = {
            event_id: event_config.clone()
            for event_id, event_config in self.events.items()
        }
        return clone
