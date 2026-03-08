from dataclasses import dataclass, field
from typing import List


@dataclass
class RuleFilter:
    field: str
    condition: str
    value: str


@dataclass
class EventConfig:
    event_id: int
    name: str
    enabled: bool = True
    include_rules: List[RuleFilter] = field(default_factory=list)
    exclude_rules: List[RuleFilter] = field(default_factory=list)


@dataclass
class SysmonConfig:
    events: List[EventConfig] = field(default_factory=list)

    def get_event(self, event_id: int) -> EventConfig | None:
        for event in self.events:
            if event.event_id == event_id:
                return event
        return None