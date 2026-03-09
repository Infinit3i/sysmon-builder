from dataclasses import dataclass

from data.sysmon_events import SYS_MON_EVENTS
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

EVENT_TOOLTIP_HINTS: dict[int, str] = {
    1: "Most teams baseline then include trusted images/parents and alert on unknown executions.",
    2: "Often excluded unless investigating timestomping; can be noisy in some environments.",
    3: "Commonly include known-good outbound destinations and ports, then watch for anomalies.",
    4: "Usually low volume; often included for operational visibility.",
    5: "Frequently optional; used when process lifecycle visibility is needed.",
    6: "Typically monitored for unexpected/unsigned driver loads.",
    7: "Can be noisy; usually scoped to high-value processes.",
    8: "Commonly monitored for injection-like behavior.",
    9: "Often enabled selectively for specific hosts/use-cases.",
    10: "Frequently monitored for suspicious process access patterns.",
    11: "Commonly used to baseline file create paths and startup locations.",
    12: "Registry events are usually path-scoped to reduce noise.",
    13: "Often path-focused; many teams exclude known-good repetitive values.",
    14: "Used with 12/13 for registry rename/change visibility.",
    15: "Often enabled for targeted paths due to volume.",
    16: "Usually included to detect Sysmon config changes.",
    17: "Named pipes are often baseline-driven with allow/deny tuning.",
    18: "Named pipes are often baseline-driven with allow/deny tuning.",
    19: "WMI events are high value for persistence and execution monitoring.",
    20: "WMI events are high value for persistence and execution monitoring.",
    21: "WMI events are high value for persistence and execution monitoring.",
    22: "DNS can be noisy; most teams baseline domains and monitor outliers.",
    23: "Used for delete tracking in sensitive paths.",
    24: "Clipboard is usually enabled for specific monitoring objectives.",
    25: "Generally high-signal for process tampering behaviors.",
    26: "Used where delete-detection policy matters for investigations.",
    27: "Used when executable blocking telemetry is required.",
    28: "Used when shredding/block events are in policy scope.",
    29: "Used when executable detection/block telemetry is needed.",
    30: "Used when blocking/defense telemetry is needed.",
}


@dataclass
class BaselineOptions:
    enabled_sources: set[str]
    selected_event_ids: set[int]
    event_rule_modes: dict[int, str]


class BaselineOptionsDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Baseline Options")
        self.setMinimumSize(700, 600)

        root = QVBoxLayout(self)

        root.addWidget(QLabel("Select sources to baseline and choose include/exclude mode per Event ID."))

        source_group = QGroupBox("Sources")
        source_layout = QGridLayout(source_group)

        self.source_processes = QCheckBox("Processes")
        self.source_processes.setChecked(True)
        self.source_network = QCheckBox("Network Connections")
        self.source_network.setChecked(True)
        self.source_services = QCheckBox("Services")
        self.source_services.setChecked(True)
        self.source_scheduled_tasks = QCheckBox("Scheduled Tasks")
        self.source_scheduled_tasks.setChecked(True)
        self.source_registry = QCheckBox("Registry")
        self.source_registry.setChecked(False)

        source_layout.addWidget(self.source_processes, 0, 0)
        source_layout.addWidget(self.source_network, 0, 1)
        source_layout.addWidget(self.source_services, 1, 0)
        source_layout.addWidget(self.source_scheduled_tasks, 1, 1)
        source_layout.addWidget(self.source_registry, 2, 0)

        root.addWidget(source_group)

        event_group = QGroupBox("Event IDs 1-30")
        event_layout = QVBoxLayout(event_group)

        toolbar = QHBoxLayout()
        self.select_all_btn = QPushButton("Select All")
        self.clear_all_btn = QPushButton("Clear All")
        self.mode_include_btn = QPushButton("Set All Include")
        self.mode_exclude_btn = QPushButton("Set All Exclude")
        toolbar.addWidget(self.select_all_btn)
        toolbar.addWidget(self.clear_all_btn)
        toolbar.addWidget(self.mode_include_btn)
        toolbar.addWidget(self.mode_exclude_btn)
        event_layout.addLayout(toolbar)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        grid = QGridLayout(content)
        grid.addWidget(QLabel("Use"), 0, 0)
        grid.addWidget(QLabel("Event"), 0, 1)
        grid.addWidget(QLabel("Rule Mode"), 0, 2)

        self.event_rows: dict[int, tuple[QCheckBox, QComboBox]] = {}
        for index, event_id in enumerate(range(1, 31), start=1):
            enabled = QCheckBox()
            enabled.setChecked(True)
            event_name = SYS_MON_EVENTS.get(event_id, f"Event {event_id}")
            label = QLabel(f"{event_id} - {event_name}")
            mode = QComboBox()
            mode.addItems(["include", "exclude"])
            mode.setCurrentText("include")
            tooltip = EVENT_TOOLTIP_HINTS.get(
                event_id,
                "Most teams baseline first, then tune include/exclude based on environment noise.",
            )
            label.setToolTip(tooltip)
            enabled.setToolTip(tooltip)
            mode.setToolTip(tooltip)

            row = index
            grid.addWidget(enabled, row, 0)
            grid.addWidget(label, row, 1)
            grid.addWidget(mode, row, 2)
            self.event_rows[event_id] = (enabled, mode)

        scroll.setWidget(content)
        event_layout.addWidget(scroll)
        root.addWidget(event_group)

        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        root.addWidget(button_box)

        self.select_all_btn.clicked.connect(self._select_all)
        self.clear_all_btn.clicked.connect(self._clear_all)
        self.mode_include_btn.clicked.connect(lambda: self._set_all_modes("include"))
        self.mode_exclude_btn.clicked.connect(lambda: self._set_all_modes("exclude"))
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)

    def _select_all(self) -> None:
        for enabled, _mode in self.event_rows.values():
            enabled.setChecked(True)

    def _clear_all(self) -> None:
        for enabled, _mode in self.event_rows.values():
            enabled.setChecked(False)

    def _set_all_modes(self, mode: str) -> None:
        for _enabled, selector in self.event_rows.values():
            selector.setCurrentText(mode)

    def get_options(self) -> BaselineOptions:
        enabled_sources: set[str] = set()
        if self.source_processes.isChecked():
            enabled_sources.add("processes")
        if self.source_network.isChecked():
            enabled_sources.add("network")
        if self.source_services.isChecked():
            enabled_sources.add("services")
        if self.source_scheduled_tasks.isChecked():
            enabled_sources.add("scheduled_tasks")
        if self.source_registry.isChecked():
            enabled_sources.add("registry")
        enabled_sources.add("sysmon_events")

        selected_event_ids: set[int] = set()
        event_rule_modes: dict[int, str] = {}
        for event_id, (enabled, mode) in self.event_rows.items():
            event_rule_modes[event_id] = mode.currentText()
            if enabled.isChecked():
                selected_event_ids.add(event_id)

        return BaselineOptions(
            enabled_sources=enabled_sources,
            selected_event_ids=selected_event_ids,
            event_rule_modes=event_rule_modes,
        )
