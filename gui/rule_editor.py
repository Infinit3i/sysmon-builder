from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QLabel,
    QComboBox,
    QLineEdit,
    QPushButton,
    QListWidget,
)
from models.sysmon_config import RuleFilter, SysmonConfig


class RuleEditor(QWidget):
    def __init__(self, config: SysmonConfig) -> None:
        super().__init__()

        self.config = config
        self.current_event_id: int | None = None
        self.current_event_name: str = ""

        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        self.title = QLabel("No Event Selected")

        self.rule_type = QComboBox()
        self.rule_type.addItems(["include", "exclude"])

        self.field_box = QComboBox()
        self.field_box.addItems(["Image", "CommandLine", "ParentImage"])

        self.condition_box = QComboBox()
        self.condition_box.addItems(["is", "contains", "begin with", "end with"])

        self.value_input = QLineEdit()
        self.value_input.setPlaceholderText("Enter value...")

        self.add_button = QPushButton("Add Rule")
        self.remove_button = QPushButton("Remove Selected Rule")

        self.rule_list = QListWidget()

        self.layout.addWidget(self.title)
        self.layout.addWidget(self.rule_type)
        self.layout.addWidget(self.field_box)
        self.layout.addWidget(self.condition_box)
        self.layout.addWidget(self.value_input)
        self.layout.addWidget(self.add_button)
        self.layout.addWidget(self.remove_button)
        self.layout.addWidget(self.rule_list)

        self.add_button.clicked.connect(self.add_rule)
        self.remove_button.clicked.connect(self.remove_selected_rule)

    def set_event(self, event_id: int, event_name: str) -> None:
        self.current_event_id = event_id
        self.current_event_name = event_name
        self.title.setText(f"{event_id} - {event_name}")
        self.refresh_rules()

    def refresh_rules(self) -> None:
        self.rule_list.clear()

        if self.current_event_id is None:
            return

        event_config = self.config.get_or_create_event(
            self.current_event_id,
            self.current_event_name,
        )

        for rule in event_config.rules:
            rule_text = (
                f"{rule.rule_type} | "
                f"{rule.field_name} | "
                f"{rule.condition} | "
                f"{rule.value}"
            )
            self.rule_list.addItem(rule_text)

    def add_rule(self) -> None:
        if self.current_event_id is None:
            return

        value = self.value_input.text().strip()
        if not value:
            return

        event_config = self.config.get_or_create_event(
            self.current_event_id,
            self.current_event_name,
        )

        event_config.rules.append(
            RuleFilter(
                rule_type=self.rule_type.currentText(),
                field_name=self.field_box.currentText(),
                condition=self.condition_box.currentText(),
                value=value,
            )
        )

        self.value_input.clear()
        self.refresh_rules()

    def remove_selected_rule(self) -> None:
        if self.current_event_id is None:
            return

        selected_row = self.rule_list.currentRow()
        if selected_row < 0:
            return

        event_config = self.config.get_or_create_event(
            self.current_event_id,
            self.current_event_name,
        )

        if 0 <= selected_row < len(event_config.rules):
            del event_config.rules[selected_row]

        self.refresh_rules()