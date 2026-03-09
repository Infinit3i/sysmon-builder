from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QComboBox,
    QLineEdit,
    QPushButton,
    QCheckBox,
    QTreeWidget,
    QTreeWidgetItem,
)
from models.sysmon_config import RuleFilter, SysmonConfig
from PySide6.QtGui import QColor
from PySide6.QtCore import Qt


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

        self.group_box = QComboBox()
        self.group_box.setEditable(True)
        self.group_box.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.group_box.setPlaceholderText("Select or type rule group (optional)")

        self.group_relation = QComboBox()
        self.group_relation.addItems(["or", "and"])

        self.field_box = QComboBox()

        self.condition_box = QComboBox()
        self.condition_box.addItems(["is", "contains", "begin with", "end with"])

        self.value_preset_box = QComboBox()
        self.value_preset_box.setEditable(False)

        self.value_input = QLineEdit()
        self.value_input.setPlaceholderText("Enter custom value...")

        self.add_button = QPushButton("Add Rule")
        self.remove_button = QPushButton("Remove Selected Rule")
        self.new_rules_only_toggle = QCheckBox("Show New Rules Only")

        self.rule_tree = QTreeWidget()
        self.rule_tree.setHeaderHidden(True)

        self.rule_row_1 = QHBoxLayout()
        self.rule_row_1.addWidget(self.rule_type)
        self.rule_row_1.addWidget(self.field_box)
        self.rule_row_1.addWidget(self.condition_box)

        self.group_row = QHBoxLayout()
        self.group_row.addWidget(self.group_box)
        self.group_row.addWidget(self.group_relation)

        self.rule_row_2 = QHBoxLayout()
        self.rule_row_2.addWidget(self.value_preset_box)
        self.rule_row_2.addWidget(self.value_input)

        self.layout.addWidget(self.title)
        self.layout.addLayout(self.group_row)
        self.layout.addLayout(self.rule_row_1)
        self.layout.addLayout(self.rule_row_2)
        self.layout.addWidget(self.add_button)
        self.layout.addWidget(self.remove_button)
        self.layout.addWidget(self.new_rules_only_toggle)
        self.layout.addWidget(self.rule_tree)

        self.add_button.clicked.connect(self.add_rule)
        self.remove_button.clicked.connect(self.remove_selected_rule)
        self.field_box.currentTextChanged.connect(self.load_value_presets_for_field)
        self.group_box.currentIndexChanged.connect(self.on_group_selected)
        self.new_rules_only_toggle.stateChanged.connect(self.refresh_rules)

    def set_event(self, event_id: int, event_name: str) -> None:
        self.current_event_id = event_id
        self.current_event_name = event_name
        self.title.setText(f"{event_id} - {event_name}")
        self.load_fields_for_event()
        self.refresh_group_options()
        self.refresh_rules()

    def refresh_group_options(self) -> None:
        self.group_box.blockSignals(True)
        self.group_box.clear()
        self.group_box.addItem("")
        self.group_box.setItemData(0, None, Qt.ItemDataRole.UserRole)

        if self.current_event_id is None:
            self.group_box.blockSignals(False)
            return

        event_config = self.config.events.get(self.current_event_id)
        if event_config is None:
            self.group_box.blockSignals(False)
            return

        seen_group_ids: set[str] = set()
        for rule in event_config.rules:
            if not rule.group_id or rule.group_id in seen_group_ids:
                continue
            seen_group_ids.add(rule.group_id)

            group_name = rule.group_name or "Imported Rule"
            group_relation = rule.group_relation or "or"
            label = f"{group_name} ({group_relation})"
            self.group_box.addItem(label)
            self.group_box.setItemData(
                self.group_box.count() - 1,
                {
                    "group_id": rule.group_id,
                    "group_name": rule.group_name,
                    "group_relation": group_relation,
                },
                Qt.ItemDataRole.UserRole,
            )

        self.group_box.blockSignals(False)

    def on_group_selected(self, *_args) -> None:
        selected_data = self.group_box.currentData(Qt.ItemDataRole.UserRole)
        if not isinstance(selected_data, dict):
            return

        selected_relation = selected_data.get("group_relation")
        if selected_relation in ("or", "and"):
            self.group_relation.setCurrentText(selected_relation)

    def load_fields_for_event(self) -> None:
        from data.sysmon_fields import SYS_MON_FIELDS

        self.field_box.clear()

        if self.current_event_id is None:
            self.title.setText("No Event Selected")
            return

        fields = SYS_MON_FIELDS.get(self.current_event_id, [])

        if not fields:
            self.title.setText(f"{self.current_event_id} - {self.current_event_name} (no fields found)")
            self.value_preset_box.clear()
            return

        self.field_box.addItems(fields)
        self.load_value_presets_for_field(self.field_box.currentText())

    def load_value_presets_for_field(self, field_name: str) -> None:
        from data.sysmon_value_presets import SYS_MON_VALUE_PRESETS

        self.value_preset_box.clear()
        self.value_preset_box.addItem("")

        presets = SYS_MON_VALUE_PRESETS.get(field_name, [])
        if presets:
            self.value_preset_box.addItems(presets)

    def refresh_rules(self) -> None:
        self.rule_tree.clear()
        show_new_only = self.new_rules_only_toggle.isChecked()

        for event_id, event_config in sorted(self.config.events.items()):
            if not event_config.rules:
                continue

            visible_rule_indexes = [
                idx
                for idx, rule in enumerate(event_config.rules)
                if (not show_new_only) or (not rule.imported)
            ]
            if not visible_rule_indexes:
                continue

            event_item = QTreeWidgetItem([f"{event_id} - {event_config.event_name}"])
            self.rule_tree.addTopLevelItem(event_item)

            grouped_parents: dict[str, QTreeWidgetItem] = {}
            ungrouped_parent: QTreeWidgetItem | None = None

            for rule_index in visible_rule_indexes:
                rule = event_config.rules[rule_index]
                if rule.group_id:
                    if rule.group_id not in grouped_parents:
                        group_name = rule.group_name or "Imported Rule"
                        group_relation = rule.group_relation or "or"
                        grouped_parents[rule.group_id] = QTreeWidgetItem(
                            [f"Rule: {group_name} ({group_relation})"]
                        )
                        event_item.addChild(grouped_parents[rule.group_id])
                    parent_item = grouped_parents[rule.group_id]
                else:
                    if ungrouped_parent is None:
                        ungrouped_parent = QTreeWidgetItem(["Ungrouped Rules"])
                        event_item.addChild(ungrouped_parent)
                    parent_item = ungrouped_parent

                rule_text = (
                    f"{event_id} | "
                    f"{rule.rule_type} | "
                    f"{rule.field_name} | "
                    f"{rule.condition} | "
                    f"{rule.value}"
                )
                item = QTreeWidgetItem([rule_text])
                item.setData(0, Qt.ItemDataRole.UserRole, (event_id, rule_index))

                if not rule.imported:
                    item.setBackground(0, QColor("#ffe6cc"))  # light orange

                parent_item.addChild(item)

            event_item.setExpanded(True)

        self.rule_tree.expandAll()

    def add_rule(self) -> None:
        if self.current_event_id is None:
            return

        custom_value = self.value_input.text().strip()
        preset_value = self.value_preset_box.currentText().strip()

        value = custom_value if custom_value else preset_value
        if not value:
            return

        event_config = self.config.get_or_create_event(
            self.current_event_id,
            self.current_event_name,
        )

        selected_group_data = self.group_box.currentData(Qt.ItemDataRole.UserRole)
        selected_group_text = self.group_box.currentText().strip()

        group_id: str | None = None
        group_name: str | None = None
        group_relation: str | None = None

        if isinstance(selected_group_data, dict):
            group_id = selected_group_data.get("group_id")
            group_name = selected_group_data.get("group_name")
            group_relation = selected_group_data.get("group_relation")
        elif selected_group_text:
            existing_group = None
            for existing_rule in event_config.rules:
                if not existing_rule.group_id:
                    continue
                if (existing_rule.group_name or "").strip().lower() == selected_group_text.lower():
                    existing_group = existing_rule
                    break

            if existing_group is not None:
                group_id = existing_group.group_id
                group_name = existing_group.group_name
                group_relation = existing_group.group_relation or self.group_relation.currentText()
            else:
                existing_ids = {
                    existing_rule.group_id
                    for existing_rule in event_config.rules
                    if existing_rule.group_id
                }
                next_index = 1
                group_id = f"user-group-{next_index}"
                while group_id in existing_ids:
                    next_index += 1
                    group_id = f"user-group-{next_index}"

                group_name = selected_group_text
                group_relation = self.group_relation.currentText()

        event_config.rules.append(
            RuleFilter(
                rule_type=self.rule_type.currentText(),
                field_name=self.field_box.currentText(),
                condition=self.condition_box.currentText(),
                value=value,
                group_id=group_id,
                group_name=group_name,
                group_relation=group_relation,
            )
        )

        self.value_input.clear()
        self.value_preset_box.setCurrentIndex(0)
        self.refresh_group_options()
        self.refresh_rules()

    def remove_selected_rule(self) -> None:
        if self.current_event_id is None:
            return

        selected_item = self.rule_tree.currentItem()
        if selected_item is None:
            return

        rule_key = selected_item.data(0, Qt.ItemDataRole.UserRole)
        if not isinstance(rule_key, tuple) or len(rule_key) != 2:
            return

        event_id, rule_index = rule_key
        event_config = self.config.events.get(event_id)

        if event_config is None:
            return

        if 0 <= rule_index < len(event_config.rules):
            del event_config.rules[rule_index]

        self.refresh_group_options()
        self.refresh_rules()
