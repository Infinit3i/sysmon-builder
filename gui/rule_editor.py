from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QComboBox,
    QPushButton,
    QCheckBox,
    QCompleter,
    QTreeWidget,
    QTreeWidgetItem,
    QHeaderView,
    QTableWidget,
    QTableWidgetItem,
    QMessageBox,
    QGroupBox,
)
from models.sysmon_config import RuleFilter, SysmonConfig
from data.sysmon_value_presets import SYS_MON_BASELINE_PRESETS
from data.sysmon_events import SYS_MON_EVENTS
from PySide6.QtGui import QColor
from PySide6.QtCore import Qt
from typing import Callable


class RuleEditor(QWidget):
    def __init__(
        self,
        config: SysmonConfig,
        on_config_change: Callable[[str, SysmonConfig], None] | None = None,
    ) -> None:
        super().__init__()

        self.config = config
        self.on_config_change = on_config_change
        self.current_event_id: int | None = None
        self.current_event_name: str = ""
        self.tree_meta_role = int(Qt.ItemDataRole.UserRole) + 1

        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        self.title = QLabel("No Event Selected")

        self.rule_type = QComboBox()
        self.rule_type.addItems(["include", "exclude"])

        self.group_box = QComboBox()
        self.group_box.setEditable(True)
        self.group_box.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.group_box.setPlaceholderText("Rule Name")
        self.group_box.lineEdit().setPlaceholderText("Rule Name")
        self.group_completer = QCompleter(self.group_box.model(), self.group_box)
        self.group_completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.group_completer.setFilterMode(Qt.MatchFlag.MatchContains)
        self.group_completer.setCompletionMode(QCompleter.CompletionMode.PopupCompletion)
        self.group_box.setCompleter(self.group_completer)

        self.group_relation = QComboBox()
        self.group_relation.addItems(["or", "and"])

        self.field_box = QComboBox()
        self.field_box.setEditable(True)
        self.field_box.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.field_box.setPlaceholderText("Select a Category")
        self.field_box.lineEdit().setPlaceholderText("Select a Category")
        self.field_completer = QCompleter(self.field_box.model(), self.field_box)
        self.field_completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.field_completer.setFilterMode(Qt.MatchFlag.MatchContains)
        self.field_completer.setCompletionMode(QCompleter.CompletionMode.PopupCompletion)
        self.field_box.setCompleter(self.field_completer)

        self.condition_box = QComboBox()
        self.condition_box.addItems(["is", "contains", "begin with", "end with"])

        self.value_preset_box = QComboBox()
        self.value_preset_box.setEditable(True)
        self.value_preset_box.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.value_preset_box.setPlaceholderText("...")
        self.value_preset_box.lineEdit().setPlaceholderText("...")
        self.value_completer = QCompleter(self.value_preset_box.model(), self.value_preset_box)
        self.value_completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.value_completer.setFilterMode(Qt.MatchFlag.MatchContains)
        self.value_completer.setCompletionMode(QCompleter.CompletionMode.PopupCompletion)
        self.value_preset_box.setCompleter(self.value_completer)

        self.add_button = QPushButton("Add Rule")
        self.add_button.setObjectName("positiveButton")
        self.add_button.setMinimumHeight(44)
        self.remove_button = QPushButton("Remove Rule")
        self.remove_button.setObjectName("negativeButton")
        self.remove_button.setMinimumHeight(44)
        self.add_preset_button = QPushButton("Add Rule")
        self.add_preset_button.setObjectName("positiveButton")
        self.add_preset_button.setMinimumHeight(44)
        self.remove_preset_button = QPushButton("Remove Rule")
        self.remove_preset_button.setObjectName("negativeButton")
        self.remove_preset_button.setMinimumHeight(44)
        self.new_rules_only_toggle = QCheckBox("Show New Rules Only")
        self.total_counts_label = QLabel("Include (0)  Exclude (0)")

        self.rule_tree = QTreeWidget()
        self.rule_tree.setColumnCount(2)
        self.rule_tree.setHeaderHidden(True)
        self.rule_tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.rule_tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.rule_tree.setSelectionMode(QTreeWidget.SelectionMode.ExtendedSelection)

        self.rule_row_1 = QHBoxLayout()
        self.rule_row_1.addWidget(self.rule_type)
        self.rule_row_1.addWidget(self.field_box)
        self.rule_row_1.addWidget(self.condition_box)

        self.group_row = QHBoxLayout()
        self.group_row.addWidget(self.group_box)
        self.group_row.addWidget(self.group_relation)

        self.rule_row_2 = QHBoxLayout()
        self.rule_row_2.addWidget(self.value_preset_box)

        self.preset_table = QTableWidget()
        self.preset_table.setColumnCount(1)
        self.preset_table.setHorizontalHeaderLabels(["Preset Baseline Options"])
        self.preset_table.verticalHeader().setVisible(False)
        self.preset_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.preset_table.setSelectionMode(QTableWidget.SelectionMode.ExtendedSelection)
        self.preset_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.preset_table.horizontalHeader().setStretchLastSection(True)
        self.preset_table.setFixedHeight(280)
        self._load_preset_options()

        self.action_row = QHBoxLayout()
        self.action_row.addWidget(self.add_button)
        self.action_row.addWidget(self.remove_button)

        self.config_group = QGroupBox("Sysmon Config")
        self.config_group_layout = QVBoxLayout()
        self.config_group_layout.setContentsMargins(12, 12, 12, 12)
        self.config_group_layout.setSpacing(8)
        self.config_group_layout.addWidget(self.new_rules_only_toggle)
        self.config_group_layout.addWidget(self.total_counts_label)
        self.config_group_layout.addWidget(self.rule_tree)
        self.config_group.setLayout(self.config_group_layout)

        self.preset_view = QWidget()
        self.preset_view_layout = QVBoxLayout()
        self.preset_view_layout.setContentsMargins(0, 0, 0, 0)
        self.preset_view_layout.setSpacing(8)
        self.preset_view_layout.addWidget(self.preset_table)
        self.preset_button_row = QHBoxLayout()
        self.preset_button_row.addWidget(self.add_preset_button)
        self.preset_button_row.addWidget(self.remove_preset_button)
        self.preset_view_layout.addLayout(self.preset_button_row)
        self.preset_view.setLayout(self.preset_view_layout)

        self.general_view = QWidget()
        self.general_view_layout = QVBoxLayout()
        self.general_view_layout.setContentsMargins(0, 0, 0, 0)
        self.general_view_layout.setSpacing(10)
        self.general_title = QLabel("General Settings")
        self.general_desc = QLabel("Select global Sysmon settings and defaults.")
        self.general_desc.setWordWrap(True)
        self.general_group = QGroupBox("Global Settings")
        self.general_group_layout = QVBoxLayout()
        self.general_dns_checkbox = QCheckBox("Enable DNS Query Logging (Event 22)")
        self.general_hash_md5_checkbox = QCheckBox("Include MD5 in Hash Algorithms")
        self.general_hash_sha256_checkbox = QCheckBox("Include SHA256 in Hash Algorithms")
        self.general_hash_imphash_checkbox = QCheckBox("Include IMPHASH in Hash Algorithms")
        self.general_revocation_checkbox = QCheckBox("Check Revocation")
        self.general_copy_pe_checkbox = QCheckBox("Archive Executables (CopyOnDeletePE)")
        self.general_copy_sids_checkbox = QCheckBox("Archive by SIDs (CopyOnDeleteSIDs)")
        self.general_pipe_monitor_checkbox = QCheckBox("Monitor Named Pipes (Events 17/18)")
        self.general_wmi_monitor_checkbox = QCheckBox("Monitor WMI Events (19/20/21)")

        self.general_dns_checkbox.setChecked(True)
        self.general_hash_sha256_checkbox.setChecked(True)
        self.general_hash_imphash_checkbox.setChecked(True)
        self.general_revocation_checkbox.setChecked(True)
        self.general_pipe_monitor_checkbox.setChecked(True)
        self.general_wmi_monitor_checkbox.setChecked(True)

        self.general_group_layout.addWidget(self.general_dns_checkbox)
        self.general_group_layout.addWidget(self.general_hash_md5_checkbox)
        self.general_group_layout.addWidget(self.general_hash_sha256_checkbox)
        self.general_group_layout.addWidget(self.general_hash_imphash_checkbox)
        self.general_group_layout.addWidget(self.general_revocation_checkbox)
        self.general_group_layout.addWidget(self.general_copy_pe_checkbox)
        self.general_group_layout.addWidget(self.general_copy_sids_checkbox)
        self.general_group_layout.addWidget(self.general_pipe_monitor_checkbox)
        self.general_group_layout.addWidget(self.general_wmi_monitor_checkbox)
        self.general_group.setLayout(self.general_group_layout)
        self.apply_general_button = QPushButton("Apply")
        self.apply_general_button.setObjectName("positiveButton")
        self.apply_general_button.setMinimumHeight(40)
        self.general_view_layout.addWidget(self.general_title)
        self.general_view_layout.addWidget(self.general_desc)
        self.general_view_layout.addWidget(self.general_group)
        self.general_view_layout.addWidget(self.apply_general_button)
        self.general_view.setLayout(self.general_view_layout)

        self.layout.addWidget(self.title)
        self.layout.addLayout(self.group_row)
        self.layout.addLayout(self.rule_row_1)
        self.layout.addLayout(self.rule_row_2)
        self.layout.addLayout(self.action_row)
        self.layout.addWidget(self.preset_view)
        self.layout.addWidget(self.general_view)
        self.layout.addWidget(self.config_group)
        self.layout.setStretchFactor(self.config_group, 1)

        self.add_button.clicked.connect(self.add_rule)
        self.remove_button.clicked.connect(self.remove_selected_rule)
        self.add_preset_button.clicked.connect(self.add_selected_preset)
        self.remove_preset_button.clicked.connect(self.remove_selected_preset_rules)
        self.apply_general_button.clicked.connect(self.apply_general_settings)
        self.field_box.currentTextChanged.connect(self.load_value_presets_for_field)
        self.new_rules_only_toggle.stateChanged.connect(self.refresh_rules)
        self.rule_tree.itemClicked.connect(self.on_rule_tree_item_clicked)
        self.show_event_editor()

    def show_event_editor(self, event_id: int | None = None, event_name: str | None = None) -> None:
        self._set_event_mode_visible(True)
        self.preset_view.setVisible(False)
        self.general_view.setVisible(False)
        self.total_counts_label.setVisible(True)
        self.rule_tree.setColumnHidden(1, False)
        if event_id is not None and event_name is not None:
            self._set_active_event(event_id, event_name)
        self.refresh_rules()

    def show_preset_editor(self) -> None:
        self._set_event_mode_visible(False)
        self.preset_view.setVisible(True)
        self.general_view.setVisible(False)
        self.total_counts_label.setVisible(False)
        self.rule_tree.setColumnHidden(1, True)
        self.current_event_id = None
        self.current_event_name = ""
        self.title.setText("Recommended Presets")
        self.refresh_rules()

    def show_general_settings(self, setting_name: str | None = None) -> None:
        self._set_event_mode_visible(False)
        self.preset_view.setVisible(False)
        self.general_view.setVisible(True)
        self.total_counts_label.setVisible(False)
        self.rule_tree.setColumnHidden(1, True)
        self.current_event_id = None
        self.current_event_name = ""
        if setting_name:
            self.general_title.setText(f"General Settings - {setting_name}")
        else:
            self.general_title.setText("General Settings")
        self.refresh_rules()

    def _set_event_mode_visible(self, visible: bool) -> None:
        self.title.setVisible(visible)
        self.rule_type.setVisible(visible)
        self.group_box.setVisible(visible)
        self.group_relation.setVisible(visible)
        self.field_box.setVisible(visible)
        self.condition_box.setVisible(visible)
        self.value_preset_box.setVisible(visible)
        self.add_button.setVisible(visible)
        self.remove_button.setVisible(visible)

    def _load_preset_options(self) -> None:
        self.preset_table.setRowCount(len(SYS_MON_BASELINE_PRESETS))
        for row, preset in enumerate(SYS_MON_BASELINE_PRESETS):
            item = QTableWidgetItem(str(preset["name"]))
            item.setToolTip(str(preset["tooltip"]))
            self.preset_table.setItem(row, 0, item)

    def set_event(self, event_id: int, event_name: str) -> None:
        self.show_event_editor(event_id, event_name)

    def set_config(self, config: SysmonConfig) -> None:
        self.config = config

    def _set_active_event(self, event_id: int, event_name: str) -> None:
        self.current_event_id = event_id
        self.current_event_name = event_name
        self.title.setText(f"{event_id} - {event_name}")
        self.group_box.setEditText("")
        self.load_fields_for_event()
        self.refresh_group_options()

    def refresh_group_options(self) -> None:
        typed_text = self.group_box.currentText()
        self.group_box.blockSignals(True)
        self.group_box.clear()
        self.group_box.addItem("")

        if self.current_event_id is None:
            self.group_box.setEditText(typed_text)
            self.group_box.blockSignals(False)
            return

        event_config = self.config.events.get(self.current_event_id)
        if event_config is None:
            self.group_box.setEditText(typed_text)
            self.group_box.blockSignals(False)
            return

        group_labels: list[str] = []
        seen_group_ids: set[str] = set()
        for rule in event_config.rules:
            if not rule.group_id or rule.group_id in seen_group_ids:
                continue
            seen_group_ids.add(rule.group_id)

            group_name = (rule.group_name or "").strip()
            if group_name:
                group_relation = (rule.group_relation or "or").strip()
                group_labels.append(f"{group_name} ({group_relation})")

        self.group_box.addItems(group_labels)
        self.group_box.setEditText(typed_text)
        self.group_box.blockSignals(False)

    def _split_group_text(self, raw_text: str) -> tuple[str, str | None]:
        text = raw_text.strip()
        if text.endswith(")") and " (" in text:
            name_part, relation_part = text.rsplit(" (", 1)
            relation = relation_part[:-1].strip().lower()
            if relation in ("or", "and"):
                return name_part.strip(), relation
        return text, None

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
            self.value_preset_box.lineEdit().setPlaceholderText("...")
            return

        self.field_box.addItems(fields)
        self.field_box.setCurrentIndex(-1)
        self.field_box.setEditText("")
        self.value_preset_box.clear()
        self.value_preset_box.lineEdit().setPlaceholderText("...")
        self.value_preset_box.setEditText("")

    def load_value_presets_for_field(self, field_name: str) -> None:
        from data.sysmon_value_presets import SYS_MON_VALUE_PRESETS

        typed_value = self.value_preset_box.currentText()
        self.value_preset_box.clear()
        self.value_preset_box.addItem("")

        presets = SYS_MON_VALUE_PRESETS.get(field_name, [])
        if presets:
            self.value_preset_box.addItems(presets)
            self.value_preset_box.lineEdit().setPlaceholderText(str(presets[0]))
        else:
            self.value_preset_box.lineEdit().setPlaceholderText("...")

        self.value_preset_box.setCurrentIndex(-1)
        self.value_preset_box.setEditText(typed_value)

    def refresh_rules(self) -> None:
        self.rule_tree.clear()
        show_new_only = self.new_rules_only_toggle.isChecked()
        total_include = 0
        total_exclude = 0

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

            include_count = 0
            exclude_count = 0
            for rule_index in visible_rule_indexes:
                rule = event_config.rules[rule_index]
                if rule.rule_type == "include":
                    include_count += 1
                elif rule.rule_type == "exclude":
                    exclude_count += 1

            total_include += include_count
            total_exclude += exclude_count

            event_item = QTreeWidgetItem(
                [
                    f"{event_id} - {event_config.event_name}",
                    f"Include ({include_count})  Exclude ({exclude_count})",
                ]
            )
            event_item.setTextAlignment(1, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            event_item.setForeground(1, QColor("#90ee90"))  # light green counts
            event_item.setData(
                0,
                self.tree_meta_role,
                {"kind": "event", "event_id": event_id},
            )
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
                            [f"Rule: {group_name} ({group_relation})", ""]
                        )
                        grouped_parents[rule.group_id].setData(
                            0,
                            self.tree_meta_role,
                            {
                                "kind": "group",
                                "event_id": event_id,
                                "group_name": group_name,
                                "group_relation": group_relation,
                            },
                        )
                        event_item.addChild(grouped_parents[rule.group_id])
                    parent_item = grouped_parents[rule.group_id]
                else:
                    if ungrouped_parent is None:
                        ungrouped_parent = QTreeWidgetItem(["Ungrouped Rules", ""])
                        ungrouped_parent.setData(
                            0,
                            self.tree_meta_role,
                            {"kind": "ungrouped", "event_id": event_id},
                        )
                        event_item.addChild(ungrouped_parent)
                    parent_item = ungrouped_parent

                rule_text = (
                    f"{event_id} | "
                    f"{rule.rule_type} | "
                    f"{rule.field_name} | "
                    f"{rule.condition} | "
                    f"{rule.value}"
                )
                item = QTreeWidgetItem([rule_text, ""])
                item.setData(0, Qt.ItemDataRole.UserRole, (event_id, rule_index))
                item.setData(
                    0,
                    self.tree_meta_role,
                    {"kind": "rule", "event_id": event_id, "rule_index": rule_index},
                )

                if not rule.imported:
                    item.setBackground(0, QColor("#ffe6cc"))  # light orange

                parent_item.addChild(item)

            event_item.setExpanded(True)

        self.rule_tree.expandAll()
        self.total_counts_label.setText(
            f'Total Include <span style="color:#90ee90">({total_include})</span>  '
            f'Total Exclude <span style="color:#90ee90">({total_exclude})</span>'
        )

    def on_rule_tree_item_clicked(self, item: QTreeWidgetItem, _column: int) -> None:
        meta = item.data(0, self.tree_meta_role)
        if not isinstance(meta, dict):
            return

        kind = meta.get("kind")
        event_id = meta.get("event_id")
        if not isinstance(event_id, int):
            return

        event_config = self.config.events.get(event_id)
        if event_config is None:
            return

        self._set_active_event(event_id, event_config.event_name)

        if kind == "group":
            group_name = (meta.get("group_name") or "").strip()
            group_relation = (meta.get("group_relation") or "or").strip().lower()
            if group_name:
                self.group_box.setEditText(f"{group_name} ({group_relation})")
            else:
                self.group_box.setEditText("")
            if group_relation in ("or", "and"):
                self.group_relation.setCurrentText(group_relation)
            return

        if kind != "rule":
            return

        rule_index = meta.get("rule_index")
        if not isinstance(rule_index, int) or not (0 <= rule_index < len(event_config.rules)):
            return

        rule = event_config.rules[rule_index]
        self.rule_type.setCurrentText(rule.rule_type)
        self.field_box.setCurrentText(rule.field_name)
        self.condition_box.setCurrentText(rule.condition)

        if rule.group_name:
            relation = rule.group_relation or "or"
            self.group_box.setEditText(f"{rule.group_name} ({relation})")
            if relation in ("or", "and"):
                self.group_relation.setCurrentText(relation)
        else:
            self.group_box.setEditText("")

        self.value_preset_box.setCurrentText(rule.value)

    def add_rule(self) -> None:
        if self.current_event_id is None:
            return

        value = self.value_preset_box.currentText().strip()
        if not value:
            return

        previous_config = self.config.clone()

        event_config = self.config.get_or_create_event(
            self.current_event_id,
            self.current_event_name,
        )

        selected_group_text = self.group_box.currentText().strip()
        selected_group_name, selected_group_relation = self._split_group_text(selected_group_text)

        group_id: str | None = None
        group_name: str | None = None
        group_relation: str | None = None

        if selected_group_name:
            existing_group = None
            for existing_rule in event_config.rules:
                if not existing_rule.group_id:
                    continue
                if (existing_rule.group_name or "").strip().lower() == selected_group_name.lower():
                    existing_group = existing_rule
                    break

            if existing_group is not None:
                group_id = existing_group.group_id
                group_name = existing_group.group_name
                group_relation = (
                    existing_group.group_relation
                    or selected_group_relation
                    or self.group_relation.currentText()
                )
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

                group_name = selected_group_name
                group_relation = selected_group_relation or self.group_relation.currentText()

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

        self.value_preset_box.setEditText("")
        self.refresh_group_options()
        self.refresh_rules()
        if self.on_config_change is not None:
            self.on_config_change("Add Rule", previous_config)

    def remove_selected_rule(self) -> None:
        if self.current_event_id is None:
            return

        selected_items = self.rule_tree.selectedItems()
        if not selected_items:
            return

        to_delete: dict[int, set[int]] = {}
        for item in selected_items:
            rule_key = item.data(0, Qt.ItemDataRole.UserRole)
            if not isinstance(rule_key, tuple) or len(rule_key) != 2:
                continue
            event_id, rule_index = rule_key
            if not isinstance(event_id, int) or not isinstance(rule_index, int):
                continue
            to_delete.setdefault(event_id, set()).add(rule_index)

        if not to_delete:
            return

        previous_config = self.config.clone()
        deleted_count = 0

        for event_id, indexes in to_delete.items():
            event_config = self.config.events.get(event_id)
            if event_config is None:
                continue
            for rule_index in sorted(indexes, reverse=True):
                if 0 <= rule_index < len(event_config.rules):
                    del event_config.rules[rule_index]
                    deleted_count += 1

        self.refresh_group_options()
        self.refresh_rules()
        if deleted_count > 0 and self.on_config_change is not None:
            self.on_config_change("Remove Rule", previous_config)

    def add_selected_preset(self) -> None:
        selected_rows = sorted(
            {index.row() for index in self.preset_table.selectionModel().selectedRows()}
        )
        if not selected_rows:
            QMessageBox.information(
                self,
                "Select Preset",
                "Select one or more preset options first (Ctrl+Click for multi-select).",
            )
            return

        from data.sysmon_fields import SYS_MON_FIELDS

        rules_added = 0
        previous_config: SysmonConfig | None = None
        target_events = (
            [(self.current_event_id, self.current_event_name)]
            if self.current_event_id is not None
            else [(event_id, event_name) for event_id, event_name in sorted(SYS_MON_EVENTS.items())]
        )

        for target_event_id, target_event_name in target_events:
            event_fields = set(SYS_MON_FIELDS.get(target_event_id, []))
            event_config = self.config.get_or_create_event(target_event_id, target_event_name)
            existing_rule_keys = {
                (
                    rule.rule_type,
                    rule.field_name,
                    rule.condition,
                    rule.value.strip().lower(),
                    rule.group_id,
                    rule.group_name,
                    rule.group_relation,
                )
                for rule in event_config.rules
            }

            for row in selected_rows:
                if not (0 <= row < len(SYS_MON_BASELINE_PRESETS)):
                    continue
                preset = SYS_MON_BASELINE_PRESETS[row]
                preset_name = str(preset["name"])
                preset_group_id = f"preset-{row + 1}"

                for rule_type, field_name, condition, value in preset["rules"]:  # type: ignore[index]
                    if field_name not in event_fields:
                        continue

                    key = (
                        str(rule_type),
                        str(field_name),
                        str(condition),
                        str(value).strip().lower(),
                        preset_group_id,
                        preset_name,
                        "or",
                    )
                    if key in existing_rule_keys:
                        continue
                    existing_rule_keys.add(key)
                    if previous_config is None:
                        previous_config = self.config.clone()

                    event_config.rules.append(
                        RuleFilter(
                            rule_type=str(rule_type),
                            field_name=str(field_name),
                            condition=str(condition),
                            value=str(value),
                            group_id=preset_group_id,
                            group_name=preset_name,
                            group_relation="or",
                        )
                    )
                    rules_added += 1

        if rules_added == 0:
            QMessageBox.information(
                self,
                "Preset Not Applied",
                "No compatible new rules were found for this event. Try another Event ID.",
            )
            return

        self.refresh_group_options()
        self.refresh_rules()
        if previous_config is not None and self.on_config_change is not None:
            self.on_config_change("Add Preset Rules", previous_config)

    def remove_selected_preset_rules(self) -> None:
        selected_rows = sorted(
            {index.row() for index in self.preset_table.selectionModel().selectedRows()}
        )
        if not selected_rows:
            QMessageBox.information(
                self,
                "Select Preset",
                "Select one or more preset options first (Ctrl+Click for multi-select).",
            )
            return

        group_ids_to_remove = {f"preset-{row + 1}" for row in selected_rows}
        previous_config: SysmonConfig | None = None
        removed = 0
        for event_config in self.config.events.values():
            original = len(event_config.rules)
            if previous_config is None and any(
                (rule.group_id or "") in group_ids_to_remove for rule in event_config.rules
            ):
                previous_config = self.config.clone()
            event_config.rules = [
                rule for rule in event_config.rules if (rule.group_id or "") not in group_ids_to_remove
            ]
            removed += original - len(event_config.rules)

        if removed == 0:
            QMessageBox.information(self, "No Changes", "No matching preset rules were found to remove.")
            return

        self.refresh_group_options()
        self.refresh_rules()
        if previous_config is not None and self.on_config_change is not None:
            self.on_config_change("Remove Preset Rules", previous_config)

    def apply_general_settings(self) -> None:
        QMessageBox.information(
            self,
            "General Settings Applied",
            "General settings have been applied in the UI context.",
        )
