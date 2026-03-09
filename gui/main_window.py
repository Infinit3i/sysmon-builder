from exporters.xml_exporter import export_config
from importers.xml_importer import import_config
from importers.powershell_script_generator import ensure_ps_scripts
from importers.powershell_live_importer import import_live_system_state
from gui.rule_editor import RuleEditor
from models.sysmon_config import SysmonConfig
from data.sysmon_events import SYS_MON_EVENTS
from gui.toggle_theme import toggle
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
    QSpacerItem,
    QSizePolicy,
)

class MainWindow(QMainWindow):
    def __init__(self, app) -> None:
        self.app = app
        super().__init__()

        self.setWindowTitle("Sysmon Config Builder")
        self.setGeometry(100, 100, 1000, 600)
        self.event_map = SYS_MON_EVENTS
        self.config = SysmonConfig()

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        outer_layout = QVBoxLayout()
        
        top_bar = QHBoxLayout()

        spacer = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)

        self.theme_button = QPushButton("☀")
        self.theme_button.setFixedSize(32, 32)
        self.theme_button.clicked.connect(self.toggle_theme)

        top_bar.addItem(spacer)
        top_bar.addWidget(self.theme_button)

        outer_layout.addLayout(top_bar)
        central_widget.setLayout(outer_layout)

        main_layout = QHBoxLayout()
        outer_layout.addLayout(main_layout)

        self.event_list = QListWidget()
        for event_id, event_name in self.event_map.items():
            self.event_list.addItem(f"{event_id} - {event_name}")

        self.event_list.currentTextChanged.connect(self.on_event_selected)

        self.rule_editor = RuleEditor(self.config)

        main_layout.addWidget(self.event_list, 1)
        main_layout.addWidget(self.rule_editor, 3)

        button_layout = QHBoxLayout()

        self.import_button = QPushButton("Import XML")
        self.import_button.clicked.connect(self.import_xml)

        self.save_button = QPushButton("Save XML")
        self.save_button.clicked.connect(self.save_xml)

        self.generate_ps_button = QPushButton("Generate PS Scripts")
        self.generate_ps_button.clicked.connect(self.generate_ps_scripts)

        self.import_live_button = QPushButton("Import Live Windows Data")
        self.import_live_button.clicked.connect(self.import_live_data)

        button_layout.addWidget(self.import_button)
        button_layout.addWidget(self.save_button)
        button_layout.addWidget(self.generate_ps_button)
        button_layout.addWidget(self.import_live_button)

        outer_layout.addLayout(button_layout)

        self.event_list.setCurrentRow(0)

    def on_event_selected(self, event_text: str) -> None:
        event_id_str, event_name = event_text.split(" - ", 1)
        self.rule_editor.set_event(int(event_id_str), event_name)

    def import_xml(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Import Sysmon Config",
            "",
            "XML Files (*.xml)",
        )

        if not file_path:
            return

        try:
            imported_config = import_config(file_path)
            self.config.events = imported_config.events
            self.rule_editor.config = self.config
            self.rule_editor.refresh_rules()
        except Exception as exc:
            QMessageBox.critical(self, "Import Failed", f"Failed to import XML:\n{exc}")
            return

        QMessageBox.information(self, "Success", f"Imported Sysmon config from:\n{file_path}")

    def save_xml(self) -> None:
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Sysmon Config",
            "sysmon_config.xml",
            "XML Files (*.xml)",
        )

        if not file_path:
            return

        try:
            export_config(self.config, file_path)
        except Exception as exc:
            QMessageBox.critical(self, "Save Failed", f"Failed to save XML:\n{exc}")
            return

        QMessageBox.information(self, "Success", f"Saved Sysmon config to:\n{file_path}")

    def generate_ps_scripts(self) -> None:
        try:
            created_paths = ensure_ps_scripts()
        except Exception as exc:
            QMessageBox.critical(self, "Script Generation Failed", f"Failed to generate scripts:\n{exc}")
            return

        output_dir = created_paths[0].parent if created_paths else "importers/ps1"
        QMessageBox.information(
            self,
            "Scripts Generated",
            f"Generated {len(created_paths)} PowerShell scripts in:\n{output_dir}",
        )

    def import_live_data(self) -> None:
        try:
            imported_config = import_live_system_state()
            imported_events, imported_rules = self._merge_config_rules(imported_config)
            self.rule_editor.refresh_rules()
        except Exception as exc:
            QMessageBox.critical(self, "Live Import Failed", f"Failed to import live system data:\n{exc}")
            return

        QMessageBox.information(
            self,
            "Live Import Complete",
            f"Imported {imported_rules} rules across {imported_events} events from live system data.",
        )

    def _merge_config_rules(self, incoming: SysmonConfig) -> tuple[int, int]:
        imported_event_count = 0
        imported_rule_count = 0

        for event_id, incoming_event in incoming.events.items():
            target_event = self.config.get_or_create_event(event_id, incoming_event.event_name)

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
                for rule in target_event.rules
            }

            event_rules_added = 0
            for rule in incoming_event.rules:
                rule_key = (
                    rule.rule_type,
                    rule.field_name,
                    rule.condition,
                    rule.value.strip().lower(),
                    rule.group_id,
                    rule.group_name,
                    rule.group_relation,
                )
                if rule_key in existing_rule_keys:
                    continue

                existing_rule_keys.add(rule_key)
                target_event.rules.append(rule)
                event_rules_added += 1
                imported_rule_count += 1

            if event_rules_added > 0:
                imported_event_count += 1

        return imported_event_count, imported_rule_count
        
    def toggle_theme(self):
        toggle(self.app)

        if self.theme_button.text() == "☀":
            self.theme_button.setText("🌙")
        else:
            self.theme_button.setText("☀")
