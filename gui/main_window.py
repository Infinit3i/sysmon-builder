from exporters.xml_exporter import export_config
from importers.xml_importer import import_config
from importers.powershell_script_generator import ensure_ps_scripts
from importers.powershell_live_importer import import_live_system_state
from pathlib import Path
from gui.baseline_options_dialog import BaselineOptions, BaselineOptionsDialog
from gui.rule_editor import RuleEditor
from models.sysmon_config import SysmonConfig
from data.sysmon_events import SYS_MON_EVENTS
from gui.toggle_theme import toggle
from PySide6.QtCore import QObject, QThread, Signal, Qt
from PySide6.QtWidgets import (
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QProgressDialog,
    QPushButton,
    QVBoxLayout,
    QWidget,
    QSpacerItem,
    QSizePolicy,
)


class BaselineWorker(QObject):
    progress = Signal(str)
    finished = Signal(object)
    failed = Signal(str)

    def __init__(self, options: BaselineOptions) -> None:
        super().__init__()
        self.options = options

    def run(self) -> None:
        try:
            self.progress.emit("Step 1/2: Generating PowerShell scripts...")
            ensure_ps_scripts()

            self.progress.emit("Step 2/2: Importing live system baseline...")
            config = import_live_system_state(
                enabled_sources=self.options.enabled_sources,
                selected_event_ids=self.options.selected_event_ids,
                event_rule_modes=self.options.event_rule_modes,
                status_callback=self.progress.emit,
            )
            self.finished.emit(config)
        except Exception as exc:
            self.failed.emit(str(exc))


class MainWindow(QMainWindow):
    def __init__(self, app) -> None:
        self.app = app
        super().__init__()
        self.progress_dialog = None
        self.worker_thread = None
        self.worker = None

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
        self._populate_navigation_list()
        self.event_list.currentItemChanged.connect(self.on_nav_selected)

        self.rule_editor = RuleEditor(self.config)

        main_layout.addWidget(self.event_list, 1)
        main_layout.addWidget(self.rule_editor, 3)

        button_layout = QHBoxLayout()

        self.import_button = QPushButton("Import XML")
        self.import_button.clicked.connect(self.import_xml)

        self.save_button = QPushButton("Save XML")
        self.save_button.clicked.connect(self.save_xml)

        self.baseline_button = QPushButton("Baseline Live System")
        self.baseline_button.clicked.connect(self.run_baseline_workflow)

        button_layout.addWidget(self.import_button)
        button_layout.addWidget(self.save_button)
        button_layout.addWidget(self.baseline_button)

        outer_layout.addLayout(button_layout)

        self._set_default_nav_selection()
        self._apply_modern_styles()

    def _populate_navigation_list(self) -> None:
        self.event_list.clear()

        section_general = QListWidgetItem("General Settings")
        section_general.setData(Qt.ItemDataRole.UserRole, {"kind": "general"})
        self.event_list.addItem(section_general)

        section_presets = QListWidgetItem("Recommended Presets")
        section_presets.setData(Qt.ItemDataRole.UserRole, {"kind": "presets"})
        self.event_list.addItem(section_presets)

        for event_id, event_name in self.event_map.items():
            item = QListWidgetItem(f"{event_id} - {event_name}")
            item.setData(
                Qt.ItemDataRole.UserRole,
                {"kind": "event", "event_id": event_id, "event_name": event_name},
            )
            self.event_list.addItem(item)

    def _set_default_nav_selection(self) -> None:
        for row in range(self.event_list.count()):
            item = self.event_list.item(row)
            meta = item.data(Qt.ItemDataRole.UserRole)
            if isinstance(meta, dict) and meta.get("kind") == "event" and meta.get("event_id") == 1:
                self.event_list.setCurrentRow(row)
                return
        self.event_list.setCurrentRow(0)

    def on_nav_selected(self, current: QListWidgetItem | None, _previous: QListWidgetItem | None) -> None:
        if current is None:
            return

        meta = current.data(Qt.ItemDataRole.UserRole)
        if not isinstance(meta, dict):
            return

        kind = meta.get("kind")
        if kind == "event":
            event_id = meta.get("event_id")
            event_name = meta.get("event_name")
            if isinstance(event_id, int) and isinstance(event_name, str):
                self.rule_editor.set_event(event_id, event_name)
            return

        if kind == "presets":
            self.rule_editor.show_preset_editor()
            return

        if kind == "general":
            self.rule_editor.show_general_settings()

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

    def run_baseline_workflow(self) -> None:
        options_dialog = BaselineOptionsDialog(self)
        if options_dialog.exec() != QDialog.DialogCode.Accepted:
            return

        options = options_dialog.get_options()
        if not options.enabled_sources:
            QMessageBox.warning(self, "Missing Selection", "Select at least one baseline source.")
            return
        if not options.selected_event_ids:
            QMessageBox.warning(self, "Missing Selection", "Select at least one Event ID.")
            return

        self.progress_dialog = QProgressDialog("Preparing baseline...", "", 0, 0, self)
        self.progress_dialog.setWindowTitle("Baselining")
        self.progress_dialog.setCancelButton(None)
        self.progress_dialog.setWindowModality(Qt.WindowModality.WindowModal)
        self.progress_dialog.setMinimumDuration(0)
        self.progress_dialog.show()

        self.baseline_button.setEnabled(False)
        self.worker_thread = QThread(self)
        self.worker = BaselineWorker(options)
        self.worker.moveToThread(self.worker_thread)

        self.worker_thread.started.connect(self.worker.run)
        self.worker.progress.connect(self._on_baseline_progress)
        self.worker.finished.connect(self._on_baseline_finished)
        self.worker.failed.connect(self._on_baseline_failed)

        self.worker.finished.connect(self.worker_thread.quit)
        self.worker.failed.connect(self.worker_thread.quit)
        self.worker_thread.finished.connect(self.worker.deleteLater)
        self.worker_thread.finished.connect(self.worker_thread.deleteLater)

        self.worker_thread.start()

    def _on_baseline_progress(self, text: str) -> None:
        if hasattr(self, "progress_dialog") and self.progress_dialog is not None:
            self.progress_dialog.setLabelText(text)

    def _on_baseline_finished(self, imported_config: SysmonConfig) -> None:
        imported_events, imported_rules = self._merge_config_rules(imported_config)
        self.rule_editor.refresh_rules()

        if hasattr(self, "progress_dialog") and self.progress_dialog is not None:
            self.progress_dialog.close()
            self.progress_dialog = None

        self.baseline_button.setEnabled(True)
        QMessageBox.information(
            self,
            "Baseline Complete",
            f"Imported {imported_rules} rules across {imported_events} events.",
        )

    def _on_baseline_failed(self, error_text: str) -> None:
        if hasattr(self, "progress_dialog") and self.progress_dialog is not None:
            self.progress_dialog.close()
            self.progress_dialog = None

        self.baseline_button.setEnabled(True)
        QMessageBox.critical(self, "Baseline Failed", f"Failed to baseline live system data:\n{error_text}")

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

    def _apply_modern_styles(self) -> None:
        style_path = Path(__file__).resolve().parent.parent / "assets" / "style.qss"
        if style_path.exists():
            self.setStyleSheet(style_path.read_text(encoding="utf-8"))
