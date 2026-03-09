from exporters.xml_exporter import export_config
from importers.xml_importer import import_config
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
        self.theme_button = QPushButton("Toggle Theme")
        self.theme_button.clicked.connect(self.toggle_theme)
        outer_layout.addWidget(self.theme_button)
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

        button_layout.addWidget(self.import_button)
        button_layout.addWidget(self.save_button)

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
        
    def toggle_theme(self):
        toggle(self.app)