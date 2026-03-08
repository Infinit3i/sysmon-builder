from exporters.xml_exporter import export_config
from gui.rule_editor import RuleEditor
from models.sysmon_config import SysmonConfig
from data.sysmon_events import SYS_MON_EVENTS
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
    def __init__(self) -> None:
        super().__init__()

        self.setWindowTitle("Sysmon Config Builder")
        self.setGeometry(100, 100, 1000, 600)
        
        self.event_map = SYS_MON_EVENTS

        self.config = SysmonConfig()

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        outer_layout = QVBoxLayout()
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

        self.save_button = QPushButton("Save XML")
        self.save_button.clicked.connect(self.save_xml)
        outer_layout.addWidget(self.save_button)

        self.event_list.setCurrentRow(0)

    def on_event_selected(self, event_text: str) -> None:
        event_id_str, event_name = event_text.split(" - ", 1)
        self.rule_editor.set_event(int(event_id_str), event_name)

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