from gui.rule_editor import RuleEditor
from models.sysmon_config import SysmonConfig
from PySide6.QtWidgets import (
    QHBoxLayout,
    QListWidget,
    QMainWindow,
    QWidget,
)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()

        self.setWindowTitle("Sysmon Config Builder")
        self.setGeometry(100, 100, 1000, 600)

        self.event_map: dict[int, str] = {
            1: "Process Create",
            3: "Network Connection",
            7: "Image Load",
            11: "File Create",
            13: "Registry Value Set",
        }

        self.config = SysmonConfig()

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QHBoxLayout()
        central_widget.setLayout(main_layout)

        self.event_list = QListWidget()
        for event_id, event_name in self.event_map.items():
            self.event_list.addItem(f"{event_id} - {event_name}")

        self.event_list.currentTextChanged.connect(self.on_event_selected)

        self.rule_editor = RuleEditor(self.config)

        main_layout.addWidget(self.event_list, 1)
        main_layout.addWidget(self.rule_editor, 3)

        self.event_list.setCurrentRow(0)

    def on_event_selected(self, event_text: str) -> None:
        event_id_str, event_name = event_text.split(" - ", 1)
        self.rule_editor.set_event(int(event_id_str), event_name)