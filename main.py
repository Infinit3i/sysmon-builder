import sys
from PySide6.QtWidgets import QApplication
from gui.main_window import MainWindow
from gui.toggle_theme import apply_dark, system_is_dark


def main():
    app = QApplication(sys.argv)
    if system_is_dark(app):
        apply_dark(app)

    window = MainWindow(app)
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()