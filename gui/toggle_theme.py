from PySide6.QtGui import QPalette, QColor
from PySide6.QtCore import Qt


def system_is_dark(app) -> bool:
    palette = app.palette()
    return palette.color(QPalette.Window).lightness() < 128


def apply_dark(app):
    palette = QPalette()

    palette.setColor(QPalette.Window, QColor(53, 53, 53))
    palette.setColor(QPalette.WindowText, Qt.white)
    palette.setColor(QPalette.Base, QColor(35, 35, 35))
    palette.setColor(QPalette.Text, Qt.white)
    palette.setColor(QPalette.Button, QColor(53, 53, 53))
    palette.setColor(QPalette.ButtonText, Qt.white)

    app.setPalette(palette)


def apply_light(app):
    app.setPalette(app.style().standardPalette())


def toggle(app):
    if system_is_dark(app):
        apply_light(app)
    else:
        apply_dark(app)