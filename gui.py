import sys
import asyncio
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QFormLayout, QLineEdit, QSpinBox, QCheckBox,
                             QPushButton, QPlainTextEdit, QHBoxLayout)
from PyQt6.QtCore import QObject, pyqtSignal, QThread

# Import the core logic from our refactored main.py
from main import run_scan_logic, display_banner

class Stream(QObject):
    """Custom stream object to redirect console output to a Qt widget."""
    newText = pyqtSignal(str)

    def write(self, text):
        self.newText.emit(str(text))

    def flush(self):
        pass

class ScanThread(QThread):
    """Runs the asyncio scan logic in a separate thread."""
    def __init__(self, args_dict):
        super().__init__()
        self.args_dict = args_dict

    def run(self):
        try:
            # Each thread needs its own asyncio event loop
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(run_scan_logic(self.args_dict))
            loop.close()
        except Exception as e:
            # Emit the exception to be displayed in the GUI
            # The custom stream will handle this
            print(f"[bold red]An error occurred in the scan thread: {e}[/bold red]")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SQLi Hunter")
        self.setGeometry(100, 100, 900, 700)

        # --- Layouts ---
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        self.form_layout = QFormLayout()
        self.button_layout = QHBoxLayout()

        # --- Input Widgets ---
        self.url_input = QLineEdit("https://radio.espressolab.com/")
        self.depth_input = QSpinBox()
        self.depth_input.setValue(2)
        self.cookie_input = QLineEdit()
        self.json_report_input = QLineEdit("scan_report.json")

        self.no_crawl_checkbox = QCheckBox("Scan only the provided URL")
        self.dump_db_checkbox = QCheckBox("Attempt to dump data")
        self.dump_db_checkbox.setChecked(True)
        self.debug_checkbox = QCheckBox("Enable debug logging")

        self.form_layout.addRow("Target URL:", self.url_input)
        self.form_layout.addRow("Crawl Depth:", self.depth_input)
        self.form_layout.addRow("Cookie:", self.cookie_input)
        self.form_layout.addRow("JSON Report File:", self.json_report_input)
        self.form_layout.addRow(self.no_crawl_checkbox)
        self.form_layout.addRow(self.dump_db_checkbox)
        self.form_layout.addRow(self.debug_checkbox)

        # --- Log Output ---
        self.log_output = QPlainTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setStyleSheet("background-color: #0d1117; color: #e6edf3; font-family: 'Courier New';")

        # --- Buttons ---
        self.start_button = QPushButton("Start Scan")
        self.start_button.clicked.connect(self.start_scan)
        self.button_layout.addWidget(self.start_button)

        # --- Assemble Main Layout ---
        self.main_layout.addLayout(self.form_layout)
        self.main_layout.addLayout(self.button_layout)
        self.main_layout.addWidget(self.log_output)

        # --- Redirect stdout/stderr ---
        self.stream = Stream()
        self.stream.newText.connect(self.on_new_text)
        sys.stdout = self.stream
        sys.stderr = self.stream

    def on_new_text(self, text):
        self.log_output.moveCursor(self.log_output.textCursor().End)
        self.log_output.insertPlainText(text)

    def start_scan(self):
        self.start_button.setEnabled(False)
        self.log_output.clear()

        # Gather args from the GUI
        args = {
            "url": self.url_input.text(),
            "depth": self.depth_input.value(),
            "no_crawl": self.no_crawl_checkbox.isChecked(),
            "dump_db": self.dump_db_checkbox.isChecked(),
            "cookie": self.cookie_input.text(),
            "json_report": self.json_report_input.text(),
            "debug": self.debug_checkbox.isChecked(),
            "n_calls": 25, # Hardcoded for now
            "collaborator": None, # Hardcoded for now
            "retest": None # Hardcoded for now
        }

        # Run the scan in a separate thread
        self.scan_thread = ScanThread(args)
        self.scan_thread.finished.connect(self.scan_finished)
        self.scan_thread.start()

    def scan_finished(self):
        self.start_button.setEnabled(True)
        print("\n--- GUI: Scan thread finished. ---")

    def closeEvent(self, event):
        # Restore stdout/stderr on close
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__
        super().closeEvent(event)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
