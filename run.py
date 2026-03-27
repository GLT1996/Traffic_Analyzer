#!/usr/bin/env python3
"""Run the Network Traffic Analyzer."""

if __name__ == "__main__":
    import sys
    import os

    # Add src to path
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    # Import and run
    from PyQt6.QtWidgets import QApplication
    from src.ui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("Network Traffic Analyzer")

    window = MainWindow()
    window.show()

    sys.exit(app.exec())