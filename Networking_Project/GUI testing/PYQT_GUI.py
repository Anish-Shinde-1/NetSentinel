from PyQt5 import QtWidgets, QtGui, QtCore

class FirewallGUI(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Firewall Management")
        self.setGeometry(100, 100, 900, 550)
        self.setStyleSheet("background-color: #1E1E2E; color: #00FFFF;")
        
        layout = QtWidgets.QVBoxLayout(self)
        
        # Greeting
        self.greeting = QtWidgets.QLabel("Hi Ankit")
        self.greeting.setStyleSheet("font-size: 14pt; font-weight: bold;")
        layout.addWidget(self.greeting)
        
        # Input Section
        input_frame = QtWidgets.QFrame()
        input_frame.setStyleSheet("border: 1px solid #444; padding: 10px;")
        input_layout = QtWidgets.QGridLayout(input_frame)
        
        self.endpoint_combo = QtWidgets.QComboBox()
        self.endpoint_combo.addItem("Select Endpoint")
        self.ip_entry = QtWidgets.QLineEdit()
        self.ip_entry.setPlaceholderText("Enter IP Address")
        self.app_entry = QtWidgets.QLineEdit()
        self.app_entry.setPlaceholderText("App Name")
        self.domain_entry = QtWidgets.QLineEdit()
        self.domain_entry.setPlaceholderText("Domain")
        self.action_combo = QtWidgets.QComboBox()
        self.action_combo.addItems(["Block", "Allow"])
        self.add_rule_btn = QtWidgets.QPushButton("Add Rule")
        self.add_rule_btn.setStyleSheet("background-color: #00FF00; color: black; padding: 5px;")
        
        input_layout.addWidget(self.endpoint_combo, 0, 0)
        input_layout.addWidget(self.ip_entry, 0, 1)
        input_layout.addWidget(self.app_entry, 0, 2)
        input_layout.addWidget(self.domain_entry, 0, 3)
        input_layout.addWidget(self.action_combo, 1, 0)
        input_layout.addWidget(self.add_rule_btn, 1, 1, 1, 3)
        
        layout.addWidget(input_frame)
        
        # Firewall Rules Table
        self.firewall_table = QtWidgets.QTableWidget()
        self.firewall_table.setColumnCount(6)
        self.firewall_table.setHorizontalHeaderLabels(["ID", "Application Name", "IP Address", "Domain", "Action", "Actions"])
        self.firewall_table.setStyleSheet("border: 1px solid #444;")
        layout.addWidget(QtWidgets.QLabel("Firewall Rules"))
        layout.addWidget(self.firewall_table)
        
        # Connected Endpoints Table
        self.endpoints_table = QtWidgets.QTableWidget()
        self.endpoints_table.setColumnCount(3)
        self.endpoints_table.setHorizontalHeaderLabels(["Name", "IP Address", "Action"])
        self.endpoints_table.setStyleSheet("border: 1px solid #444;")
        layout.addWidget(QtWidgets.QLabel("Connected Endpoints"))
        layout.addWidget(self.endpoints_table)
        
        self.setLayout(layout)

if __name__ == "__main__":
    app = QtWidgets.QApplication([])
    window = FirewallGUI()
    window.show()
    app.exec_()
