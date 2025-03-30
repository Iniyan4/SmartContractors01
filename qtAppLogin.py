import sys
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QTableWidget,
    QTableWidgetItem, QMessageBox, QFormLayout, QDialog,
    QDialogButtonBox, QComboBox, QListWidget
)
from models import Session, User, Patient, MedicalRecord
from blockchain import Blockchain
from cryptography.fernet import Fernet
import hashlib
from predict import predict_disease

fernet = Fernet(Fernet.generate_key())

class LoginDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Login")
        layout = QVBoxLayout()

        self.username = QLineEdit()
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.authenticate)
        buttons.rejected.connect(self.reject)

        layout.addWidget(QLabel("Username:"))
        layout.addWidget(self.username)
        layout.addWidget(QLabel("Password:"))
        layout.addWidget(self.password)
        layout.addWidget(buttons)

        self.setLayout(layout)
        self.user = None

    def authenticate(self):
        session = Session()
        user = session.query(User).filter_by(username=self.username.text()).first()
        if user and user.check_password(self.password.text()):
            self.user = user
            self.accept()
        else:
            QMessageBox.warning(self, "Error", "Invalid credentials")
        session.close()

class HealthcareApp(QMainWindow):
    def __init__(self, user):
        super().__init__()
        self.patient_table = QTableWidget()
        self.user = user
        self.session = Session()
        self.blockchain = Blockchain()
        self.init_ui()
        self.load_data()
        self.init_fab()

    def init_ui(self):
        self.setWindowTitle(f"Healthcare System - {self.user.username}")
        self.setGeometry(100, 100, 1200, 800)

        tabs = QTabWidget()

        if self.user.role == 'admin':
            tabs.addTab(self.create_admin_dashboard(), "Admin Dashboard")
            tabs.addTab(self.create_provider_registration_tab(), "Manage Providers")
        else:
            tabs.addTab(self.create_provider_dashboard(), "Provider Dashboard")

        tabs.addTab(self.create_blockchain_view(), "Blockchain View")

        self.setCentralWidget(tabs)

    def create_admin_dashboard(self):
        tab = QWidget()
        layout = QVBoxLayout()

        # Provider Selection
        self.provider_combo = QComboBox()
        self.provider_combo.currentIndexChanged.connect(self.load_patients_for_provider)
        self.load_providers()

        # Patient Table
        self.patient_table = QTableWidget()
        self.patient_table.setColumnCount(3)
        self.patient_table.setHorizontalHeaderLabels(["ID", "Name", "Created Date"])
        self.patient_table.setRowCount(0)  # Ensure the table starts empty

        layout.addWidget(QLabel("Select Provider:"))
        layout.addWidget(self.provider_combo)
        layout.addWidget(QLabel("Provider's Patients:"))
        layout.addWidget(self.patient_table)

        tab.setLayout(layout)
        return tab

    def create_provider_dashboard(self):
        tab = QWidget()
        layout = QVBoxLayout()

        # Initialize the patients table
        self.my_patients_table = QTableWidget()  # Correct attribute name
        self.my_patients_table.setColumnCount(4)
        self.my_patients_table.setHorizontalHeaderLabels([
            "ID", "Name", "Created Date", "Last Updated"
        ])

        # Patient registration form
        self.patient_name = QLineEdit()
        self.medical_data = QTextEdit()
        register_btn = QPushButton("Register Patient")
        register_btn.clicked.connect(self.register_patient)

        # Add components to layout
        layout.addWidget(QLabel("Patient Name:"))
        layout.addWidget(self.patient_name)
        layout.addWidget(QLabel("Medical Data:"))
        layout.addWidget(self.medical_data)
        layout.addWidget(register_btn)
        layout.addWidget(QLabel("My Patients:"))
        layout.addWidget(self.my_patients_table)

        tab.setLayout(layout)
        return tab

    def create_provider_registration_tab(self):
        tab = QWidget()
        layout = QFormLayout()

        self.prov_username = QLineEdit()
        self.prov_password = QLineEdit()
        self.prov_password.setEchoMode(QLineEdit.EchoMode.Password)
        register_btn = QPushButton("Register Provider")
        register_btn.clicked.connect(self.register_provider)

        layout.addRow("Username:", self.prov_username)
        layout.addRow("Password:", self.prov_password)
        layout.addRow(register_btn)

        tab.setLayout(layout)
        return tab

    def create_blockchain_view(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.blockchain_table = QTableWidget()
        self.blockchain_table.setColumnCount(5)
        headers = ["Index", "Timestamp", "Action", "Patient ID", "Provider ID"]
        if self.user.role == 'admin':
            headers.append("Hash")
        self.blockchain_table.setHorizontalHeaderLabels(headers)
        self.update_blockchain_view()

        layout.addWidget(self.blockchain_table)
        tab.setLayout(layout)
        return tab

    def register_patient(self):
        if self.user.role != 'provider':
            QMessageBox.critical(self, "Error", "Unauthorized action!")
            return

        name = self.patient_name.text()
        plaintext_data = self.medical_data.toPlainText()

        if not name or not plaintext_data:
            QMessageBox.warning(self, "Error", "All fields are required!")
            return

        try:
            # Generate patient ID
            patient_id = hashlib.sha256(name.encode()).hexdigest()

            # Create patient
            patient = Patient(
                id=patient_id,
                name=name,
                provider_id=self.user.id
            )

            # Create and configure medical record
            record = MedicalRecord()
            record.set_data(plaintext_data)  # Encrypts and sets hash
            record.patient = patient

            # Generate record ID from encrypted data hash
            record.id = hashlib.sha256(record.encrypted_data.encode()).hexdigest()

            self.session.add(patient)
            self.session.add(record)
            self.session.commit()

            # Add to blockchain
            self.blockchain.add_block({
                "action": "patient_registration",
                "patient_id": patient_id,
                "provider_id": self.user.id
            })

            self.blockchain.save_to_disk()

            QMessageBox.information(self, "Success", "Patient registered!")
            self.load_my_patients()
            self.update_blockchain_view()
            self.clear_registration_form()

        except Exception as e:
            self.session.rollback()
            QMessageBox.critical(self, "Error", str(e))

    def register_provider(self):
        if self.user.role != 'admin':
            QMessageBox.critical(self, "Error", "Unauthorized action!")
            return

        username = self.prov_username.text()
        password = self.prov_password.text()

        if not username or not password:
            QMessageBox.warning(self, "Error", "All fields are required!")
            return

        try:
            provider_id = hashlib.sha256(username.encode()).hexdigest()
            provider = User(
                id=provider_id,
                username=username,
                role='provider'
            )
            provider.set_password(password)

            self.session.add(provider)
            self.session.commit()

            self.blockchain.add_block({
                "action": "provider_registration",
                "provider_id": provider_id,
                "by_admin": self.user.id
            })
            self.blockchain.save_to_disk()
            QMessageBox.information(self, "Success", "Provider registered!")
            self.clear_provider_form()

        except Exception as e:
            self.session.rollback()
            QMessageBox.critical(self, "Error", str(e))

    def load_data(self):
        if self.user.role == 'admin':
            self.load_all_patients()
            self.load_providers()
        else:
            self.load_my_patients()

    def load_providers(self):

        self.provider_combo.clear()
        self.provider_combo.addItem("None", None)
        providers = self.session.query(User).filter_by(role='provider').all()

        for provider in providers:
            self.provider_combo.addItem(
                f"{provider.username}",
                provider.id  # Store provider ID as user data
            )

    def load_patients_for_provider(self):
        provider_id = self.provider_combo.currentData()

        # Clear existing table data
        self.patient_table.setRowCount(0)

        if provider_id is None:
            return

        if provider_id:
            patients = self.session.query(Patient).filter_by(provider_id=provider_id).all()

            for row, patient in enumerate(patients):
                self.patient_table.insertRow(row)
                self.patient_table.setItem(row, 0, QTableWidgetItem(patient.id))
                self.patient_table.setItem(row, 1, QTableWidgetItem(patient.name))
                self.patient_table.setItem(row, 2, QTableWidgetItem(str(patient.created_at)))


    def load_all_patients(self):
        self.patient_table.setRowCount(0)
        patients = self.session.query(Patient).all()
        for row, patient in enumerate(patients):
            self.patient_table.insertRow(row)
            self.patient_table.setItem(row, 0, QTableWidgetItem(patient.id))
            self.patient_table.setItem(row, 1, QTableWidgetItem(patient.name))
            self.patient_table.setItem(row, 2, QTableWidgetItem(patient.provider_id))

    def load_my_patients(self):
        """Load patients for the current provider"""
        try:
            self.my_patients_table.setRowCount(0)  # Clear existing data
            patients = self.session.query(Patient).filter_by(
                provider_id=self.user.id
            ).order_by(Patient.updated_at.desc()).all()

            for row, patient in enumerate(patients):
                self.my_patients_table.insertRow(row)
                self.my_patients_table.setItem(row, 0, QTableWidgetItem(patient.id[:8] + '...'))
                self.my_patients_table.setItem(row, 1, QTableWidgetItem(patient.name))
                self.my_patients_table.setItem(row, 2, QTableWidgetItem(
                    patient.created_at.strftime("%Y-%m-%d")
                ))
                self.my_patients_table.setItem(row, 3, QTableWidgetItem(
                    patient.updated_at.strftime("%Y-%m-%d") if patient.updated_at else "N/A"
                ))

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error loading patients:\n{str(e)}")

    def init_fab(self):
        if self.user.role == 'admin':
            # Create floating action button
            self.fab = QPushButton("+", self)
            self.fab.setFixedSize(60, 60)
            self.fab.setStyleSheet("""
                QPushButton {
                    background-color: #2196F3;
                    border-radius: 30px;
                    border: none;
                    color: white;
                    font-size: 24px;
                }
                QPushButton:hover {
                    background-color: #1976D2;
                }
            """)
            self.fab.clicked.connect(self.show_symptoms_input)
            self.update_fab_position()

    def resizeEvent(self, event):
        """Update FAB position when window resizes"""
        super().resizeEvent(event)
        if self.user.role == 'admin':
            self.update_fab_position()

    def update_fab_position(self):
        """Position FAB 100px from right and 200px from bottom"""
        fab_x = self.width() - 100 - self.fab.width()
        fab_y = self.height() - 200 - self.fab.height()
        self.fab.move(fab_x, fab_y)
        def process_symptoms(self, dialog):
            """Handle submitted symptoms"""
            symptoms = self.symptoms_input.toPlainText()
            if symptoms.strip():
                # Add your logic to handle symptoms here
                print("Symptoms recorded:", symptoms)
                QMessageBox.information(self, "Success", "Symptoms recorded successfully!")
                dialog.accept()
            else:
                QMessageBox.warning(self, "Error", "Please enter symptoms!")

    def show_symptoms_input(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Record Symptoms")
        dialog.setFixedSize(300, 200)

        layout = QVBoxLayout()

        # Symptoms input
        self.symptoms_input = QTextEdit()
        self.symptoms_input.setPlaceholderText("Enter patient symptoms...")

        # Buttons
        btn_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btn_box.accepted.connect(lambda: self.process_symptoms(dialog))
        btn_box.rejected.connect(dialog.reject)

        layout.addWidget(QLabel("Symptoms:"))
        layout.addWidget(self.symptoms_input)
        layout.addWidget(btn_box)

        dialog.setLayout(layout)
        dialog.exec()

    def process_symptoms(self, dialog):
        """Handle submitted symptoms and show prediction results"""
        symptoms_text = self.symptoms_input.toPlainText()

        if not symptoms_text.strip():
            QMessageBox.warning(self, "Error", "Please enter symptoms!")
            return

        try:
            # Get prediction from ML model
            disease, description, precautions = predict_disease(symptoms_text)

            # Create results dialog
            result_dialog = QDialog(self)
            result_dialog.setWindowTitle("Diagnosis Results")
            result_dialog.setFixedSize(500, 400)

            layout = QVBoxLayout()

            # Disease information
            lbl_disease = QLabel(f"<b>Predicted Disease:</b> {disease}")
            lbl_disease.setStyleSheet("font-size: 16px; color: #f39c12;")  # Orange text for emphasis

            # Description Box
            lbl_description = QTextEdit(description)
            lbl_description.setReadOnly(True)
            lbl_description.setStyleSheet("""
                QTextEdit {
                    background-color: #1a1a1a;  /* Dark background */
                    color: #ffffff;  /* White text */
                    border: 2px solid #3d3d3d;
                    border-radius: 5px;
                    padding: 10px;
                    font-size: 14px;
                }
                QScrollBar:vertical {
                    background: #2d2d2d;
                    width: 12px;
                }
                QScrollBar::handle:vertical {
                    background: #4d4d4d;
                    min-height: 20px;
                    border-radius: 6px;
                }
            """)

            # Precautions List
            lbl_precautions = QLabel("<b>Recommended Precautions:</b>")
            precaution_list = QListWidget()
            precaution_list.addItems(precautions)
            precaution_list.setStyleSheet("""
                QListWidget {
                    background-color: #1a1a1a;
                    color: #ffffff;
                    border: 2px solid #3d3d3d;
                    border-radius: 5px;
                }
                QListWidget::item {
                    color: #ffffff;
                    padding: 8px;
                    border-bottom: 1px solid #3d3d3d;
                }
                QListWidget::item:selected {
                    background-color: #3d3d3d;
                }
            """)

            # Style the result dialog
            result_dialog.setStyleSheet("""
                QDialog {
                    background-color: #2d2d2d;
                }
                QLabel {
                    color: #ffffff;
                    font-family: Arial;
                }
                QTextEdit {
                    background-color: #1a1a1a;
                    color: #ffffff;
                    border: 2px solid #3d3d3d;
                    border-radius: 5px;
                    padding: 10px;
                    font-size: 14px;
                }
                QListWidget {
                    background-color: #1a1a1a;
                    color: #ffffff;
                    border: 2px solid #3d3d3d;
                    border-radius: 5px;
                }
                QListWidget::item {
                    color: #ffffff;
                    padding: 8px;
                    border-bottom: 1px solid #3d3d3d;
                }
                QListWidget::item:selected {
                    background-color: #3d3d3d;
                }
                QScrollBar:vertical {
                    background: #2d2d2d;
                    width: 12px;
                }
                QScrollBar::handle:vertical {
                    background: #4d4d4d;
                    min-height: 20px;
                    border-radius: 6px;
                }
            """)

            # Add to layout
            layout.addWidget(lbl_disease)
            layout.addWidget(QLabel("<b>Description:</b>"))
            layout.addWidget(lbl_description)
            layout.addWidget(lbl_precautions)
            layout.addWidget(precaution_list)

            result_dialog.setLayout(layout)
            dialog.accept()
            result_dialog.exec()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Prediction failed:\n{str(e)}")


    def clear_provider_form(self):
        self.prov_username.clear()
        self.prov_password.clear()

    def update_blockchain_view(self):
        self.blockchain_table.setRowCount(0)
        for row, block in enumerate(self.blockchain.chain):
            self.blockchain_table.insertRow(row)
            self.blockchain_table.setItem(row, 0, QTableWidgetItem(str(block.index)))
            self.blockchain_table.setItem(row, 1, QTableWidgetItem(str(block.timestamp)))
            self.blockchain_table.setItem(row, 2, QTableWidgetItem(block.data.get('action', '')))
            self.blockchain_table.setItem(row, 3, QTableWidgetItem(block.data.get('patient_id', '')))
            self.blockchain_table.setItem(row, 4, QTableWidgetItem(block.data.get('provider_id', '')))

            if self.user.role == 'admin':
                self.blockchain_table.setItem(row, 5, QTableWidgetItem(block.hash))

    def clear_registration_form(self):
        self.patient_name.clear()
        self.medical_data.clear()

    def closeEvent(self, event):
        self.session.close()
        super().closeEvent(event)

if __name__ == "__main__":
    app = QApplication(sys.argv)

    # Initialize database
    from models import Base, engine
    Base.metadata.create_all(engine)

    # Create admin user if not exists
    with Session() as session:
        if not session.query(User).filter_by(username='admin').first():
            admin = User(
                id=hashlib.sha256(b'admin').hexdigest(),
                username='admin',
                role='admin'
            )
            admin.set_password('admin123')
            session.add(admin)
            session.commit()

    login = LoginDialog()
    if login.exec() == QDialog.DialogCode.Accepted:
        window = HealthcareApp(login.user)
        window.show()
        sys.exit(app.exec())