from sqlalchemy import create_engine, Column, String, Text, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from datetime import datetime
from cryptography.fernet import Fernet
import hashlib

# Encryption setup
fernet_key = Fernet.generate_key()
cipher = Fernet(fernet_key)

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'

    id = Column(String(64), primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String(128), nullable=False)
    role = Column(String(20), nullable=False)  # 'admin' or 'provider'
    is_active = Column(Boolean, default=True)
    organization = Column(String(100))
    specialization = Column(String(100))

    # Relationships
    patients = relationship('Patient', back_populates='provider')

    def set_password(self, password):
        self.password_hash = hashlib.sha256(password.encode()).hexdigest()

    def check_password(self, password):
        return self.password_hash == hashlib.sha256(password.encode()).hexdigest()

    def __repr__(self):
        return f"<User({self.role}: {self.username})>"

class Patient(Base):
    __tablename__ = 'patients'
    id = Column(String(64), primary_key=True)
    name = Column(String(100), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)

    # Relationships
    provider_id = Column(String(64), ForeignKey('users.id'), nullable=False)
    provider = relationship('User', back_populates='patients')
    medical_records = relationship('MedicalRecord', back_populates='patient')

class MedicalRecord(Base):
    __tablename__ = 'medical_records'
    id = Column(String(64), primary_key=True)
    encrypted_data = Column(Text, nullable=False)  # Encrypted storage
    hash = Column(String(64), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    patient_id = Column(String(64), ForeignKey('patients.id'), nullable=False)
    patient = relationship('Patient', back_populates='medical_records')

    def set_data(self, plaintext):
        self.encrypted_data = cipher.encrypt(plaintext.encode()).decode()
        self.hash = hashlib.sha256(plaintext.encode()).hexdigest()

    def get_data(self):
        return cipher.decrypt(self.encrypted_data.encode()).decode()

# Database setup
engine = create_engine('sqlite:///healthcare.db')
Session = sessionmaker(bind=engine)

def init_db():
    Base.metadata.create_all(engine)

    # Create default admin if not exists
    with Session() as session:
        if not session.query(User).filter_by(username='admin').first():
            admin = User(
                id=hashlib.sha256(b'admin').hexdigest(),
                username='admin',
                role='admin',
                is_active=True
            )
            admin.set_password('admin123')
            session.add(admin)
            session.commit()

if __name__ == '__main__':
    init_db()