# models.py
from sqlalchemy import Column, Integer, String, ForeignKey, Table
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, index=True)
    password_hash = Column(String(200))
    role = Column(String(20), default="user")

    # Relationship to track which VMs this user can access
    vms = relationship("UserVM", back_populates="user")


class VMInfo(Base):
    __tablename__ = "vm_info"
    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(100), unique=True)
    ip_address = Column(String(100))
    sunshine_user = Column(String(100))
    sunshine_password = Column(String(100))

    # Relationship to track which users can access this VM
    users = relationship("UserVM", back_populates="vm")


class UserVM(Base):
    """
    Association table linking users and VMs 
    (one user can have multiple VMs, and one VM can belong to multiple users 
     if you want, or just do a 1-n if that fits your use-case).
    """
    __tablename__ = "user_vm"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    vm_id = Column(Integer, ForeignKey("vm_info.id"))

    user = relationship("User", back_populates="vms")
    vm = relationship("VMInfo", back_populates="users")


class SystemConfig(Base):
    """Table pour stocker la configuration système"""
    __tablename__ = "system_config"
    id = Column(Integer, primary_key=True)
    key = Column(String(100), unique=True, index=True)
    value = Column(String(500))
    updated_at = Column(String(50))  # Timestamp de mise à jour


