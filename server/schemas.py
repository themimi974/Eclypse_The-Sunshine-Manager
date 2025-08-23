# schemas.py
from pydantic import BaseModel, ConfigDict
from typing import Optional, List

class UserCreate(BaseModel):
    username: str
    password: str
    role: str  # e.g. "admin", "user", or "master"

class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    username: str
    role: str

class VMInfoIn(BaseModel):
    hostname: str
    ip_address: str
    sunshine_user: str
    sunshine_password: str

class VMInfoOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    hostname: str
    ip_address: str
    sunshine_user: str
    sunshine_password: str

class AssignVM(BaseModel):
    user_id: int
    vm_id: int

class UserOutWithVMs(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    username: str
    role: str
    vms: List[VMInfoOut]  # List of associated VMs

class SunshinePinRequest(BaseModel):
    """Schéma pour la requête de PIN Sunshine sécurisée"""
    vm_id: int
    pin: str

class PairRequest(BaseModel):
    vm_id: int
    pin: str

class PreparePairingRequest(BaseModel):
    vm_id: int

class PreparePairingResponse(BaseModel):
    vm_id: int
    pin: str
    status: str = "ready"

class CompletePairingRequest(BaseModel):
    vm_id: int
    pin: str

class AssignmentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int  # ID de l'assignation (table user_vm)
    user_id: int
    username: str
    vm_id: int
    vm_hostname: str

class UnassignVM(BaseModel):
    user_id: int
    vm_id: int
