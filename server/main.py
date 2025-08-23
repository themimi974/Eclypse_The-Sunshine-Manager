# main.py (or routes.py)
from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session, joinedload
from typing import List
import requests
import json
import base64
from pydantic import BaseModel
import random
import os
from datetime import datetime
from sqlalchemy.exc import OperationalError

from database import SessionLocal, engine
import models
from models import User, VMInfo, UserVM, SystemConfig
from schemas import (
    UserCreate, UserOut, VMInfoIn, VMInfoOut, AssignVM, UserOutWithVMs,
    SunshinePinRequest, PairRequest, PreparePairingRequest, PreparePairingResponse, CompletePairingRequest,
    AssignmentOut, UnassignVM
)
from security import pwd_context, create_access_token, get_current_user, get_admin_user

app = FastAPI()

# Create tables on startup if not present
models.Base.metadata.create_all(bind=engine)


# Dependency for DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.post("/auth/register", response_model=UserOut, tags=["Auth"])
def register_user(
            user_data: UserCreate, 
            db: Session = Depends(get_db),
            current_user : User = Depends(get_admin_user)
    ):
    """
    Admin or Master can create new users (including normal users).
    If you want to allow self-registration, remove the admin check.
    """
    # (Optional) Check if current user is admin
    # current_admin = get_admin_user(...)  # or route-level dependency

    # Check if username already exists
    existing = db.query(User).filter(User.username == user_data.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="User already exists")

    hashed_pw = pwd_context.hash(user_data.password)
    new_user = User(
        username=user_data.username,
        password_hash=hashed_pw,
        role=user_data.role
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user  # Pydantic model: UserOut


@app.post("/auth/token", tags=["Auth"])
def login(form_data: dict, db: Session = Depends(get_db)):
    """
    Example: expects JSON like { "username": "bob", "password": "secret" }
    or switch to OAuth2PasswordRequestForm if desired.
    """
    username = form_data.get("username")
    password = form_data.get("password")

    user = db.query(User).filter(User.username == username).first()
    if not user or not pwd_context.verify(password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

    # create JWT
    token = create_access_token({"sub": user.username, "role": user.role})
    return {"access_token": token, "token_type": "bearer"}


@app.post("/vm/register", response_model=VMInfoOut, tags=["VM"])
def register_vm(
    vminfo: VMInfoIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_admin_user)
):
    """
    Only 'admin' or 'master' can register a VM.
    """
    existing_vm = db.query(VMInfo).filter(VMInfo.hostname == vminfo.hostname).first()
    if existing_vm:
        raise HTTPException(status_code=400, detail="VM hostname already used")

    new_vm = VMInfo(
        hostname=vminfo.hostname,
        ip_address=vminfo.ip_address,
        sunshine_user=vminfo.sunshine_user,
        sunshine_password=vminfo.sunshine_password,
    )
    db.add(new_vm)
    db.commit()
    db.refresh(new_vm)
    return new_vm  # Pydantic: VMInfoOut


@app.post("/vm/assign", tags=["VM"])
def assign_vm(
    assignment: AssignVM,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_admin_user)
):
    """
    Admin can assign a VM to a given user.
    """
    user = db.query(User).filter(User.id == assignment.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    vm = db.query(VMInfo).filter(VMInfo.id == assignment.vm_id).first()
    if not vm:
        raise HTTPException(status_code=404, detail="VM not found")

    # Check if association already exists
    existing = db.query(UserVM).filter_by(user_id=user.id, vm_id=vm.id).first()
    if existing:
        raise HTTPException(status_code=400, detail="VM already assigned to user")

    association = UserVM(user_id=user.id, vm_id=vm.id)
    db.add(association)
    db.commit()
    return {"msg": f"VM {vm.hostname} assigned to user {user.username}"}


@app.get("/vm/list", response_model=List[VMInfoOut], tags=["VM"])
def list_vms_for_user(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    An admin/master sees all VMs.
    A normal user sees ONLY the VMs assigned to them.
    """
    # Check if the user is an admin or master
    if current_user.role in ["admin", "master"]:
        # Admin or Master: Return all VMs
        vms = db.query(VMInfo).all()
    else:
        # Normal User: Return only their assigned VMs
        # 1) Find all association rows where user_id == current_user.id
        associations = db.query(UserVM).filter(UserVM.user_id == current_user.id).all()

        # 2) Extract VM IDs from those associations
        vm_ids = [assoc.vm_id for assoc in associations]

        # 3) Fetch the actual VM objects
        vms = db.query(VMInfo).filter(VMInfo.id.in_(vm_ids)).all()

    return vms  # Each item => VMInfoOut


@app.get("/admin/user/{user_id}", response_model=UserOutWithVMs, tags=["Admin"])
def get_user_details(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_admin_user)  # Restrict access to admins
):
    """
    Fetch details of a specific user by user ID, including associated VMs.
    Only accessible to admin or master roles.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Fetch associated VMs using the relationship
    associated_vms = [association.vm for association in user.vms]

    # Return user details with associated VMs
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "vms": associated_vms,  # Automatically serialized into VMInfoOut format
    }

@app.get("/admin/users", response_model=List[UserOut], tags=["Admin"])
def get_all_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_admin_user)  # Restrict access to admins
):
    """
    Get the list of all users.
    Only accessible to admin or master roles.
    """
    users = db.query(User).all()
    return users  # List of UserOut

@app.delete("/admin/user/{user_id}", tags=["Admin"])
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_admin_user)  # Restrict access to admins
):
    """
    Delete a user by ID.
    Only accessible to admin or master roles.
    Cannot delete yourself.
    """
    # Vérifier que l'utilisateur existe
    user_to_delete = db.query(User).filter(User.id == user_id).first()
    if not user_to_delete:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Empêcher la suppression de soi-même
    if user_to_delete.id == current_user.id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account")
    
    # Supprimer toutes les assignations VM de cet utilisateur
    db.query(UserVM).filter(UserVM.user_id == user_id).delete()
    
    # Supprimer l'utilisateur
    db.delete(user_to_delete)
    db.commit()
    
    return {"msg": f"User {user_to_delete.username} deleted successfully"}

@app.post("/vm/send-pin", tags=["VM"])
async def send_pin_to_sunshine(
    pin_request: SunshinePinRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Endpoint sécurisé pour envoyer le PIN à Sunshine.
    Le client n'a plus besoin de connaître les identifiants Sunshine.
    """
    # Récupérer les informations de la VM
    vm = db.query(VMInfo).filter(VMInfo.id == pin_request.vm_id).first()
    if not vm:
        raise HTTPException(status_code=404, detail="VM not found")
    
    # Vérifier que l'utilisateur a accès à cette VM
    if current_user.role not in ["admin", "master"]:
        # Pour les utilisateurs normaux, vérifier l'association
        association = db.query(UserVM).filter(
            UserVM.user_id == current_user.id,
            UserVM.vm_id == vm.id
        ).first()
        if not association:
            raise HTTPException(
                status_code=403, 
                detail="You don't have permission to access this VM"
            )
    
    # Préparer la requête pour Sunshine
    url = f"https://{vm.ip_address}:47990/api/pin"
    auth_str = f"{vm.sunshine_user}:{vm.sunshine_password}"
    auth_bytes = auth_str.encode('utf-8')
    auth_b64 = base64.b64encode(auth_bytes).decode('utf-8')
    
    headers = {
        "Accept": "*/*",
        "Authorization": f"Basic {auth_b64}",
        "Content-Type": "text/plain; charset=UTF-8"
    }
    
    data = json.dumps({"pin": pin_request.pin})
    
    try:
        # Désactiver temporairement la vérification SSL pour les certificats auto-signés
        # En production, utilisez un certificat valide ou une CA personnalisée
        response = requests.post(
            url,
            headers=headers,
            data=data,
            verify=False  # À remplacer par un certificat valide en production
        )
        
        if response.status_code == 200:
            return {"status": "success", "message": f"PIN {pin_request.pin} successfully sent to Sunshine"}
        else:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"Error sending PIN to Sunshine: {response.text}"
            )
    except requests.exceptions.RequestException as e:
        raise HTTPException(
            status_code=500,
            detail=f"Connection error to Sunshine: {str(e)}"
        )

@app.post("/vm/pair", tags=["VM"])
async def pair_with_vm(
    pair_request: PairRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Endpoint pour gérer le processus de pairing avec une VM.
    """
    # Récupérer les informations de la VM
    vm = db.query(VMInfo).filter(VMInfo.id == pair_request.vm_id).first()
    if not vm:
        raise HTTPException(status_code=404, detail="VM not found")
    
    # Vérifier que l'utilisateur a accès à cette VM
    if current_user.role not in ["admin", "master"]:
        association = db.query(UserVM).filter(
            UserVM.user_id == current_user.id,
            UserVM.vm_id == vm.id
        ).first()
        if not association:
            raise HTTPException(
                status_code=403, 
                detail="You don't have permission to access this VM"
            )
    
    # Envoyer le PIN au serveur Sunshine
    url = f"https://{vm.ip_address}:47990/api/pin"
    auth_str = f"{vm.sunshine_user}:{vm.sunshine_password}"
    auth_bytes = auth_str.encode('utf-8')
    auth_b64 = base64.b64encode(auth_bytes).decode('utf-8')
    
    headers = {
        "Accept": "*/*",
        "Authorization": f"Basic {auth_b64}",
        "Content-Type": "text/plain; charset=UTF-8"
    }
    
    try:
        response = requests.post(
            url,
            headers=headers,
            data=json.dumps({"pin": pair_request.pin}),
            verify=False
        )
        
        if response.status_code == 200:
            return {
                "status": "success",
                "message": "PIN sent successfully to Sunshine server"
            }
        else:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"Error from Sunshine server: {response.text}"
            )
    except requests.exceptions.RequestException as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to connect to Sunshine server: {str(e)}"
        )

# Fonction d'aide pour générer un PIN
def generate_4digit_pin() -> str:
    """Génère un PIN aléatoire à 4 chiffres (e.g. 0123)."""
    return f"{random.randint(0, 9999):04d}"

@app.post("/vm/prepare-pairing", response_model=PreparePairingResponse, tags=["VM"])
async def prepare_vm_pairing(
    request: PreparePairingRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Prépare le processus de pairing en générant un PIN et en vérifiant les permissions.
    Le serveur génère le PIN et le renvoie au client.
    """
    # Vérifier si la VM existe et si l'utilisateur y a accès
    vm = db.query(VMInfo).filter(VMInfo.id == request.vm_id).first()
    if not vm:
        raise HTTPException(status_code=404, detail="VM not found")
    
    # Vérifier que l'utilisateur a accès à cette VM (sauf admin/master)
    if current_user.role not in ["admin", "master"]:
        association = db.query(UserVM).filter(
            UserVM.user_id == current_user.id,
            UserVM.vm_id == vm.id
        ).first()
        if not association:
            raise HTTPException(
                status_code=403, 
                detail="You don't have permission to access this VM"
            )
    
    # Générer un PIN 4 chiffres pour le pairing
    pin = generate_4digit_pin()
    
    # Retourner le PIN au client
    return {
        "vm_id": vm.id,
        "pin": pin,
        "status": "ready"
    }

@app.post("/vm/complete-pairing", tags=["VM"])
async def complete_vm_pairing(
    request: CompletePairingRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Finalise le processus de pairing en envoyant le PIN au serveur Sunshine.
    Le client a déjà lancé Moonlight avec le PIN et attend la confirmation.
    """
    print(f"[DEBUG] User {current_user.username} (ID: {current_user.id}, Role: {current_user.role}) trying to access VM {request.vm_id}")
    
    # Récupérer les informations de la VM
    vm = db.query(VMInfo).filter(VMInfo.id == request.vm_id).first()
    if not vm:
        print(f"[DEBUG] VM {request.vm_id} not found")
        raise HTTPException(status_code=404, detail="VM not found")
    
    print(f"[DEBUG] VM found: {vm.hostname} ({vm.ip_address})")
    
    # Vérifier que l'utilisateur a accès à cette VM
    if current_user.role not in ["admin", "master"]:
        associations = db.query(UserVM).filter(UserVM.user_id == current_user.id).all()
        vm_ids = [assoc.vm_id for assoc in associations]
        if request.vm_id not in vm_ids:
            print(f"[DEBUG] Access denied - VM {request.vm_id} not in user's assigned VMs: {vm_ids}")
            raise HTTPException(
                status_code=403, 
                detail=f"You don't have permission to access VM {vm.hostname}"
            )
        else:
            print(f"[DEBUG] Access granted - VM {request.vm_id} found in user's assigned VMs")
    else:
        print(f"[DEBUG] Admin/Master access granted for user {current_user.username}")
    
    # Utiliser l'IP originale de la VM
    url = f"https://{vm.ip_address}:47990/api/pin"
    
    # Définir le nom de la machine cliente
    client_name = "clienteclypse" # Nom de machine demandé
    
    print(f"[DEBUG] Sending PIN and Name to Sunshine at {url}")
    
    auth_str = f"{vm.sunshine_user}:{vm.sunshine_password}"
    auth_bytes = auth_str.encode('utf-8')
    auth_b64 = base64.b64encode(auth_bytes).decode('utf-8')
    
    headers = {
        "Accept": "*/*",
        "Authorization": f"Basic {auth_b64}",
        "Content-Type": "application/json"  # Doit être application/json
    }
    
    # Données à envoyer à Sunshine
    payload_to_sunshine = {
        "pin": request.pin,
        "name": client_name
    }
    print(f"[DEBUG] Payload to Sunshine: {payload_to_sunshine}")
    
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        print(f"[DEBUG] Waiting 5 seconds before sending PIN to Sunshine...")
        import time
        time.sleep(5)
        print(f"[DEBUG] Sending PIN {request.pin} and name '{client_name}' to Sunshine now...")
        
        response = requests.post(
            url,
            headers=headers,
            json=payload_to_sunshine, # Envoyer le dictionnaire directement comme JSON
            verify=False,
            timeout=10
        )
        
        print(f"[DEBUG] Sunshine response: {response.status_code}")
        print(f"[DEBUG] Sunshine response body: {response.text}")
        
        if response.status_code == 200:
            return {
                "status": "success",
                "message": "PIN and name sent successfully to Sunshine server"
            }
        else:
            error_detail = f"Sunshine server responded with status {response.status_code}"
            if response.text:
                error_detail += f": {response.text}"
            else:
                error_detail += " (no response body)"
            
            print(f"[DEBUG] Sunshine error: {error_detail}")
            raise HTTPException(
                status_code=response.status_code,
                detail=error_detail
            )
    except requests.exceptions.ConnectionError as e:
        error_msg = f"Cannot connect to Sunshine server at {vm.ip_address}:47990. Make sure Sunshine is running and accessible."
        print(f"[DEBUG] Connection error: {error_msg}")
        raise HTTPException(status_code=500, detail=error_msg)
    except requests.exceptions.Timeout as e:
        error_msg = f"Connection to Sunshine server timed out. The server might be overloaded or unreachable."
        print(f"[DEBUG] Timeout error: {error_msg}")
        raise HTTPException(status_code=500, detail=error_msg)
    except requests.exceptions.RequestException as e:
        error_msg = f"Failed to connect to Sunshine server: {str(e)}"
        print(f"[DEBUG] Request error: {error_msg}")
        raise HTTPException(status_code=500, detail=error_msg)

@app.get("/vm/assignments", response_model=List[AssignmentOut], tags=["VM"])
def list_assignments(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_admin_user)
):
    """
    Liste toutes les assignations de VM aux utilisateurs.
    Accessible uniquement aux rôles admin ou master.
    """
    assignments = db.query(UserVM).options(
        joinedload(UserVM.user),
        joinedload(UserVM.vm)
    ).all()
    
    return [
        AssignmentOut(
            id=assign.id,
            user_id=assign.user.id,
            username=assign.user.username,
            vm_id=assign.vm.id,
            vm_hostname=assign.vm.hostname
        )
        for assign in assignments
    ]

@app.delete("/vm/unassign", tags=["VM"])
def unassign_vm(
    unassign_data: UnassignVM,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_admin_user)
):
    """
    Supprime une assignation VM-utilisateur.
    Accessible uniquement aux rôles admin ou master.
    """
    # Vérifier que l'utilisateur existe
    user = db.query(User).filter(User.id == unassign_data.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Vérifier que la VM existe
    vm = db.query(VMInfo).filter(VMInfo.id == unassign_data.vm_id).first()
    if not vm:
        raise HTTPException(status_code=404, detail="VM not found")

    # Trouver et supprimer l'assignation
    assignment = db.query(UserVM).filter(
        UserVM.user_id == unassign_data.user_id,
        UserVM.vm_id == unassign_data.vm_id
    ).first()
    
    if not assignment:
        raise HTTPException(status_code=404, detail="Assignment not found")

    db.delete(assignment)
    db.commit()
    
    return {
        "msg": f"VM {vm.hostname} unassigned from user {user.username}",
        "deleted_assignment_id": assignment.id
    }

@app.get("/vm/debug-access/{vm_id}", tags=["VM"])
def debug_vm_access(
    vm_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Fonction de débogage pour vérifier les permissions d'accès à une VM.
    """
    vm = db.query(VMInfo).filter(VMInfo.id == vm_id).first()
    if not vm:
        return {"error": "VM not found"}
    
    # Vérifier l'association
    association = db.query(UserVM).filter(
        UserVM.user_id == current_user.id,
        UserVM.vm_id == vm.id
    ).first()
    
    return {
        "user_id": current_user.id,
        "username": current_user.username,
        "user_role": current_user.role,
        "vm_id": vm.id,
        "vm_hostname": vm.hostname,
        "association_exists": association is not None,
        "association_id": association.id if association else None
    }

def auto_init_db():
    """Initialisation automatique de la base de données au démarrage"""
    from models import User, SystemConfig
    
    try:
        # Créer toutes les tables (y compris system_config)
        models.Base.metadata.create_all(bind=engine)
        print("[INIT] Tables créées/vérifiées avec succès")
    except OperationalError as e:
        print(f"[INIT] Erreur de connexion à la base de données: {e}")
        print("[INIT] Vérifiez que le service PostgreSQL est démarré")
        return

    db = SessionLocal()
    try:
        # Vérifier si l'initialisation a déjà été faite
        init_check = db.query(SystemConfig).filter(SystemConfig.key == "db_initialized").first()
        
        if not init_check:
            print("[INIT] Première initialisation de la base de données...")
            
            # Créer l'utilisateur admin par défaut
            admin_user = os.getenv("ADMIN_USER", "admin")
            admin_pass = os.getenv("ADMIN_PASS", "admin1234")
            admin_role = os.getenv("ADMIN_ROLE", "master")
            
            # Vérifier si l'admin existe déjà (par sécurité)
            existing_admin = db.query(User).filter(User.username == admin_user).first()
            if not existing_admin:
                hashed_pw = pwd_context.hash(admin_pass)
                user = User(username=admin_user, password_hash=hashed_pw, role=admin_role)
                db.add(user)
                print(f"[INIT] Utilisateur admin '{admin_user}' créé (mot de passe: '{admin_pass}')")
            else:
                print(f"[INIT] Utilisateur admin '{admin_user}' existe déjà")
            
            # Marquer l'initialisation comme terminée
            init_record = SystemConfig(
                key="db_initialized",
                value="true",
                updated_at=datetime.now().isoformat()
            )
            db.add(init_record)
            
            db.commit()
            print("[INIT] Initialisation terminée avec succès")
        else:
            print("[INIT] Base de données déjà initialisée")
            
    except Exception as e:
        print(f"[INIT] Erreur lors de l'initialisation: {e}")
        db.rollback()
    finally:
        db.close()

# Appel automatique au démarrage
auto_init_db()