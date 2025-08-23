#!/usr/bin/env python3
"""
Script d'initialisation de la base de données Eclypse Server
Crée les tables et un utilisateur admin par défaut
"""

import os
import sys
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import OperationalError, ProgrammingError
import getpass

# Import des modèles
from models import Base, User
from security import pwd_context

def get_database_config():
    """Demande les informations de connexion à la base de données"""
    print("=== Configuration de la base de données ===")
    
    db_user = input("Utilisateur PostgreSQL (défaut: myuser): ").strip() or "myuser"
    db_pass = getpass.getpass("Mot de passe PostgreSQL: ")
    db_host = input("Hôte/IP PostgreSQL (défaut: localhost): ").strip() or "localhost"
    db_port = input("Port PostgreSQL (défaut: 5432): ").strip() or "5432"
    db_name = input("Nom de la base de données (défaut: vdi_db): ").strip() or "vdi_db"
    
    return {
        'user': db_user,
        'password': db_pass,
        'host': db_host,
        'port': db_port,
        'name': db_name
    }

def get_admin_config():
    """Demande les informations pour l'utilisateur admin par défaut"""
    print("\n=== Configuration de l'utilisateur admin ===")
    
    admin_username = input("Nom d'utilisateur admin (défaut: admin): ").strip() or "admin"
    admin_password = getpass.getpass("Mot de passe admin: ")
    
    if not admin_password:
        print("❌ Le mot de passe admin est obligatoire!")
        sys.exit(1)
    
    return {
        'username': admin_username,
        'password': admin_password
    }

def test_connection(engine):
    """Teste la connexion à la base de données"""
    try:
        with engine.connect() as conn:
            result = conn.execute(text("SELECT version();"))
            version = result.fetchone()[0]
            print(f"✅ Connexion réussie à PostgreSQL: {version}")
            return True
    except OperationalError as e:
        print(f"❌ Erreur de connexion à la base de données: {e}")
        return False

def create_database_if_not_exists(db_config):
    """Crée la base de données si elle n'existe pas"""
    # Connexion à PostgreSQL sans spécifier de base de données
    temp_url = f"postgresql://{db_config['user']}:{db_config['password']}@{db_config['host']}:{db_config['port']}/postgres"
    temp_engine = create_engine(temp_url)
    
    try:
        with temp_engine.connect() as conn:
            # Vérifier si la base existe
            result = conn.execute(text(f"SELECT 1 FROM pg_database WHERE datname = '{db_config['name']}'"))
            exists = result.fetchone()
            
            if not exists:
                print(f"📦 Création de la base de données '{db_config['name']}'...")
                conn.execute(text(f"CREATE DATABASE {db_config['name']}"))
                conn.commit()
                print(f"✅ Base de données '{db_config['name']}' créée avec succès")
            else:
                print(f"✅ Base de données '{db_config['name']}' existe déjà")
                
    except Exception as e:
        print(f"❌ Erreur lors de la création de la base de données: {e}")
        return False
    
    return True

def create_tables(engine):
    """Crée toutes les tables nécessaires"""
    try:
        print("📦 Création des tables...")
        Base.metadata.create_all(bind=engine)
        print("✅ Tables créées avec succès")
        return True
    except Exception as e:
        print(f"❌ Erreur lors de la création des tables: {e}")
        return False

def create_admin_user(db_config, admin_config):
    """Crée l'utilisateur admin par défaut"""
    # Connexion à la base de données spécifique
    db_url = f"postgresql://{db_config['user']}:{db_config['password']}@{db_config['host']}:{db_config['port']}/{db_config['name']}"
    engine = create_engine(db_url)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    
    db = SessionLocal()
    try:
        # Vérifier si l'utilisateur admin existe déjà
        existing_user = db.query(User).filter(User.username == admin_config['username']).first()
        
        if existing_user:
            print(f"⚠️  L'utilisateur '{admin_config['username']}' existe déjà")
            update = input("Voulez-vous mettre à jour son mot de passe? (o/n): ").strip().lower()
            if update in ['o', 'oui', 'y', 'yes']:
                existing_user.password_hash = pwd_context.hash(admin_config['password'])
                db.commit()
                print(f"✅ Mot de passe de '{admin_config['username']}' mis à jour")
            return True
        
        # Créer le nouvel utilisateur admin
        hashed_password = pwd_context.hash(admin_config['password'])
        admin_user = User(
            username=admin_config['username'],
            password_hash=hashed_password,
            role="master"  # Rôle le plus élevé
        )
        
        db.add(admin_user)
        db.commit()
        db.refresh(admin_user)
        
        print(f"✅ Utilisateur admin '{admin_config['username']}' créé avec succès")
        print(f"   ID: {admin_user.id}")
        print(f"   Rôle: {admin_user.role}")
        
        return True
        
    except Exception as e:
        print(f"❌ Erreur lors de la création de l'utilisateur admin: {e}")
        db.rollback()
        return False
    finally:
        db.close()

def main():
    """Fonction principale"""
    print("🚀 Initialisation de la base de données Eclypse Server")
    print("=" * 50)
    
    # Récupération des configurations
    db_config = get_database_config()
    admin_config = get_admin_config()
    
    print("\n" + "=" * 50)
    print("Résumé de la configuration:")
    print(f"Base de données: {db_config['user']}@{db_config['host']}:{db_config['port']}/{db_config['name']}")
    print(f"Admin: {admin_config['username']}")
    print("=" * 50)
    
    # Confirmation
    confirm = input("\nContinuer avec cette configuration? (o/n): ").strip().lower()
    if confirm not in ['o', 'oui', 'y', 'yes']:
        print("❌ Initialisation annulée")
        sys.exit(0)
    
    # Création de la base de données si nécessaire
    if not create_database_if_not_exists(db_config):
        sys.exit(1)
    
    # Test de connexion
    db_url = f"postgresql://{db_config['user']}:{db_config['password']}@{db_config['host']}:{db_config['port']}/{db_config['name']}"
    engine = create_engine(db_url)
    
    if not test_connection(engine):
        sys.exit(1)
    
    # Création des tables
    if not create_tables(engine):
        sys.exit(1)
    
    # Création de l'utilisateur admin
    if not create_admin_user(db_config, admin_config):
        sys.exit(1)
    
    print("\n" + "=" * 50)
    print("🎉 Initialisation terminée avec succès!")
    print("=" * 50)
    print(f"Vous pouvez maintenant vous connecter avec:")
    print(f"  Username: {admin_config['username']}")
    print(f"  Password: [celui que vous avez saisi]")
    print("\nPour lancer le serveur:")
    print("  docker-compose up -d")
    print("  ou")
    print("  python main.py")

if __name__ == "__main__":
    main()