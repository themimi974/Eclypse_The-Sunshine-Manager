import customtkinter as ctk
from tkinter import ttk, messagebox, scrolledtext
import requests
import subprocess
import threading
import time
import urllib3
import jwt
import os # Import du module os pour les opérations de fichiers

# Désactiver l'avertissement pour les certificats non vérifiés
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration Globale ---
# URL de l'API par défaut si aucune n'est sauvegardée
DEFAULT_API_URL = "https://api.caron.fun" 
MOONLIGHT_EXEC = "./moonlight_p/Moonlight.exe"
CONFIG_FILE = "client_config.txt" # Nom du fichier pour sauvegarder/charger l'URL

class EclypseApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Eclypse Client")
        self.root.geometry("800x600")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        self.token = None
        self.headers = None
        self.current_user = None
        self.user_role = None
        self.verify_ssl = False  # Par défaut, désactiver la vérification SSL
        
        # Charger l'URL de l'API au démarrage de l'application
        self.api_url = self._load_api_url()
        
        # Création du conteneur principal
        self.main_frame = ctk.CTkFrame(self.root)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Zone de connexion (visible au démarrage)
        self.setup_login_frame()
        
        # Zone principale (visible après connexion)
        self.content_frame = ctk.CTkFrame(self.main_frame)
        
        # Zone de logs
        self.log_frame = ctk.CTkFrame(self.root)
        self.log_frame.pack(fill="x", padx=10, pady=(0, 10), side="bottom")
        
        self.log_area = scrolledtext.ScrolledText(self.log_frame, height=6)
        self.log_area.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.log("Application démarrée.")
        self.log(f"URL de l'API actuelle: {self.api_url}")
    
    def _load_api_url(self):
        """Charge l'URL de l'API depuis un fichier de configuration.
        Si le fichier n'existe pas ou est vide, utilise l'URL par défaut."""
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    url = f.readline().strip()
                    if url:
                        return url
            except Exception as e:
                self.log(f"Erreur lors de la lecture du fichier de configuration: {str(e)}")
        return DEFAULT_API_URL

    def _save_api_url(self, url):
        """Sauvegarde l'URL de l'API dans un fichier de configuration."""
        try:
            with open(CONFIG_FILE, 'w') as f:
                f.write(url)
            self.log(f"URL de l'API sauvegardée: {url}")
        except Exception as e:
            self.log(f"Erreur lors de la sauvegarde de l'URL de l'API: {str(e)}")
    
    def setup_login_frame(self):
        """Configure l'écran de connexion"""
        self.login_frame = ctk.CTkFrame(self.main_frame)
        self.login_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        login_title = ctk.CTkLabel(self.login_frame, text="Connexion Eclypse", font=("Arial", 18))
        login_title.pack(pady=20)
        
        # --- Champ pour l'URL de l'API (initialement masqué) ---
        self.api_url_frame = ctk.CTkFrame(self.login_frame) # Nouveau cadre pour contenir le champ URL
        
        api_url_label = ctk.CTkLabel(self.api_url_frame, text="URL de l'API:")
        api_url_label.pack(pady=(10, 0))
        self.api_url_entry = ctk.CTkEntry(self.api_url_frame, width=300)
        self.api_url_entry.pack(pady=5)
        self.api_url_entry.insert(0, self.api_url) # Pré-remplir avec l'URL chargée
        
        # Champs de connexion
        username_label = ctk.CTkLabel(self.login_frame, text="Nom d'utilisateur:")
        username_label.pack(pady=(10, 0))
        self.username_entry = ctk.CTkEntry(self.login_frame, width=200)
        self.username_entry.pack(pady=5)
        
        password_label = ctk.CTkLabel(self.login_frame, text="Mot de passe:")
        password_label.pack(pady=(10, 0))
        self.password_entry = ctk.CTkEntry(self.login_frame, width=200, show="•")
        self.password_entry.pack(pady=5)
        
        # Option pour la vérification SSL
        ssl_frame = ctk.CTkFrame(self.login_frame)
        ssl_frame.pack(pady=10)
        
        self.ssl_var = ctk.BooleanVar(value=self.verify_ssl)  # Décocher par défaut
        self.ssl_checkbox = ctk.CTkCheckBox(ssl_frame, text="Vérifier les certificats SSL", 
                                            variable=self.ssl_var, 
                                            command=self.toggle_ssl_verification)
        self.ssl_checkbox.pack(side="left", padx=5)
        
        ssl_info_btn = ctk.CTkButton(ssl_frame, text="ℹ️", width=30, 
                                     command=self.show_ssl_info)
        ssl_info_btn.pack(side="left", padx=5)
        
        # --- Nouvelle checkbox pour l'URL de l'API ---
        self.show_api_url_var = ctk.BooleanVar(value=False) # Décochée par défaut
        self.show_api_url_checkbox = ctk.CTkCheckBox(
            self.login_frame, 
            text="Afficher le champ URL de l'API", 
            variable=self.show_api_url_var, 
            command=self.toggle_api_url_visibility
        )
        self.show_api_url_checkbox.pack(pady=5) # Placez-la sous les champs de connexion
        
        # Bouton de connexion
        login_button = ctk.CTkButton(self.login_frame, text="Se connecter", command=self.authenticate)
        login_button.pack(pady=20)
        
        # Afficher l'avertissement de sécurité si la vérification SSL est désactivée
        self.show_ssl_warning()

        # Masquer le champ URL de l'API au démarrage
        self.toggle_api_url_visibility() 
    
    def toggle_api_url_visibility(self):
        """Affiche ou masque le champ de saisie de l'URL de l'API."""
        if self.show_api_url_var.get():
            self.api_url_frame.pack(pady=5) # Affiche le cadre
        else:
            self.api_url_frame.pack_forget() # Masque le cadre

    def toggle_ssl_verification(self):
        """Active ou désactive la vérification SSL"""
        self.verify_ssl = self.ssl_var.get()
        self.log(f"Vérification SSL {'activée' if self.verify_ssl else 'désactivée'}")
        self.show_ssl_warning()
        
    def show_ssl_warning(self):
        """Affiche un avertissement si la vérification SSL est désactivée"""
        # Supprimer l'avertissement existant s'il y en a un
        for widget in self.login_frame.winfo_children():
            # Assurez-vous que c'est bien l'avertissement SSL et non d'autres widgets
            if hasattr(widget, 'ssl_warning_tag') and widget.ssl_warning_tag:
                widget.destroy()
                
        # Afficher un nouvel avertissement si nécessaire
        if not self.verify_ssl:
            warning_frame = ctk.CTkFrame(self.login_frame, fg_color="darkred")
            warning_frame.ssl_warning_tag = True # Tag pour identifier ce widget
            warning_frame.pack(fill="x", padx=20, pady=(0, 10))
            
            warning_text = ctk.CTkLabel(
                warning_frame, 
                text="⚠️ La vérification des certificats SSL est désactivée.\nCela peut présenter un risque de sécurité.",
                text_color="white"
            )
            warning_text.pack(pady=5)
    
    def show_ssl_info(self):
        """Affiche des informations sur la vérification SSL"""
        messagebox.showinfo(
            "Vérification SSL", 
            "La vérification des certificats SSL garantit que la connexion est sécurisée.\n\n"
            "Désactivez cette option uniquement si vous utilisez un certificat auto-signé "
            "ou si vous rencontrez des problèmes de connexion.\n\n"
            "Pour la production, il est recommandé de garder cette option activée."
        )
    
    def setup_admin_interface(self):
        """Configure l'interface administrateur"""
        self.content_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Création d'onglets pour les différentes fonctions admin
        self.tabs = ctk.CTkTabview(self.content_frame)
        self.tabs.pack(fill="both", expand=True)
        
        # Onglet de gestion des utilisateurs
        self.users_tab = self.tabs.add("Utilisateurs")
        self.setup_users_tab()
        
        # Onglet de gestion des VMs
        self.vms_tab = self.tabs.add("Machines virtuelles")
        self.setup_vms_tab()
        
        # Onglet d'association VM-Utilisateur
        self.assign_tab = self.tabs.add("Assignation")
        self.setup_assign_tab()
        
        # Onglet pour la connexion aux VMs (comme un utilisateur normal)
        self.connect_tab = self.tabs.add("Connexion VM")
        self.setup_connect_tab()
        
        # Charger les données des utilisateurs et des VMs
        self.load_users()
        self.load_vms()
    
    def setup_user_interface(self):
        """Configure l'interface utilisateur normal"""
        self.content_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Interface simple pour les utilisateurs: juste la liste de leurs VMs
        vm_label = ctk.CTkLabel(self.content_frame, text="Vos machines virtuelles:", font=("Arial", 14))
        vm_label.pack(pady=(10, 5), anchor="w")
        
        # Liste des VMs
        self.vm_list_frame = ctk.CTkFrame(self.content_frame)
        self.vm_list_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Bouton de connexion
        self.connect_button = ctk.CTkButton(self.content_frame, text="Se connecter à la VM", command=self.connect_to_vm)
        self.connect_button.pack(pady=10)
        
        # Rafraîchir la liste des VMs de l'utilisateur
        self.load_user_vms()
    
    def setup_users_tab(self):
        """Configure l'onglet de gestion des utilisateurs"""
        # Zone de liste d'utilisateurs
        list_frame = ctk.CTkFrame(self.users_tab)
        list_frame.pack(fill="both", expand=True, side="left", padx=5, pady=5)
        
        list_label = ctk.CTkLabel(list_frame, text="Utilisateurs:", font=("Arial", 12))
        list_label.pack(pady=5, anchor="w")
        
        self.users_listbox = ttk.Treeview(list_frame, columns=("id", "username", "role"), show="headings")
        self.users_listbox.heading("id", text="ID")
        self.users_listbox.heading("username", text="Nom")
        self.users_listbox.heading("role", text="Rôle")
        self.users_listbox.column("id", width=50)
        self.users_listbox.column("username", width=150)
        self.users_listbox.column("role", width=100)
        self.users_listbox.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Boutons d'action
        action_frame = ctk.CTkFrame(list_frame)
        action_frame.pack(fill="x", pady=5)
        
        reload_btn = ctk.CTkButton(action_frame, text="Actualiser", command=self.load_users)
        reload_btn.pack(side="left", padx=5)
        
        delete_btn = ctk.CTkButton(action_frame, text="Supprimer", fg_color="red", command=self.delete_user)
        delete_btn.pack(side="right", padx=5)
        
        # Zone de création d'utilisateur
        create_frame = ctk.CTkFrame(self.users_tab)
        create_frame.pack(fill="y", side="right", padx=5, pady=5)
        
        create_label = ctk.CTkLabel(create_frame, text="Nouvel utilisateur:", font=("Arial", 12))
        create_label.pack(pady=5, anchor="w")
        
        # Champs pour nouvel utilisateur
        username_label = ctk.CTkLabel(create_frame, text="Nom d'utilisateur:")
        username_label.pack(pady=(10, 0))
        self.new_username = ctk.CTkEntry(create_frame, width=150)
        self.new_username.pack(pady=2)
        
        password_label = ctk.CTkLabel(create_frame, text="Mot de passe:")
        password_label.pack(pady=(10, 0))
        self.new_password = ctk.CTkEntry(create_frame, width=150, show="•")
        self.new_password.pack(pady=2)
        
        role_label = ctk.CTkLabel(create_frame, text="Rôle:")
        role_label.pack(pady=(10, 0))
        self.new_role = ctk.CTkComboBox(create_frame, width=150, values=["user", "admin", "master"])
        self.new_role.pack(pady=2)
        
        # Bouton de création
        create_btn = ctk.CTkButton(create_frame, text="Créer utilisateur", command=self.create_user)
        create_btn.pack(pady=20)
    
    def setup_vms_tab(self):
        """Configure l'onglet de gestion des VMs"""
        # Liste des VMs
        self.vms_treeview = ttk.Treeview(self.vms_tab, columns=("id", "hostname", "ip"), show="headings")
        self.vms_treeview.heading("id", text="ID")
        self.vms_treeview.heading("hostname", text="Nom d'hôte")
        self.vms_treeview.heading("ip", text="Adresse IP")
        self.vms_treeview.column("id", width=50)
        self.vms_treeview.column("hostname", width=150)
        self.vms_treeview.column("ip", width=150)
        self.vms_treeview.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Bouton d'actualisation
        refresh_btn = ctk.CTkButton(self.vms_tab, text="Actualiser VMs", command=self.load_vms)
        refresh_btn.pack(pady=10)
    
    def setup_assign_tab(self):
        """Configure l'onglet d'assignation VM-Utilisateur"""
        # Section utilisateur
        user_frame = ctk.CTkFrame(self.assign_tab)
        user_frame.pack(fill="x", padx=5, pady=5)
        
        user_label = ctk.CTkLabel(user_frame, text="Utilisateur:")
        user_label.pack(side="left", padx=5)
        
        self.assign_user = ctk.CTkComboBox(user_frame, width=200, values=[])
        self.assign_user.pack(side="left", padx=5)
        
        # Section VM
        vm_frame = ctk.CTkFrame(self.assign_tab)
        vm_frame.pack(fill="x", padx=5, pady=5)
        
        vm_label = ctk.CTkLabel(vm_frame, text="Machine virtuelle:")
        vm_label.pack(side="left", padx=5)
        
        self.assign_vm = ctk.CTkComboBox(vm_frame, width=200, values=[])
        self.assign_vm.pack(side="left", padx=5)
        
        # Bouton d'assignation
        assign_btn = ctk.CTkButton(self.assign_tab, text="Assigner VM à l'utilisateur", command=self.assign_vm_to_user)
        assign_btn.pack(pady=10)
        
        # Liste des assignations existantes
        assign_label = ctk.CTkLabel(self.assign_tab, text="Assignations existantes:", font=("Arial", 12))
        assign_label.pack(pady=5, anchor="w")
        
        self.assign_treeview = ttk.Treeview(self.assign_tab, columns=("user", "vm"), show="headings")
        self.assign_treeview.heading("user", text="Utilisateur")
        self.assign_treeview.heading("vm", text="Machine virtuelle")
        self.assign_treeview.column("user", width=150)
        self.assign_treeview.column("vm", width=150)
        self.assign_treeview.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Bouton pour supprimer une assignation
        unassign_btn = ctk.CTkButton(self.assign_tab, text="Supprimer assignation", fg_color="red", command=self.unassign_vm)
        unassign_btn.pack(pady=10)

        # Bouton d'actualisation des assignations
        refresh_assign_btn = ctk.CTkButton(self.assign_tab, text="Actualiser Assignations", command=self.load_assignments)
        refresh_assign_btn.pack(pady=5)
    
    def setup_connect_tab(self):
        """Configure l'onglet de connexion aux VMs (pour admin)"""
        # Liste des VMs accessibles
        vm_label = ctk.CTkLabel(self.connect_tab, text="Vos machines virtuelles:", font=("Arial", 12))
        vm_label.pack(pady=(10, 5), anchor="w")
        
        self.admin_vm_treeview = ttk.Treeview(self.connect_tab, columns=("id", "hostname", "ip"), show="headings")
        self.admin_vm_treeview.heading("id", text="ID")
        self.admin_vm_treeview.heading("hostname", text="Nom d'hôte")
        self.admin_vm_treeview.heading("ip", text="Adresse IP")
        self.admin_vm_treeview.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Boutons d'action
        action_frame = ctk.CTkFrame(self.connect_tab)
        action_frame.pack(fill="x", pady=5)
        
        refresh_btn = ctk.CTkButton(action_frame, text="Actualiser", command=self.load_admin_vms)
        refresh_btn.pack(side="left", padx=5)
        
        connect_btn = ctk.CTkButton(action_frame, text="Se connecter", command=self.connect_to_vm)
        connect_btn.pack(side="right", padx=5)
    
    def authenticate(self):
        """Authentifie l'utilisateur et charge l'interface appropriée"""
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Erreur", "Veuillez entrer un nom d'utilisateur et un mot de passe")
            return
        
        # Récupérer l'URL de l'API depuis le champ de saisie et la sauvegarder si elle a changé
        new_api_url = self.api_url_entry.get().strip()
        if new_api_url and new_api_url != self.api_url:
            self.api_url = new_api_url
            self._save_api_url(self.api_url) # Sauvegarder la nouvelle URL
            self.log(f"URL de l'API mise à jour vers: {self.api_url}")
        
        # Récupérer la valeur actuelle de la vérification SSL
        self.verify_ssl = self.ssl_var.get()
        
        self.log(f"Tentative de connexion pour {username}...")
        self.log(f"Vérification SSL: {'activée' if self.verify_ssl else 'désactivée'}")
        
        try:
            response = requests.post(
                f"{self.api_url}/auth/token", # Utiliser self.api_url
                json={"username": username, "password": password},
                verify=self.verify_ssl
            )
            
            if response.status_code != 200:
                self.log(f"Échec d'authentification: {response.text}")
                messagebox.showerror("Erreur", f"Authentification échouée: {response.status_code}")
                return
            
            token_data = response.json()
            self.token = token_data["access_token"]
            self.headers = {"Authorization": f"Bearer {self.token}"}
            
            # Obtenir les infos utilisateur à partir du token
            token_info = jwt.decode(self.token, options={"verify_signature": False})
            self.current_user = token_info.get("sub", "unknown")
            self.user_role = token_info.get("role", "user")
            
            self.log(f"Connexion réussie pour {self.current_user} (rôle: {self.user_role})")
            
            # Supprimer le cadre de connexion
            self.login_frame.destroy()
            
            # Afficher l'interface appropriée selon le rôle
            if self.user_role in ["admin", "master"]:
                self.setup_admin_interface()
            else:
                self.setup_user_interface()
                
        except Exception as e:
            self.log(f"Erreur lors de l'authentification: {str(e)}")
            messagebox.showerror("Erreur", f"Erreur de connexion: {str(e)}")
    
    def load_users(self):
        """Charge la liste des utilisateurs (pour admin)"""
        if not self.headers:
            return
            
        self.log("Chargement de la liste des utilisateurs...")
        try:
            response = requests.get(f"{self.api_url}/admin/users", headers=self.headers, verify=self.verify_ssl) # Utiliser self.api_url
            
            if response.status_code != 200:
                self.log(f"Échec du chargement des utilisateurs: {response.text}")
                return
                
            users = response.json()
            
            # Effacer la liste actuelle
            for item in self.users_listbox.get_children():
                self.users_listbox.delete(item)
                
            # Remplir avec les nouvelles données
            for user in users:
                self.users_listbox.insert("", "end", values=(user["id"], user["username"], user["role"]))
                
            # Mettre à jour le combobox d'assignation
            self.assign_user.configure(values=[f"{user['id']}: {user['username']}" for user in users])
            if users:
                self.assign_user.set(f"{users[0]['id']}: {users[0]['username']}")
                
            self.log(f"{len(users)} utilisateurs chargés.")
            
        except Exception as e:
            self.log(f"Erreur lors du chargement des utilisateurs: {str(e)}")
    
    def load_vms(self):
        """Charge la liste des VMs"""
        if not self.headers:
            return
            
        self.log("Chargement de la liste des VMs...")
        try:
            response = requests.get(f"{self.api_url}/vm/list", headers=self.headers, verify=self.verify_ssl) # Utiliser self.api_url
            
            if response.status_code != 200:
                self.log(f"Échec du chargement des VMs: {response.text}")
                return
                
            vms = response.json()
            
            # Effacer la liste actuelle
            for item in self.vms_treeview.get_children():
                self.vms_treeview.delete(item)
                
            # Remplir avec les nouvelles données
            for vm in vms:
                self.vms_treeview.insert("", "end", values=(vm["id"], vm["hostname"], vm["ip_address"]))
                
            # Mettre à jour le combobox d'assignation
            self.assign_vm.configure(values=[f"{vm['id']}: {vm['hostname']}" for vm in vms])
            if vms:
                self.assign_vm.set(f"{vms[0]['id']}: {vms[0]['hostname']}")
                
            self.log(f"{len(vms)} VMs chargées.")
            
        except Exception as e:
            self.log(f"Erreur lors du chargement des VMs: {str(e)}")
    
    def load_user_vms(self):
        """Charge les VMs assignées à l'utilisateur actuel"""
        if not self.headers:
            return
            
        self.log("Chargement de vos machines virtuelles...")
        try:
            response = requests.get(f"{self.api_url}/vm/list", headers=self.headers, verify=self.verify_ssl) # Utiliser self.api_url
            
            if response.status_code != 200:
                self.log(f"Échec du chargement des VMs: {response.text}")
                return
                
            vms = response.json()
            
            # Effacer la liste actuelle
            for widget in self.vm_list_frame.winfo_children():
                widget.destroy()
                
            # Si aucune VM
            if not vms:
                no_vm_label = ctk.CTkLabel(self.vm_list_frame, text="Aucune machine virtuelle assignée")
                no_vm_label.pack(pady=20)
                self.connect_button.configure(state="disabled")
                return
                
            # Créer des boutons radio pour chaque VM
            self.selected_vm = ctk.StringVar(value=str(vms[0]["id"]))
            for vm in vms:
                vm_radio = ctk.CTkRadioButton(
                    self.vm_list_frame,
                    text=f"{vm['hostname']} ({vm['ip_address']})",
                    variable=self.selected_vm,
                    value=str(vm["id"])
                )
                vm_radio.pack(anchor="w", pady=5)
                
            self.connect_button.configure(state="normal")
            self.log(f"{len(vms)} VMs assignées chargées.")
            
        except Exception as e:
            self.log(f"Erreur lors du chargement des VMs: {str(e)}")
    
    def load_admin_vms(self):
        """Charge les VMs pour l'admin dans l'onglet de connexion"""
        if not self.headers:
            return
            
        self.log("Chargement des VMs pour connexion...")
        try:
            response = requests.get(f"{self.api_url}/vm/list", headers=self.headers, verify=self.verify_ssl) # Utiliser self.api_url
            
            if response.status_code != 200:
                self.log(f"Échec du chargement des VMs: {response.text}")
                return
                
            vms = response.json()
            
            # Effacer la liste actuelle
            for item in self.admin_vm_treeview.get_children():
                self.admin_vm_treeview.delete(item)
                
            # Remplir avec les nouvelles données
            for vm in vms:
                self.admin_vm_treeview.insert("", "end", values=(vm["id"], vm["hostname"], vm["ip_address"]))
                
            self.log(f"{len(vms)} VMs chargées pour connexion.")
            
        except Exception as e:
            self.log(f"Erreur lors du chargement des VMs: {str(e)}")
    
    def create_user(self):
        """Crée un nouvel utilisateur"""
        username = self.new_username.get()
        password = self.new_password.get()
        role = self.new_role.get()
        
        if not username or not password or not role:
            messagebox.showerror("Erreur", "Veuillez remplir tous les champs")
            return
            
        self.log(f"Création de l'utilisateur {username} avec rôle {role}...")
        try:
            response = requests.post(
                f"{self.api_url}/auth/register", # Utiliser self.api_url
                headers=self.headers,
                json={"username": username, "password": password, "role": role},
                verify=self.verify_ssl
            )
            
            if response.status_code != 200:
                self.log(f"Échec de création de l'utilisateur: {response.text}")
                messagebox.showerror("Erreur", f"Création utilisateur échouée: {response.status_code}")
                return
                
            self.log(f"Utilisateur {username} créé avec succès")
            messagebox.showinfo("Succès", f"Utilisateur {username} créé")
            
            # Vider les champs
            self.new_username.delete(0, 'end')
            self.new_password.delete(0, 'end')
            
            # Rafraîchir la liste
            self.load_users()
            
        except Exception as e:
            self.log(f"Erreur lors de la création de l'utilisateur: {str(e)}")
            messagebox.showerror("Erreur", f"Erreur de création: {str(e)}")
    
    def delete_user(self):
        """Supprime un utilisateur sélectionné"""
        selected = self.users_listbox.selection()
        if not selected:
            messagebox.showwarning("Avertissement", "Veuillez sélectionner un utilisateur")
            return
            
        user_id = self.users_listbox.item(selected[0])['values'][0]
        username = self.users_listbox.item(selected[0])['values'][1]
        
        if username == self.current_user:
            messagebox.showerror("Erreur", "Vous ne pouvez pas supprimer votre propre compte")
            return
            
        if not messagebox.askyesno("Confirmation", f"Voulez-vous vraiment supprimer l'utilisateur {username}?"):
            return
            
        self.log(f"Suppression de l'utilisateur {username} (ID: {user_id})...")
        try:
            response = requests.delete(
                f"{self.api_url}/admin/user/{user_id}", # Utiliser self.api_url
                headers=self.headers,
                verify=self.verify_ssl
            )
            
            if response.status_code != 200:
                self.log(f"Échec de suppression de l'utilisateur: {response.text}")
                messagebox.showerror("Erreur", f"Suppression échouée: {response.status_code}")
                return
                
            self.log(f"Utilisateur {username} supprimé avec succès")
            messagebox.showinfo("Succès", f"Utilisateur {username} supprimé")
            
            # Rafraîchir la liste
            self.load_users()
            
        except Exception as e:
            self.log(f"Erreur lors de la suppression de l'utilisateur: {str(e)}")
            messagebox.showerror("Erreur", f"Erreur de suppression: {str(e)}")
    
    def load_assignments(self):
        """Charge la liste des assignations VM-Utilisateur (version optimisée)"""
        if not self.headers:
            return

        self.log("Chargement des assignations existantes...")
        try:
            response = requests.get(f"{self.api_url}/vm/assignments", headers=self.headers, verify=self.verify_ssl) # Utiliser self.api_url

            if response.status_code != 200:
                self.log(f"Échec du chargement des assignations: {response.text}")
                return

            assignments = response.json()

            # Effacer la liste actuelle
            for item in self.assign_treeview.get_children():
                self.assign_treeview.delete(item)

            # Remplir avec les nouvelles données
            for assign in assignments:
                # Créer un ID unique pour l'assignation
                assignment_id = f"assign_{assign['user_id']}_{assign['vm_id']}"
                self.assign_treeview.insert(
                    "", "end", 
                    values=(assign["username"], assign["vm_hostname"]), 
                    iid=assignment_id  # Définir explicitement l'iid
                )

            self.log(f"{len(assignments)} assignations chargées.")

        except Exception as e:
            self.log(f"Erreur lors du chargement des assignations: {str(e)}")
    
    def assign_vm_to_user(self):
        """Assigne une VM à un utilisateur"""
        user_selection = self.assign_user.get()
        vm_selection = self.assign_vm.get()
        
        if not user_selection or not vm_selection:
            messagebox.showwarning("Avertissement", "Veuillez sélectionner un utilisateur et une VM")
            return
            
        # Extraire les IDs
        user_id = int(user_selection.split(":")[0])
        vm_id = int(vm_selection.split(":")[0])
        
        self.log(f"Assignation de la VM {vm_id} à l'utilisateur {user_id}...")
        try:
            response = requests.post(
                f"{self.api_url}/vm/assign", # Utiliser self.api_url
                headers=self.headers,
                json={"user_id": user_id, "vm_id": vm_id},
                verify=self.verify_ssl
            )
            
            if response.status_code != 200:
                self.log(f"Échec d'assignation: {response.text}")
                messagebox.showerror("Erreur", f"Assignation échouée: {response.status_code}")
                return
                
            result = response.json()
            self.log(f"Assignation réussie: {result.get('msg', 'OK')}")
            messagebox.showinfo("Succès", "VM assignée avec succès")
            
            # Rafraîchir la liste des assignations après un succès
            self.load_assignments()
            
        except Exception as e:
            self.log(f"Erreur lors de l'assignation: {str(e)}")
            messagebox.showerror("Erreur", f"Erreur d'assignation: {str(e)}")
    
    def unassign_vm(self):
        """Supprime une assignation VM-utilisateur (version fonctionnelle)"""
        selected = self.assign_treeview.selection()
        if not selected:
            messagebox.showwarning("Avertissement", "Veuillez sélectionner une assignation")
            return
        
        # Récupérer l'ID de l'assignation depuis l'iid
        assignment_id = selected[0]  # L'iid est directement l'ID de l'item
        username = self.assign_treeview.item(selected[0])['values'][0]
        vm_hostname = self.assign_treeview.item(selected[0])['values'][1]

        if not messagebox.askyesno("Confirmation", f"Voulez-vous vraiment supprimer l'assignation de {vm_hostname} à {username}?"):
            return

        # Extraire user_id et vm_id de l'ID d'assignation
        try:
            # L'ID est au format "assign_userId_vmId"
            parts = assignment_id.split('_')
            if len(parts) != 3 or parts[0] != 'assign':
                raise ValueError("Format d'ID d'assignation invalide")
            
            user_id = int(parts[1])
            vm_id = int(parts[2])
            
        except (ValueError, IndexError) as e:
            self.log(f"Erreur lors de l'extraction des IDs: {e}")
            messagebox.showerror("Erreur", "Impossible de déterminer l'assignation à supprimer")
            return

        self.log(f"Tentative de suppression de l'assignation ({username} - {vm_hostname})...")
        
        try:
            delete_response = requests.delete(
                f"{self.api_url}/vm/unassign", # Utiliser self.api_url
                headers=self.headers,
                json={
                    "user_id": user_id,
                    "vm_id": vm_id
                },
                verify=self.verify_ssl
            )
            
            if delete_response.status_code != 200:
                self.log(f"Échec de suppression de l'assignation: {delete_response.text}")
                messagebox.showerror("Erreur", f"Suppression échouée: {delete_response.status_code}")
                return

            result = delete_response.json()
            self.log(f"Assignation supprimée avec succès: {result.get('msg', 'OK')}")
            messagebox.showinfo("Succès", "Assignation supprimée avec succès")
            
            # Rafraîchir la liste des assignations
            self.load_assignments()

        except requests.exceptions.RequestException as e:
            self.log(f"Erreur de communication avec l'API lors de la suppression: {e}")
            messagebox.showerror("Erreur API", f"Impossible de communiquer avec l'API.\nErreur: {e}")
        except Exception as e:
            self.log(f"Erreur inattendue lors de la suppression de l'assignation: {e}")
            messagebox.showerror("Erreur", f"Une erreur inattendue est survenue: {e}")
    
    def connect_to_vm(self):
        """Se connecte à la VM sélectionnée (utilisateur normal ET admin)"""
        vm_id = None
        
        # Déterminer quelle interface est utilisée
        if hasattr(self, 'selected_vm'):
            # Interface utilisateur normal (boutons radio)
            vm_id = self.selected_vm.get()
        else:
            # Interface admin (treeview)
            selected = self.admin_vm_treeview.selection()
            if not selected:
                messagebox.showwarning("Avertissement", "Veuillez sélectionner une VM")
                return
            vm_id = self.admin_vm_treeview.item(selected[0])['values'][0]
        
        if not vm_id:
            messagebox.showwarning("Avertissement", "Veuillez sélectionner une VM")
            return
        
        self.log(f"Préparation de la connexion à la VM {vm_id}...")
        
        # Lancer le processus de pairing et de streaming dans un thread
        threading.Thread(target=self.pairing_process, args=(vm_id,), daemon=True).start()
    
    def pairing_process(self, vm_id):
        """Gère le processus de pairing avec Sunshine"""
        try:
            # Récupérer les informations de la VM
            response = requests.get(f"{self.api_url}/vm/list", headers=self.headers, verify=self.verify_ssl)
            if response.status_code != 200:
                self.log(f"Échec de récupération des infos VM: {response.text}")
                return
                
            vms = response.json()
            
            # Chercher la VM par ID (convertir en string pour la comparaison)
            vm = None
            for vm_data in vms:
                if str(vm_data["id"]) == str(vm_id):
                    vm = vm_data
                    break
            
            if not vm:
                self.log(f"VM {vm_id} non trouvée dans la liste des VMs accessibles")
                self.log(f"VMs disponibles: {[v['id'] for v in vms]}")
                return
                
            ip = vm["ip_address"]
            
            # Préparer le pairing
            pair_init_response = requests.post(
                f"{self.api_url}/vm/prepare-pairing",
                headers=self.headers,
                json={"vm_id": int(vm_id)},
                verify=self.verify_ssl
            )
            
            if pair_init_response.status_code != 200:
                self.log(f"Échec de préparation du pairing: {pair_init_response.text}")
                return
                
            pairing_data = pair_init_response.json()
            pin = pairing_data.get("pin")
            
            if not pin:
                self.log("PIN non reçu du serveur")
                return
                
            self.log(f"PIN reçu: {pin}")
            
            # Lancer Moonlight pour le pairing
            self.log("Lancement du pairing Moonlight...")
            pair_cmd = [MOONLIGHT_EXEC, "pair", ip, "-pin", pin]
            self.log(f"Commande: {' '.join(pair_cmd)}")
            
            moonlight_process = subprocess.Popen(pair_cmd)
            
            # Court délai pour que Moonlight démarre (côté client)
            time.sleep(5)
            
            # Envoyer le PIN à Sunshine via l'API FastAPI
            self.log("Envoi du PIN à Sunshine...")
            pair_response = requests.post(
                f"{self.api_url}/vm/complete-pairing",
                headers=self.headers,
                json={"vm_id": int(vm_id), "pin": pin},
                verify=self.verify_ssl
            )
            
            if pair_response.status_code != 200:
                self.log(f"Échec de complétion du pairing: {pair_response.text}")
                moonlight_process.terminate()
                return
            
            # Attendre que le processus Moonlight se termine
            return_code = moonlight_process.wait()
            if return_code != 0:
                self.log(f"Échec du pairing Moonlight avec code {return_code}")
                return
                
            self.log("Pairing complété avec succès!")
            
            # Lancer le streaming
            self.log("Démarrage du streaming...")
            stream_cmd = [MOONLIGHT_EXEC, "stream", ip, "Desktop"]
            self.log(f"Commande: {' '.join(stream_cmd)}")
            
            subprocess.run(stream_cmd, check=True)
            self.log("Session de streaming terminée")
            
        except Exception as e:
            self.log(f"Erreur lors du processus de pairing: {str(e)}")
    
    def log(self, message):
        """Ajoute un message dans la zone de logs"""
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_area.insert("end", f"[{timestamp}] {message}\n")
        self.log_area.see("end")  # Défiler jusqu'à la fin

def main():
    root = ctk.CTk()
    app = EclypseApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
