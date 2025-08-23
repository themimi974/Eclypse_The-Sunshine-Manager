import customtkinter as ctk
from tkinter import messagebox, scrolledtext
import requests
import jwt # Pour décoder le token et afficher l'utilisateur connecté
import urllib3 # Pour désactiver les avertissements SSL

# Désactiver les avertissements pour les certificats non vérifiés
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration ---
API_URL = "https://localhost" # L'API écoute directement sur le port 443
# Si tu utilises api.caron.fun avec une entrée hosts, tu peux mettre:
# API_URL = "https://api.caron.fun"

class AddVMMangerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Eclypse: Ajouter une Machine Virtuelle")
        self.root.geometry("600x650")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.token = None
        self.headers = None
        self.current_user_role = None
        self.verify_ssl = False # Par défaut, désactiver la vérification SSL pour les certificats auto-signés

        # --- Cadre principal ---
        self.main_frame = ctk.CTkFrame(self.root)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # --- Zone de logs ---
        self.log_frame = ctk.CTkFrame(self.root)
        self.log_frame.pack(fill="x", padx=10, pady=(0, 10), side="bottom")
        self.log_area = scrolledtext.ScrolledText(self.log_frame, height=5, state='disabled')
        self.log_area.pack(fill="both", expand=True, padx=5, pady=5)
        self.log("Application 'Ajouter VM' démarrée.")

        # --- Écran de connexion ---
        self.setup_login_frame()

    def log(self, message):
        """Ajoute un message dans la zone de logs."""
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_area.configure(state='normal') # Activer l'édition
        self.log_area.insert("end", f"[{timestamp}] {message}\n")
        self.log_area.see("end") # Défiler jusqu'à la fin
        self.log_area.configure(state='disabled') # Désactiver l'édition

    def setup_login_frame(self):
        """Configure l'interface de connexion pour obtenir le token admin."""
        self.login_frame = ctk.CTkFrame(self.main_frame)
        self.login_frame.pack(fill="both", expand=True, padx=20, pady=20)

        title_label = ctk.CTkLabel(self.login_frame, text="Connexion Admin API", font=("Arial", 20, "bold"))
        title_label.pack(pady=20)

        ctk.CTkLabel(self.login_frame, text="Nom d'utilisateur Admin:").pack(pady=(10, 0))
        self.username_entry = ctk.CTkEntry(self.login_frame, width=250)
        self.username_entry.pack(pady=5)
        self.username_entry.insert(0, "admin") # Remplir par défaut "admin"

        ctk.CTkLabel(self.login_frame, text="Mot de passe Admin:").pack(pady=(10, 0))
        self.password_entry = ctk.CTkEntry(self.login_frame, width=250, show="•")
        self.password_entry.pack(pady=5)
        self.password_entry.insert(0, "Test1234") # Remplir par défaut "Test1234"

        ssl_frame = ctk.CTkFrame(self.login_frame)
        ssl_frame.pack(pady=10)
        self.ssl_var = ctk.BooleanVar(value=self.verify_ssl) # Utilise la valeur par défaut
        self.ssl_checkbox = ctk.CTkCheckBox(ssl_frame, text="Vérifier les certificats SSL",
                                            variable=self.ssl_var,
                                            command=self.toggle_ssl_verification)
        self.ssl_checkbox.pack(side="left", padx=5)

        login_button = ctk.CTkButton(self.login_frame, text="Se connecter", command=self.authenticate)
        login_button.pack(pady=20)

        self.show_ssl_warning()

    def toggle_ssl_verification(self):
        """Active ou désactive la vérification SSL."""
        self.verify_ssl = self.ssl_var.get()
        self.log(f"Vérification SSL {'activée' if self.verify_ssl else 'désactivée'}")
        self.show_ssl_warning()

    def show_ssl_warning(self):
        """Affiche un avertissement si la vérification SSL est désactivée."""
        for widget in self.login_frame.winfo_children():
            if hasattr(widget, 'ssl_warning_tag') and widget.ssl_warning_tag:
                widget.destroy()

        if not self.verify_ssl:
            warning_frame = ctk.CTkFrame(self.login_frame, fg_color="darkred")
            warning_frame.ssl_warning_tag = True
            warning_frame.pack(fill="x", padx=20, pady=(0, 10))
            warning_text = ctk.CTkLabel(
                warning_frame,
                text="⚠️ La vérification des certificats SSL est désactivée.\nCela peut présenter un risque de sécurité.",
                text_color="white"
            )
            warning_text.pack(pady=5)

    def authenticate(self):
        """Tente d'authentifier l'utilisateur admin."""
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showerror("Erreur", "Veuillez entrer un nom d'utilisateur et un mot de passe.")
            return

        self.log(f"Tentative de connexion pour {username}...")
        try:
            response = requests.post(
                f"{API_URL}/auth/token",
                json={"username": username, "password": password},
                verify=self.verify_ssl # Utilise la valeur de la checkbox
            )

            if response.status_code != 200:
                self.log(f"Échec d'authentification: {response.status_code} - {response.text}")
                messagebox.showerror("Erreur d'authentification", f"Échec: {response.status_code}\n{response.json().get('detail', 'Erreur inconnue')}")
                return

            token_data = response.json()
            self.token = token_data["access_token"]
            self.headers = {"Authorization": f"Bearer {self.token}"}

            # Décodage du token pour obtenir le rôle (pour s'assurer que c'est un admin/master)
            token_info = jwt.decode(self.token, options={"verify_signature": False})
            self.current_user_role = token_info.get("role")

            if self.current_user_role not in ["admin", "master"]:
                messagebox.showerror("Accès refusé", "Seuls les utilisateurs avec le rôle 'admin' ou 'master' peuvent utiliser cet outil.")
                self.log(f"Connexion réussie pour {username}, mais rôle ({self.current_user_role}) non autorisé.")
                self.token = None
                self.headers = None
                return

            self.log(f"Authentification réussie pour {username} (rôle: {self.current_user_role}).")
            messagebox.showinfo("Succès", f"Authentifié en tant que {username}.")

            self.login_frame.destroy() # Détruit le cadre de connexion
            self.setup_add_vm_frame() # Affiche l'interface d'ajout de VM

        except requests.exceptions.ConnectionError as e:
            self.log(f"Erreur de connexion à l'API: {e}")
            messagebox.showerror("Erreur de connexion", f"Impossible de se connecter à l'API à {API_URL}.\nVérifiez que le serveur est démarré et que le port est accessible.\n\nErreur: {e}")
        except Exception as e:
            self.log(f"Erreur inattendue lors de l'authentification: {e}")
            messagebox.showerror("Erreur", f"Une erreur inattendue est survenue: {e}")

    def setup_add_vm_frame(self):
        """Configure l'interface pour l'ajout de machines virtuelles."""
        self.add_vm_frame = ctk.CTkFrame(self.main_frame)
        self.add_vm_frame.pack(fill="both", expand=True, padx=20, pady=20)

        title_label = ctk.CTkLabel(self.add_vm_frame, text="Ajouter une Nouvelle Machine Virtuelle", font=("Arial", 20, "bold"))
        title_label.pack(pady=20)

        # Champs de saisie
        self.entries = {}
        fields = {
            "hostname": "Nom d'hôte:",
            "ip_address": "Adresse IP:",
            "sunshine_user": "Utilisateur Sunshine:",
            "sunshine_password": "Mot de passe Sunshine:",
        }

        for key, label_text in fields.items():
            frame = ctk.CTkFrame(self.add_vm_frame)
            frame.pack(fill="x", pady=5)
            ctk.CTkLabel(frame, text=label_text, width=150, anchor="w").pack(side="left", padx=5)
            entry = ctk.CTkEntry(frame, width=300)
            entry.pack(side="left", padx=5, fill="x", expand=True)
            self.entries[key] = entry

        add_button = ctk.CTkButton(self.add_vm_frame, text="Ajouter la VM", command=self.add_vm)
        add_button.pack(pady=20)

        back_button = ctk.CTkButton(self.add_vm_frame, text="Déconnexion", command=self.logout)
        back_button.pack(pady=5)

    def add_vm(self):
        """Récupère les données et envoie la requête à l'API pour enregistrer la VM."""
        vm_data = {key: entry.get().strip() for key, entry in self.entries.items()}

        # Vérification simple des champs
        for key, value in vm_data.items():
            if not value:
                messagebox.showerror("Erreur de saisie", f"Le champ '{key.replace('_', ' ').capitalize()}' ne peut pas être vide.")
                return

        self.log(f"Tentative d'ajout de la VM '{vm_data['hostname']}'...")
        try:
            response = requests.post(
                f"{API_URL}/vm/register",
                headers=self.headers,
                json=vm_data,
                verify=self.verify_ssl # Utilise la valeur de la checkbox
            )

            if response.status_code != 200:
                self.log(f"Échec d'ajout de la VM: {response.status_code} - {response.text}")
                messagebox.showerror("Erreur d'ajout de VM", f"Échec: {response.status_code}\n{response.json().get('detail', 'Erreur inconnue')}")
                return

            result = response.json()
            self.log(f"VM '{result['hostname']}' ajoutée avec succès (ID: {result['id']}).")
            messagebox.showinfo("Succès", f"VM '{result['hostname']}' ajoutée avec succès!")

            # Effacer les champs après l'ajout réussi
            for entry in self.entries.values():
                entry.delete(0, ctk.END)

        except requests.exceptions.RequestException as e:
            self.log(f"Erreur de communication avec l'API: {e}")
            messagebox.showerror("Erreur API", f"Impossible de communiquer avec l'API.\nErreur: {e}")
        except Exception as e:
            self.log(f"Erreur inattendue lors de l'ajout de la VM: {e}")
            messagebox.showerror("Erreur", f"Une erreur inattendue est survenue: {e}")

    def logout(self):
        """Déconnecte l'utilisateur et retourne à l'écran de connexion."""
        self.token = None
        self.headers = None
        self.current_user_role = None
        self.add_vm_frame.destroy()
        self.setup_login_frame()
        self.log("Déconnecté.")

def main():
    root = ctk.CTk()
    app = AddVMMangerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()