### 1. Register Sunshine Servers
- Use client\add_vm_gui.py or AddVMTool.exe
(Python with customtkinter requests PyJWT urllib3 is required)

- Log in as an admin/master user

![VM Authentication](docs/img/add_vm_auth.png)

- Provide hostname, IP address, and Sunshine credentials

![Add VM Interface](docs/img/add_vm_added.png)

---

### 2. Create User Accounts
- Use client\eclypse.py or EclypseClient.exe
- Sign in as a default admin

![Eclypse Login](docs/img/eclypse_login.png)

- Create User account in user tab

![User Creation Interface](docs/img/eclypse_user_creation.png)

---

### 3. Assign VMs to Users
- Users will only see VMs they're authorized to access

![User Creation Interface](docs/img/eclypse_assignations.png)

---

### 4. Client Pairing
- Use client\eclypse.py or EclypseClient.exe
- Sign in as a user (without admin privileges)

![Eclypse Login](docs/img/eclypse_login.png)

- Connect to the VM

![Eclypse Login](docs/img/connect.png)
