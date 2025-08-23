<div align="center">
  <img src="https://raw.githubusercontent.com/LizardByte/Sunshine/refs/heads/master/sunshine.png" alt="Sunshine Logo" width="200" height="200"/>
  <img src="https://avatars.githubusercontent.com/u/6118379" alt="Moonlight Logo" width="200" height="200"/>
</div>

# Eclypse - The Sunshine Manager

**Centralized management system for Sunshine remote access infrastructure**

*This project is based on [Sunshine](https://github.com/LizardByte/Sunshine) and [Moonlight](https://github.com/moonlight-stream/moonlight-qt) technologies*

---

## Do you need to manage computers / VMs with Sunshine utilized for gaining remote access to computers?

Here is the solution: **Eclypse_The_Sunshine_Manager**

Eclypse is a centralized web-based management system designed to simplify the management of multiple Sunshine virtual machines and physical computers in your IT infrastructure. It provides a secure, role-based interface for administrators to register Sunshine servers, assign access permissions to users, and handle secure client-server pairing without exposing sensitive credentials.

### Key Features:
- **Centralized VM Management**: Register and manage multiple Sunshine machines from a single interface
- **User Access Control**: Role-based system (master, admin, user) with secure VM assignments
- **Secure Pairing**: Handles Moonlight client authentication with Sunshine servers without credential exposure
- **Web API**: RESTful API for integration with existing management tools
- **Docker Deployment**: Easy deployment with Docker Compose

--- 

## Prerequisites

- **Operating System**: Linux distribution (Debian/Ubuntu recommended)
- **Docker** : Docker et Docker Compose installed
- **Git**: For cloning the repository
- **Network Access**: Port 443 (HTTPS) available for the web interface

---

## Quick Deployment

### 1. Clone the Repository
```bash
git clone https://github.com/themimi974/Eclypse_The-Sunshine-Manager.git
cd Eclypse_The-Sunshine-Manager
```

### 2. Launch with Docker Compose
```bash
docker-compose up -d
```

That's it! The application will be available at `https://your-server-ip`

---

## Configuration

### Environment Variables
The following environment variables can be customized in `docker-compose.yml`:

```yaml
environment:
  - DB_USER=myuser          # PostgreSQL username
  - DB_PASS=mypass          # PostgreSQL password
  - DB_HOST=localhost       # Database host
  - DB_PORT=5432           # Database port
  - DB_NAME=vdi_db         # Database name
  - JWT_SECRET_KEY=your-secret-key  # JWT encryption key
  - ADMIN_USER=admin       # Default admin username
  - ADMIN_PASS=admin1234   # Default admin password
  - ADMIN_ROLE=master      # Default admin role
```

### SSL Certificates
For production use, it's recommended to:
- Generate valid SSL certificates (Let's Encrypt, internal CA, etc.)
- Place certificates in the appropriate directory

---

## Usage

### 1. Register Sunshine Servers
- Use client\add_vm_gui.py
- Log in as an admin/master user
- Provide hostname, IP address, and Sunshine credentials

### 2. Create User Accounts
- Use client\eclypse.py
- Create User account in user tab

### 3. Assign VMs to Users
- Users will only see VMs they're authorized to access

### 4. Client Pairing
- Use client\eclypse.py
- Connect to the VM

---

## Security Considerations

- **Change Default Passwords**: Immediately change the default admin password after first login
- **Network Security**: Restrict access to the management interface using firewall rules
- **SSL Certificates**: **Do not use default** SSL certificates for production deployments
- **Regular Updates**: Keep the application and dependencies updated
