<div align="center">
<div align="center">
  <img src="https://raw.githubusercontent.com/LizardByte/Sunshine/refs/heads/master/sunshine.png" alt="Sunshine Logo" width="200" height="200"/>
  <img src="https://avatars.githubusercontent.com/u/6118379" alt="Moonlight Logo" width="200" height="200"/>
</div>

# Eclypse - The Sunshine Manager

**Centralized management system for Sunshine remote access infrastructure**

*This project is based on [Sunshine](https://github.com/LizardByte/Sunshine) and [Moonlight](https://github.com/moonlight-stream/moonlight-qt) technologies*

---

## Do you need to manage IT parc with Sunshine utilized for gaining remote access to computers?

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

## Detailed Deployment Steps

### 1. System Preparation
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install Docker (if not already installed)
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose
sudo apt install docker-compose-plugin -y

# Add user to docker group (optional, for non-root usage)
sudo usermod -aG docker $USER
```

### 2. Clone and Deploy
```bash
# Clone the repository
git clone https://github.com/themimi974/Eclypse_The-Sunshine-Manager
cd Eclypse_The-Sunshine-Manager

# Launch the application
docker-compose up -d

# Check status
docker-compose ps
```

### 3. Initial Setup
- The application will automatically create an admin user with default credentials:
  - **Username**: `admin`
  - **Password**: `admin1234`
  - **Role**: `master`

### 4. Access the Application
- **URL**: `https://your-server-ip:443`
- **Default Admin**: `admin` / `admin1234`

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
- Update the Docker Compose configuration accordingly

---

## Usage

### 1. Register Sunshine Servers
- Log in as an admin/master user
- Use the API endpoint `/vm/register` to add new Sunshine machines
- Provide hostname, IP address, and Sunshine credentials

### 2. Create User Accounts
- Use `/auth/register` to create new user accounts
- Assign appropriate roles (user, admin, master)

### 3. Assign VMs to Users
- Use `/vm/assign` to link specific VMs to users
- Users will only see VMs they're authorized to access

### 4. Client Pairing
- Users can pair their Moonlight clients using the pairing endpoints
- The system handles secure PIN generation and Sunshine authentication

---

## API Documentation

Once deployed, the interactive API documentation is available at:
- **Swagger UI**: `https://your-server-ip:443/docs`
- **ReDoc**: `https://your-server-ip:443/redoc`

---

## Troubleshooting

### Common Issues

1. **Port Already in Use**
   ```bash
   # Check what's using port 443
   sudo netstat -tlnp | grep :443
   # Stop conflicting service or change port in docker-compose.yml
   ```

2. **Database Connection Issues**
   ```bash
   # Check database container status
   docker-compose logs database
   # Ensure PostgreSQL is running and accessible
   ```

3. **Permission Issues**
   ```bash
   # Check Docker permissions
   docker ps
   # If permission denied, add user to docker group and restart session
   ```

### Logs
```bash
# View application logs
docker-compose logs -f

# View specific service logs
docker-compose logs -f server
docker-compose logs -f database
```

---

## Security Considerations

- **Change Default Passwords**: Immediately change the default admin password after first login
- **Network Security**: Restrict access to the management interface using firewall rules
- **SSL Certificates**: Use valid SSL certificates for production deployments
- **Regular Updates**: Keep the application and dependencies updated

---

## Support

For technical support or questions:
- Check the API documentation at `/docs`
- Review the deployment logs
- Open an issue on the GitHub repository

---

## License

This project is licensed under the terms specified in the LICENSE file. 
