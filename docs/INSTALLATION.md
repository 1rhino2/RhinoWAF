# Installation Guide

Complete installation instructions for RhinoWAF on various platforms.

## Quick Install (Linux/Mac)

```bash
# Download latest release
curl -LO https://github.com/1rhino2/RhinoWAF/releases/latest/download/rhinowaf-linux-amd64
chmod +x rhinowaf-linux-amd64
sudo mv rhinowaf-linux-amd64 /usr/local/bin/rhinowaf

# Verify installation
rhinowaf --version
```

## Build from Source

Requires Go 1.21 or later.

```bash
git clone https://github.com/1rhino2/RhinoWAF.git
cd RhinoWAF
make build
./rhinowaf --version
```

## Docker Installation

```bash
docker pull 1rhino2/rhinowaf:latest
docker run -d -p 8080:8080 \
  -e BACKEND=http://your-app:3000 \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/logs:/app/logs \
  --name rhinowaf \
  1rhino2/rhinowaf:latest
```

## Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rhinowaf
spec:
  replicas: 3
  selector:
    matchLabels:
      app: rhinowaf
  template:
    metadata:
      labels:
        app: rhinowaf
    spec:
      containers:
      - name: rhinowaf
        image: 1rhino2/rhinowaf:latest
        ports:
        - containerPort: 8080
        env:
        - name: BACKEND
          value: "http://backend-service:80"
        volumeMounts:
        - name: config
          mountPath: /app/config
      volumes:
      - name: config
        configMap:
          name: rhinowaf-config
---
apiVersion: v1
kind: Service
metadata:
  name: rhinowaf
spec:
  selector:
    app: rhinowaf
  ports:
  - port: 80
    targetPort: 8080
  type: LoadBalancer
```

## Systemd Service (Linux)

Create `/etc/systemd/system/rhinowaf.service`:

```ini
[Unit]
Description=RhinoWAF Web Application Firewall
After=network.target

[Service]
Type=simple
User=rhinowaf
WorkingDirectory=/opt/rhinowaf
ExecStart=/usr/local/bin/rhinowaf --config /opt/rhinowaf/config/production.json
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable rhinowaf
sudo systemctl start rhinowaf
sudo systemctl status rhinowaf
```

## Windows Installation

Download `rhinowaf-windows-amd64.exe` from releases.

Run as Windows Service using NSSM:
```powershell
nssm install RhinoWAF "C:\Program Files\RhinoWAF\rhinowaf.exe"
nssm set RhinoWAF AppParameters "--config C:\Program Files\RhinoWAF\config.json"
nssm start RhinoWAF
```

## Platform-Specific Notes

### Ubuntu/Debian
```bash
sudo apt update
sudo apt install -y curl
# Follow Quick Install steps above
```

### CentOS/RHEL
```bash
sudo yum install -y curl
# Follow Quick Install steps above
```

### Alpine Linux
```bash
apk add --no-cache ca-certificates curl
# Follow Quick Install steps above
```

## Next Steps

After installation:
1. Create configuration file - see [Configuration Guide](PRODUCTION_CONFIG.md)
2. Set up monitoring - see [Metrics Documentation](../features/METRICS.md)
3. Configure IP rules - see [IP Rules Guide](IP_RULES.md)
4. Test protection - see [Testing Guide](../TESTING.md)

## Troubleshooting

**Permission denied error:**
```bash
sudo chmod +x rhinowaf
```

**Port already in use:**
```bash
# Change port in config or find conflicting process
sudo lsof -i :8080
```

**Cannot connect to backend:**
```bash
# Verify backend is running
curl http://localhost:3000
# Check firewall rules
sudo iptables -L
```

## Uninstallation

```bash
# Stop service
sudo systemctl stop rhinowaf
sudo systemctl disable rhinowaf

# Remove files
sudo rm /usr/local/bin/rhinowaf
sudo rm -rf /opt/rhinowaf
sudo rm /etc/systemd/system/rhinowaf.service
```
