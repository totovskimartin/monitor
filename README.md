# Certificates Web Application

Web application for managing certificates.

## Getting Started

### Prerequisites
- Python 3.9+
- Docker (optional)

### Local Development
1. Create virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
./run.sh
```

### Docker Deployment
1. Build the container:
```bash
docker build -t certificates-web .
```

2. Run the container:
```bash
docker run -d -p 5000:5000 -v certificates_data:/data --name certificates-web certificates-web
```

## Configuration
Configure the application using environment variables:
- `FLASK_ENV`: Set to 'production' for production environment
- `CERT_MONITOR_DATA_DIR`: Directory for storing application data

## Contributing
1. Create a new branch for your feature
2. Make your changes
3. Submit a merge request

## License
[Your License Here]