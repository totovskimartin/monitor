# Certifly - SSL Certificate and Domain Monitoring

A modern web application for monitoring SSL certificates, domain expiration, and website uptime. Certifly helps you keep track of your domains and certificates to prevent unexpected downtime.

![Certifly Dashboard](https://example.com/certifly-dashboard.png)

## Features

- **SSL Certificate Monitoring**: Track certificate expiration dates and receive alerts before they expire
- **Domain Expiry Tracking**: Monitor domain registration expiration dates
- **Website Uptime Monitoring**: Check if your websites are up and running
- **Multi-Organization Support**: Manage domains across different organizations
- **User Management**: Role-based access control with admin and regular users
- **Customizable Alerts**: Configure alerts for different thresholds
- **Multiple Notification Channels**: Email, Slack, MS Teams, Discord, Telegram, and more
- **Exportable Reports**: Generate and export reports in CSV, PDF, and Excel formats
- **Modern UI**: Clean, responsive interface with dark/light theme support
- **Containerized Deployment**: Easy deployment with Docker and Docker Compose

## Requirements

- Docker
- Docker Compose

## Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/totovskimartin/certifly.git
   cd certifly
   ```

2. Create a `.env` file with required environment variables:
   ```bash
   cp .env.example .env
   ```
   
3. Edit the `.env` file to set your database credentials and other settings:
   ```bash
   # Required settings
   DB_USER=certifly
   DB_PASSWORD=your_secure_password
   SECRET_KEY=your_random_secret_key
   
   # Optional settings
   WHOIS_API_KEY=your_whois_api_key
   ```

4. Start the application:
   ```bash
   docker-compose up -d
   ```

5. Access the application at http://localhost:5000

6. Create your admin account on first login

## Development

1. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up environment variables:
   ```bash
   cp .env.example .env
   ```

4. Run the application:
   ```bash
   python -m flask run
   ```

## Environment Variables

See `.env.example` for a list of all environment variables. The main ones are:

- `FLASK_ENV`: Set to `production` for production deployment
- `CERT_MONITOR_DATA_DIR`: Directory to store application data
- `SECRET_KEY`: Secret key for session management (required)
- `DB_USER`: Database username (required)
- `DB_PASSWORD`: Database password (required)
- `DB_HOST`: Database host (defaults to `db` in Docker)
- `DB_PORT`: Database port (defaults to `5432`)
- `DB_NAME`: Database name (defaults to `certifly`)
- `WHOIS_API_KEY`: API key for domain expiry lookups

## Configuration

### Database

The application uses PostgreSQL by default. You can configure the database connection using the environment variables in `.env`.

### WHOIS API Key

To enable domain expiry monitoring, you need to obtain a WHOIS API key from a provider like [whoisxmlapi.com](https://www.whoisxmlapi.com/) or similar services. Set this key in the `.env` file or through the application settings interface.

## Architecture

Certifly consists of the following components:

- **Web Application**: Flask-based web interface
- **Database**: PostgreSQL for data storage
- **Scheduler**: Background tasks for monitoring and alerts

## Security Considerations

### Environment Variables

Never commit your `.env` file to version control. The repository includes a `.env.example` file with placeholder values.

### API Keys

API keys and credentials should be kept secure and not shared. Use environment variables to configure sensitive information.

### Authentication

The application uses secure password hashing and session management. Always use strong passwords for your admin accounts.

### HTTPS

For production deployments, always use HTTPS. You can set up a reverse proxy like Nginx with Let's Encrypt certificates.

## Deployment

### Docker Compose (Recommended)

The easiest way to deploy Certifly is using Docker Compose:

```bash
docker-compose up -d
```

### AWS EKS

For production deployments, you can use AWS EKS with the provided Kubernetes manifests.

### Cloudflare

Certifly works well with Cloudflare for domain management and additional security.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Recent Updates

- Fixed export functionality to properly generate PDF and Excel files in addition to CSV
- Improved UI with consistent theme support
- Added multi-organization support
- Enhanced notification system with multiple channels

## License

[MIT License](LICENSE)
