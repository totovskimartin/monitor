# Contributing to Certifly

Thank you for considering contributing to Certifly! This document provides guidelines and instructions for contributing.

## Code of Conduct

Please be respectful and considerate of others when contributing to this project.

## How to Contribute

1. Fork the repository
2. Create a new branch for your feature or bugfix
3. Make your changes
4. Run tests to ensure your changes don't break existing functionality
5. Submit a pull request

## Development Setup

1. Clone your fork of the repository
2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Set up environment variables:
   ```bash
   cp .env.example .env
   ```
5. Run the application:
   ```bash
   python -m flask run
   ```

## Testing

Run tests using pytest:

```bash
pytest
```

## Pull Request Process

1. Update the README.md with details of changes if applicable
2. Update the documentation if needed
3. The PR should work for Python 3.9 and above
4. Your PR will be reviewed by maintainers

## Coding Style

Follow PEP 8 guidelines for Python code. Use consistent indentation and naming conventions.

## License

By contributing to Certifly, you agree that your contributions will be licensed under the project's MIT License.
