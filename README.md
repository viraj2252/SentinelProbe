# SentinelProbe

![CI](https://github.com/viraj2252/SentinelProbe/workflows/CI/badge.svg)

AI-Powered Penetration Testing System

## Overview

SentinelProbe is an advanced AI-driven penetration testing solution designed to autonomously identify, exploit, and document security vulnerabilities in target systems. By leveraging machine learning and adaptive decision-making, the system emulates the capabilities of skilled human penetration testers while providing increased efficiency, consistency, and comprehensive reporting.

## Features

- Autonomous penetration testing with AI-driven decision making
- Comprehensive reconnaissance and vulnerability scanning
- Safe exploitation and post-exploitation capabilities
- Detailed reporting with remediation recommendations
- Continuous learning and improvement

## Architecture

The system consists of the following core components:

- **Orchestration Engine**: Coordinates the entire testing process
- **AI Decision Engine**: Determines strategy and next steps based on findings
- **Reconnaissance Module**: Gathers intelligence about target systems
- **Vulnerability Scanner**: Identifies potential security weaknesses
- **Exploitation Engine**: Attempts to exploit discovered vulnerabilities
- **Post-Exploitation Module**: Tests lateral movement and persistence
- **Reporting Engine**: Generates comprehensive security reports
- **Learning Module**: Improves system performance over time

## Installation

### Prerequisites

- Python 3.10+
- PostgreSQL
- MongoDB
- Redis

### Setup

1. Clone the repository:

   ```
   git clone https://github.com/viraj2252/sentinelprobe.git
   cd sentinelprobe
   ```

2. Create and activate a virtual environment:

   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:

   ```
   pip install -e .
   ```

4. Copy the example environment file and configure it:

   ```
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. Run the application:

   ```
   python -m sentinelprobe
   ```

### Docker Setup

You can also run SentinelProbe using Docker:

1. Build and run using Docker Compose:

   ```
   docker-compose up -d
   ```

2. Or build and run the Docker image directly:

   ```
   docker build -t sentinelprobe .
   docker run -p 8000:8000 --env-file .env sentinelprobe
   ```

3. Test the Docker setup:

   ```
   ./docker-test.sh
   ```

## Development

### Setup Development Environment

1. Install development dependencies:

   ```
   pip install -e ".[dev]"
   ```

2. Install pre-commit hooks:

   ```
   pre-commit install
   ```

### Code Quality Standards

SentinelProbe maintains high code quality standards through automated checks. All code must pass:

- **Black**: Code formatting
- **isort**: Import sorting
- **flake8**: Linting and code style (including docstrings)
- **mypy**: Static type checking

These checks run automatically as pre-commit hooks to prevent committing code with issues.

### Safe Commit Practice

To ensure code quality checks are always run, use the safe-commit script instead of regular git commit:

```
./scripts/safe-commit.sh -m "Your commit message"
```

This script:

- Prevents using the `--no-verify` flag which would bypass pre-commit hooks
- Runs pre-commit checks manually before committing
- Only proceeds with the commit if all checks pass

### Running Tests

```
pytest
```

### Code Quality

The project uses several tools to ensure code quality:

1. **Linting with flake8**:

   ```
   ./scripts/lint.sh
   ```

2. **Formatting with black and isort**:

   ```
   black sentinelprobe tests
   isort sentinelprobe tests
   ```

3. **Type checking with mypy**:

   ```
   mypy sentinelprobe
   ```

4. **Run all checks**:

   ```
   ./scripts/check.sh
   ```

Pre-commit hooks are configured to run these checks automatically before each commit. To install the pre-commit hooks:

```
pre-commit install
```

### CI/CD Pipeline

The project uses GitHub Actions for continuous integration and testing:

- Automatic testing on push to main branch and pull requests
- Code quality checks (linting, formatting, type checking)
- Test coverage reporting
- Docker image building and testing

## Documentation

SentinelProbe includes comprehensive documentation in the form of a wiki. The documentation covers all components, installation instructions, usage guides, and more.

### Accessing the Documentation

The documentation is available in multiple formats:

1. **GitHub Wiki**: The documentation is automatically published to the [GitHub Wiki](https://github.com/yourusername/sentinelprobe/wiki)
2. **Local MkDocs Site**: You can run a local documentation server using `mkdocs serve`
3. **Source Files**: All documentation is available in the `docs/wiki` directory

### Documentation Structure

The documentation is organized into the following sections:

- **Getting Started**: Installation, requirements, and quick start guides
- **User Guides**: Detailed guides for using SentinelProbe
- **Component Documentation**: Details about each module (Reconnaissance, Vulnerability Scanner, etc.)
- **Advanced Usage**: Custom rule development, API references, and more
- **Contributing**: Guidelines for contributing to SentinelProbe

### Automatic Wiki Publishing

The documentation is automatically published to the GitHub Wiki whenever changes are made to the `docs/wiki` directory or the `mkdocs.yml` file. This is handled by a GitHub Actions workflow that:

1. Builds the MkDocs site
2. Converts the HTML output to GitHub Wiki format
3. Updates the GitHub Wiki repository

No manual intervention is required to keep the documentation updated.

## License

[MIT License](LICENSE)
