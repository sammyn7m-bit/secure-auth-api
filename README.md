# Secure Auth API

[![Python Version](https://shields.io)](https://python.org)
[![Django Version](https://shields.io)](https://djangoproject.com)
[![DRF Version](https://shields.io)](https://django-rest-framework.org)
[![License: Unlicense](https://shields.io)](https://unlicense.org)

A production-oriented Django REST API built to learn and implement secure industry-standard authentication patterns properly.

## Features

- **Advanced Cryptography:** Industry-recommended password hashing using Argon2 (`argon2-cffi`).
- **Token Security:** Short-lived JWT access tokens paired with secure JWT rotation mechanisms.
- **Multi-Factor Authentication:** Multi-stage TOTP-based MFA setup, activation, verification, and teardown.
- **Brute-Force Protection:** Intelligent login rate limiting and IP/Username account lockout handling using Django Axes.
- **Enterprise Data Layer:** Structured storage utilizing PostgreSQL alongside Redis caching for token blacklist verification and session state.
- **Self-Documenting:** Fully integrated OpenAPI schema generation via OpenAPI tools.

## Tech Stack

- [Django](https://djangoproject.com) - High-level Python Web Framework
- [Django REST Framework](https://django-rest-framework.org) - Toolkit for building Web APIs
- [PostgreSQL](https://postgresql.org) - Advanced Open Source Relational Database
- [Redis](https://redis.io) - Real-time in-memory data store for caching and sessions
- [Simple JWT](https://readthedocs.io) - JSON Web Token authentication plugin for DRF
- [django-otp](https://readthedocs.io) - Pluggable framework for adding One-Time Passwords (OTPs)
- [Django Axes](https://readthedocs.io) - Keep track of failed login attempts and lock out attackers
- [Argon2-cffi](https://readthedocs.io) - Secure Password Hashing Competition winner for Python

## API Endpoints

### Authentication

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/auth/register/` | Create an account |
| `POST` | `/api/auth/login/` | Login and obtain JWT tokens |

### MFA

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/security/mfa/setup/` | Start TOTP setup |
| `POST` | `/api/security/mfa/activate/` | Activate TOTP |
| `POST` | `/api/security/mfa/verify/` | Verify a TOTP code |
| `POST` | `/api/security/mfa/disable/` | Disable TOTP |

## Environment Variables

Before launching the project locally, create a `.env` file in the root directory. You can use the values below as a reference for your local setup:

```env
# Django Configuration
SECRET_KEY=your-super-secret-django-key-here
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# Database Configuration (PostgreSQL)
DB_NAME=secure_auth_db
DB_USER=postgres
DB_PASSWORD=your_secure_db_password
DB_HOST=localhost
DB_PORT=5432

# Redis Cache Configuration
REDIS_URL=redis://127.0.0.1:6379/1

# Security Settings
AXES_COOLDOWN_HOURS=1
AXES_FAILURE_LIMIT=5
JWT_ACCESS_TOKEN_LIFETIME_MINUTES=15
JWT_REFRESH_TOKEN_LIFETIME_DAYS=7
```

## Running Locally

Clone the repository:

```bash
git clone https://github.com
cd secure-auth-api
```

Create a virtual environment:

```bash
python -m venv venv
source venv/bin/activate
```

Install the dependencies:

```bash
pip install -r requirements.txt
```

Create your environment file:

```bash
cp .env.example .env
```

Run the database migrations:

```bash
python manage.py migrate
```

Start the local development server:

```bash
python manage.py runserver
```

The API will be available at: [http://127.0.0](http://127.0.0)

## Project Status

This project is still under active development.

JWT authentication and TOTP MFA setup and verification are currently working.

The next major milestone is connecting the TOTP engine directly to the primary login flow, enforcing accounts with MFA enabled to successfully submit their TOTP code before receiving their JWT tokens.

## Repository

[View the project on GitHub](https://github.com)

