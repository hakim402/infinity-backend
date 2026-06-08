# 🚀 Django Backend Setup Guide

Welcome to the Django Backend Project.

This guide will help you set up the project from scratch on Windows, macOS, or Linux.

---

# 📋 Prerequisites

Before getting started, make sure you have installed:

* Python 3.11+
* Git
* Pip
* Virtual Environment (venv)
* Redis (for Celery background tasks)

Verify installation:

```bash
python --version
pip --version
```

---

# 1️⃣ Clone the Repository

```bash
git clone <repository-url>
cd infinity-backend
```

---

# 2️⃣ Create Virtual Environment

Create a dedicated Python virtual environment:

```bash
python -m venv venv
```

---

# 3️⃣ Activate Virtual Environment

### Windows

```bash
venv\Scripts\activate
```

### macOS / Linux

```bash
source venv/bin/activate
```

You should now see:

```bash
(venv)
```

at the beginning of your terminal.

---

# 4️⃣ Install Dependencies

Install all required packages:

```bash
pip install -r requirements.txt
```

If `requirements.txt` does not exist:

```bash
pip install django djangorestframework
```

Generate it:

```bash
pip freeze > requirements.txt
```

---

# 5️⃣ Environment Variables

Create a `.env` file in the project root:

```env
DEBUG=True

SECRET_KEY=your-secret-key

DB_NAME=database_name
DB_USER=database_user
DB_PASSWORD=database_password
DB_HOST=localhost
DB_PORT=5432

EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_HOST_USER=your_email@gmail.com
EMAIL_HOST_PASSWORD=your_app_password
EMAIL_USE_TLS=True

FRONTEND_BASE_URL=http://localhost:3000
```

Update values according to your environment.

---

# 6️⃣ Database Setup

Create migrations:

```bash
python manage.py makemigrations
```

Apply migrations:

```bash
python manage.py migrate
```

---

# 7️⃣ Create Superuser

Create an admin account:

```bash
python manage.py createsuperuser
```

Follow the prompts.

---

# 8️⃣ Run Development Server

Default port:

```bash
python manage.py runserver
```

Custom port:

```bash
python manage.py runserver 8005
```

API will be available at:

```text
http://127.0.0.1:8000/
```

or

```text
http://127.0.0.1:8005/
```

---

# 9️⃣ Project Structure

```text
infinity-backend/
│
├── apps/
│   ├── accounts/
│   ├── tenants/
│   ├── ...
│
├── config/
│   ├── settings.py
│   ├── urls.py
│   ├── celery.py
│
├── requirements.txt
├── manage.py
└── .env
```

---

# 🔟 Creating a New App

Create app inside `apps/` directory:

```bash
python manage.py startapp accounts apps/accounts
```

Create:

```text
apps/__init__.py
```

Update:

```python
# apps/accounts/apps.py

from django.apps import AppConfig

class AccountsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.accounts"
```

Add app to:

```python
INSTALLED_APPS = [
    ...
    "apps.accounts",
]
```

---

# 1️⃣1️⃣ Celery & Redis Setup

Celery is used for:

* Email sending
* Background jobs
* Scheduled tasks
* Notifications
* Token cleanup jobs

---

## Install Celery

```bash
pip install celery redis
```

---

# Windows Redis Setup

## Option 1 (Recommended)

Run Redis using Docker:

```bash
docker run -d --name redis -p 6379:6379 redis:7
```

Start Redis:

```bash
docker start redis
```

Stop Redis:

```bash
docker stop redis
```

---

# macOS Redis Setup

Install Redis:

```bash
brew install redis
```

Start Redis:

```bash
brew services start redis
```

Stop Redis:

```bash
brew services stop redis
```

Restart Redis:

```bash
brew services restart redis
```

Verify Redis:

```bash
redis-cli ping
```

Expected output:

```text
PONG
```

---

# Celery Configuration

Add to `settings.py`:

```python
CELERY_BROKER_URL = "redis://localhost:6379/0"
CELERY_RESULT_BACKEND = "redis://localhost:6379/1"

CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"

CELERY_TIMEZONE = "UTC"
```

Create:

```text
config/celery.py
```

```python
import os

from celery import Celery

os.environ.setdefault(
    "DJANGO_SETTINGS_MODULE",
    "config.settings"
)

app = Celery("config")

app.config_from_object(
    "django.conf:settings",
    namespace="CELERY"
)

app.autodiscover_tasks()
```

Update:

```python
# config/__init__.py

from .celery import app as celery_app

__all__ = ("celery_app",)
```

---

# Run Celery Worker

### Windows

```bash
celery -A config worker -l info --pool=solo
```

### macOS / Linux

```bash
celery -A config worker -l info
```

Stop worker:

```text
CTRL + C
```

---

# Daily Development Workflow

### Terminal 1

Run Django:

```bash
python manage.py runserver
```

### Terminal 2

Run Redis:

Windows:

```bash
docker start redis
```

macOS:

```bash
brew services start redis
```

### Terminal 3

Run Celery:

Windows:

```bash
celery -A config worker -l info --pool=solo
```

macOS:

```bash
celery -A config worker -l info
```

---

# Testing Celery

Open Django shell:

```bash
python manage.py shell
```

Run:

```python
from apps.accounts.tasks import cleanup_expired_tokens

cleanup_expired_tokens.delay()
```

Expected Celery output:

```text
Task apps.accounts.tasks.cleanup_expired_tokens received
Task apps.accounts.tasks.cleanup_expired_tokens succeeded
```

---

# Running Tests

Run all tests:

```bash
pytest
```

Run accounts tests only:

```bash
pytest apps/accounts/tests -v
```

Generate coverage report:

```bash
pytest --cov=apps.accounts --cov-report=term-missing
```

---

# Useful Commands

Create migrations:

```bash
python manage.py makemigrations
```

Apply migrations:

```bash
python manage.py migrate
```

Collect static files:

```bash
python manage.py collectstatic
```

Create superuser:

```bash
python manage.py createsuperuser
```

Open Django shell:

```bash
python manage.py shell
```

---

# Troubleshooting

### Redis Connection Error

Make sure Redis is running:

```bash
redis-cli ping
```

Expected:

```text
PONG
```

### Celery Not Detecting Tasks

Restart the worker:

```bash
celery -A config worker -l info
```

### Migration Issues

Reset migrations carefully:

```bash
python manage.py makemigrations
python manage.py migrate
```

---

# Author

Infinity Solutions

Built with:

* Django
* Django REST Framework
* PostgreSQL
* Celery
* Redis
* SimpleJWT
* Pytest
