# 🚀 Django Backend Setup Guide

This guide explains how to set up the Django backend project step by step.

---

## 1. Create Project Folder

```bash
mkdir backend
cd backend

2. Create Virtual Environment
python -m venv venv

3. Activate Virtual Environment
Windows:
venv\Scripts\activate

Linux / Mac:
source venv/bin/activate

4. Install Required Packages
pip install django djangorestframework psycopg2-binary
pip install django-environ django-filter
pip install djangorestframework-simplejwt
pip install django-cors-headers
pip install drf-spectacular
pip install celery redis django-redis
pip install gunicorn

5. Generate Requirements File
pip freeze > requirements.txt

6. Create Django Project
django-admin startproject config .

7. Create Apps Inside apps/ Folder
python manage.py startapp accounts apps/accounts

8. Configure App Properly
Step 1: Create __init__.py inside apps folder
apps/__init__.py
Step 2: Update apps.py

Open:

apps/accounts/apps.py

Set:

name = 'apps.accounts'

9. Run Database Migrations
python manage.py makemigrations
python manage.py migrate

10. Run Development Server
python manage.py runserver
python manage.py runserver 8005


11. Celery Configuration for SMTP Email Sending:
install celery:
pip install celery
run celery:
celery -A config worker -l info --pool=solo
