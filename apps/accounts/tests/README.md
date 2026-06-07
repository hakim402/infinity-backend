# Accounts App Tests

Put this folder at:

```text
apps/accounts/tests/
```

Run:

```bash
pip install pytest pytest-django
pytest apps/accounts/tests/ -v
```

Or with Django's runner:

```bash
python manage.py test apps.accounts
```

Recommended pytest.ini:

```ini
[pytest]
DJANGO_SETTINGS_MODULE = config.settings
python_files = tests.py test_*.py *_tests.py
addopts = -ra
```

Notes:
- These tests assume your URL namespace is `accounts`.
- These tests assume imports use:
  - `apps.accounts.models`
  - `apps.accounts.api.serializers`
  - `apps.accounts.services.services`
  - `apps.accounts.tasks`
- If your actual service path is different, update the patch paths in tests.
