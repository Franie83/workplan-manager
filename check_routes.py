# save this as check_routes.py
from app import app

print("=" * 50)
print("ALL REGISTERED ROUTES:")
print("=" * 50)
for rule in app.url_map.iter_rules():
    print(f"Endpoint: {rule.endpoint:20} | URL: {rule}")
print("=" * 50)