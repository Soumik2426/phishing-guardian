from app.security.password import hash_password, verify_password

hashed = hash_password("Password123!")

print(hashed)

print(verify_password("Password123!", hashed))