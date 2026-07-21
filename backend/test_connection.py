from sqlalchemy import text

from app.core.config import settings
from app.database.session import engine


print("\n========== DATABASE CONFIG ==========")
print(f"Host      : {settings.DATABASE_HOST}")
print(f"Port      : {settings.DATABASE_PORT}")
print(f"Database  : {settings.DATABASE_NAME}")
print(f"Username  : {settings.DATABASE_USERNAME}")

# Hide the password while printing
masked_password = "*" * len(settings.DATABASE_PASSWORD)

print(
    f"Connection URL : "
    f"postgresql+psycopg2://"
    f"{settings.DATABASE_USERNAME}:"
    f"{masked_password}@"
    f"{settings.DATABASE_HOST}:"
    f"{settings.DATABASE_PORT}/"
    f"{settings.DATABASE_NAME}"
)
print("=====================================\n")


try:
    with engine.connect() as connection:
        result = connection.execute(text("SELECT version();"))

        print("✅ Database connected successfully!\n")
        print("PostgreSQL Version:")
        print(result.scalar())

except Exception as e:
    print("❌ Database connection failed!\n")
    print(e)