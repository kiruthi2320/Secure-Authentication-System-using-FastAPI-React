import os
from dotenv import load_dotenv

load_dotenv()
print("Database URL:", os.getenv("DATABASE_URL"))
