import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from core.web_server import app
    print("FastAPI server imported successfully!")
except Exception as e:
    import traceback
    traceback.print_exc()
    sys.exit(1)
