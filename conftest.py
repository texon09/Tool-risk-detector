import sys
import pathlib

# Ensure the backend directory is on the PYTHONPATH for test collection
project_root = pathlib.Path(__file__).parent
backend_path = project_root / "backend"
if str(backend_path) not in sys.path:
    sys.path.insert(0, str(backend_path))
