# routes/__init__.py
# Makes 'routes' a package and exposes all blueprints for easy import.

from .encrypt import encrypt_bp
from .decrypt import decrypt_bp
from .health  import health_bp

__all__ = ["encrypt_bp", "decrypt_bp", "health_bp"]
