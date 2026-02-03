import pickle
import io
import builtins
import typing
from core.filesystem_nodes import Node, Directory, File

import hmac
import hashlib

# Internal Integrity Key
# This prevents loading arbitrary pickle files not created by this tool.
# It is NOT a cryptographic secret for external security, but an integrity check.
INTEGRITY_KEY = b"cyanide-honeypot-internal-integrity-key-v1"

class SafeUnpickler(pickle.Unpickler):
    """Restricted unpickler that only allows safe built-in types."""
    def find_class(self, module, name):
        # Allow only safe builtins
        if module == "builtins" and name in {
            'str', 'int', 'float', 'bool', 'list', 'dict', 'tuple', 'set', 'NoneType', 'bytes'
        }:
            return getattr(builtins, name)
        raise pickle.UnpicklingError(f"Unsafe class: {module}.{name}")

def save_fs(root_node, path: str):
    """Save filesystem to signed pickle file."""
    # Serialize to dict first
    fs_dict = root_node.to_dict()
    
    # Dump to bytes
    data = pickle.dumps(fs_dict)
    
    # Calculate HMAC
    signature = hmac.new(INTEGRITY_KEY, data, hashlib.sha256).digest()
    
    with open(path, "wb") as f:
        # Format: [32 bytes HMAC][Pickle Data]
        f.write(signature)
        f.write(data)

def load_fs(path: str):
    """Load filesystem from signed pickle file."""
    with open(path, "rb") as f:
        # Read HMAC
        signature = f.read(32)
        data = f.read()
        
    # Verify HMAC
    expected = hmac.new(INTEGRITY_KEY, data, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected):
        print(f"Error: Filesystem integrity check failed for {path}")
        return None
        
    # Use safe unpickler on trusted data
    try:
        # nosemgrep: python.lang.security.deserialization.pickle.avoid-pickle
        # Reason: Integrity checked via HMAC-SHA256 above. Only internal files loaded.
        fs_dict = SafeUnpickler(io.BytesIO(data)).load()
    except Exception as e:
        print(f"Error unpickling FS: {e}")
        return None
            
    # Reconstruct objects
    if fs_dict.get("type") == "dir":
        return Directory.from_dict(fs_dict)
    elif fs_dict.get("type") == "file":
        return File.from_dict(fs_dict)
    return None
