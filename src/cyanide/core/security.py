import builtins
import io
import pickle


class RestrictedUnpickler(pickle.Unpickler):
    """
    Restricted unpickler that only allows safe built-in types and specific allowed modules.
    This mitigates code execution risks from untrusted pickle data.
    """

    SAFE_BUILTINS = {
        "str",
        "int",
        "float",
        "bool",
        "list",
        "dict",
        "set",
        "tuple",
        "range",
        "slice",
        "NoneType",
        "bytes",
        "complex",
    }

    SAFE_MODULES = {
        # Core data structures
        "collections",
        "datetime",
        "pathlib",
        # ML Libraries (required for model persistence)
        "numpy",
        "numpy.core.multiarray",
        "numpy.core.numeric",
        "numpy.dtype",
        "sklearn.cluster",
        "sklearn.cluster._kmeans",
        "scipy.sparse",  # Often used by sklearn
        "joblib",  # Often used by sklearn
        # Internal Project Modules
        "ai_models.cyanideML.model",
        "src.cyanideML.model",
    }

    def find_class(self, module, name):
        # 1. Allow Safe Builtins
        if module == "builtins":
            if name in self.SAFE_BUILTINS:
                return getattr(builtins, name)
            # For robustness, reject other builtins like eval, exec, etc.

        # 2. Allow Whitelisted Modules
        if module in self.SAFE_MODULES:
            return super().find_class(module, name)

        # 3. Allow specific submodules of safe modules (prefix check)
        # e.g. numpy.core.multiarray is safe if numpy is safe?
        # Let's be explicit with the list above to be stricter.

        # nosemgrep: python.lang.security.deserialization.pickle.avoid-pickle
        raise pickle.UnpicklingError(
            f"RestrictedUnpickler: Unsafe class '{module}.{name}' detected."
        )


def load(file_obj):
    """Secure replacement for pickle.load()"""
    return RestrictedUnpickler(file_obj).load()


def loads(data):
    """Secure replacement for pickle.loads()"""
    return RestrictedUnpickler(io.BytesIO(data)).load()
