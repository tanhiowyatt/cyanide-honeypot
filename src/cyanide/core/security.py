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
        "collections",
        "datetime",
        "pathlib",
        "re",
        "numpy",
        "numpy.core.multiarray",
        "numpy.core.numeric",
        "numpy.dtype",
        "sklearn.cluster",
        "sklearn.cluster._kmeans",
        "sklearn.feature_extraction.text",
        "scipy.sparse",
        "scipy.sparse._csr",
        "joblib",
        "cyanide.ml.model",
        "cyanide.ml.classifier",
        "src.cyanide.ml.model",
        "src.cyanide.ml.classifier",
        "ai_models.cyanideML.model",
    }

    # Function 34: Performs operations related to find class.
    def find_class(self, module, name):
        if module == "builtins":
            if name in self.SAFE_BUILTINS:
                return getattr(builtins, name)

        if module in self.SAFE_MODULES:
            return super().find_class(module, name)

        raise pickle.UnpicklingError(
            f"RestrictedUnpickler: Unsafe class '{module}.{name}' detected."
        )


# Function 35: Performs operations related to load.
def load(file_obj):
    """Secure replacement for pickle.load()"""
    return RestrictedUnpickler(file_obj).load()


# Function 36: Performs operations related to loads.
def loads(data):
    """Secure replacement for pickle.loads()"""
    return RestrictedUnpickler(io.BytesIO(data)).load()
