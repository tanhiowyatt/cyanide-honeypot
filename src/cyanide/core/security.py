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
        "_codecs",
        "numpy",
        "numpy.core.multiarray",
        "numpy.core.numeric",
        "numpy.dtype",
        "numpy._core",
        "numpy._core.multiarray",
        "numpy._core.numeric",
        "sklearn.cluster",
        "sklearn.cluster._kmeans",
        "sklearn.feature_extraction.text",
        "scipy.sparse",
        "scipy.sparse._csr",
        "joblib",
        "cyanide.ml.model",
        "cyanide.ml.classifier",
        "cyanide.ml.tokenizer",
        "src.cyanide.ml.model",
        "src.cyanide.ml.classifier",
        "src.cyanide.ml.tokenizer",
        "ai_models.cyanideML.model",
        "torch",
        "torch._utils",
        "torch.serialization",
        "torch.storage",
    }

    # Function 34: Performs operations related to find class.
    def find_class(self, module, name):
        if module == "builtins" and name in self.SAFE_BUILTINS:
            return getattr(builtins, name)

        if module == "_codecs" and name in {"encode", "decode"}:
            import _codecs

            return getattr(_codecs, name)

        if module in self.SAFE_MODULES:
            return super().find_class(module, name)

        # nosemgrep: python.lang.security.deserialization.pickle.avoid-pickle
        raise pickle.UnpicklingError(
            f"RestrictedUnpickler: Unsafe class '{module}.{name}' detected."
        )


# Alias for torch.load(..., pickle_module=security) compatibility
Unpickler = RestrictedUnpickler


# Function 35: Performs operations related to load.
def load(file_obj, **kwargs):
    """Secure replacement for pickle.load()"""
    return RestrictedUnpickler(file_obj).load()


# Function 36: Performs operations related to loads.
def loads(data):
    """Secure replacement for pickle.loads()"""
    return RestrictedUnpickler(io.BytesIO(data)).load()
