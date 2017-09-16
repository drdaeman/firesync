def _patch_pybrowserid():
    """Patches PyBrowserID to use cryptography.io"""

    import warnings
    import browserid.crypto
    try:
        from . import cio
        browserid.crypto.Key = cio.Key
        browserid.crypto.RSKey = cio.RSKey
        browserid.crypto.DSKey = cio.DSKey
    except ImportError:
        warnings.warn("Failed to patch PyBrowserID to use cryptography.io")


_patch_pybrowserid()
