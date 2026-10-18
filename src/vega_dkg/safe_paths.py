"""safe_paths.py - kept so existing imports keep working; the rules now live in vega_custody.safepaths and are shared with the other repos."""
from vega_custody.safepaths import PathRefused, atomic_write, contained, read_capped, safe_name  # noqa: F401
