import importlib.metadata

import siglum


def test_dunder_version_matches_installed_metadata():
    # pyproject.toml is what the installed distribution reports; __version__ must
    # track it, so a bump that misses either place fails here instead of drifting.
    assert siglum.__version__ == importlib.metadata.version("siglum")
