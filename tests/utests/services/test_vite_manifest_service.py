import pytest

from app.services.vite_manifest_service import ViteManifestService

sample_manifest = {
    "resources/css/app.scss": {
        "file": "assets/app-OH0OBLf7.css",
        "src": "resources/css/app.scss",
    },
    "resources/js/script.js": {
        "file": "assets/script-XyZ123.js",
        "src": "resources/js/script.js",
    },
}

empty_manifest = {}


def test_init():
    service = ViteManifestService(sample_manifest)

    assert service.get_manifest() == sample_manifest


def test_init_empty_manifest():
    service = ViteManifestService(empty_manifest)

    assert service.get_manifest() == empty_manifest


def test_asset_url():
    service = ViteManifestService(sample_manifest)

    assert service.get_asset_url("resources/css/app.scss") == "assets/app-OH0OBLf7.css"
    assert service.get_asset_url("resources/js/script.js") == "assets/script-XyZ123.js"


def test_asset_url_empty_manifest():
    service = ViteManifestService(empty_manifest)

    with pytest.raises(
        ValueError, match="No asset found for input path: resources/css/app.scss"
    ):
        service.get_asset_url("resources/css/app.scss")
