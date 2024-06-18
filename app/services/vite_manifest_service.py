from typing import Dict, Any


class ViteManifestService:
    def __init__(self, manifest: Dict[str, Dict[str, Any]]):
        self.manifest = manifest

    def get_manifest(self) -> Dict[str, Dict[str, Any]]:
        return self.manifest

    def get_asset_url(self, input_path: str) -> str:
        if input_path not in self.manifest:
            raise ValueError(f"No asset found for input path: {input_path}")

        return self.manifest[input_path]["file"]
