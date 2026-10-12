import hashlib
import json
import os


class ModelLoadError(Exception):
    pass


class MissingFileError(ModelLoadError):
    pass


class ChecksumMismatchError(ModelLoadError):
    pass


class FeatureMismatchError(ModelLoadError):
    pass


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def load_model(model_dir: str, data_dir: str = None):
    manifest_path = os.path.join(model_dir, "manifest.json")
    if not os.path.exists(manifest_path):
        raise MissingFileError("manifest.json missing")

    with open(manifest_path) as f:
        manifest = json.load(f)

    if data_dir is not None:
        flist_path = os.path.join(data_dir, "feature_list.json")
        if os.path.exists(flist_path):
            with open(flist_path) as f:
                feature_list = json.load(f)
            if manifest["feature_names"] != feature_list:
                raise FeatureMismatchError("manifest feature_names != feature_list.json")

    import joblib

    models = {}
    for joblib_name, expected_sha in manifest.get("joblib_sha256", {}).items():
        joblib_path = os.path.join(model_dir, joblib_name)
        if not os.path.exists(joblib_path):
            raise MissingFileError(f"{joblib_name} missing")
        actual_sha = _sha256(joblib_path)
        if actual_sha != expected_sha:
            raise ChecksumMismatchError(f"{joblib_name} checksum mismatch")

        key = joblib_name.split(".")[0]
        loaded_obj = joblib.load(joblib_path)
        if hasattr(loaded_obj, "__dict__") and "multi_class" not in loaded_obj.__dict__:
            loaded_obj.__dict__["multi_class"] = "auto"
        models[key] = loaded_obj

    return manifest, models

