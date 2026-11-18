"""Loading and querying the trained ML model."""

from pathlib import Path

from .features import FEATURE_NAMES, feature_vector

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "model.joblib"

_cache = {}


def load_model(path=MODEL_PATH):
    """Return the trained sklearn pipeline, or None if it has not been trained yet."""
    path = Path(path)
    if path in _cache:
        return _cache[path]
    model = None
    if path.exists():
        import joblib
        try:
            model = joblib.load(path)
        except Exception as exc:  # e.g. scikit-learn version mismatch
            import warnings
            warnings.warn(f"Could not load {path.name} ({exc}); using rules only. "
                          f"Re-train with: python scripts/train.py")
    _cache[path] = model
    return model


def predict_proba(raw_url: str, model=None):
    """Probability (0-1) that the URL is phishing, or None if no model is available."""
    model = model or load_model()
    if model is None:
        return None
    return float(model.predict_proba([feature_vector(raw_url)])[0][1])


def top_signals(raw_url: str, model=None, k=5):
    """Global feature importances paired with this URL's values (for display)."""
    model = model or load_model()
    if model is None:
        return []
    clf = model[-1] if hasattr(model, "__getitem__") else model
    imps = getattr(clf, "feature_importances_", None)
    if imps is None:
        return []
    vec = feature_vector(raw_url)
    order = sorted(range(len(FEATURE_NAMES)), key=lambda i: imps[i], reverse=True)[:k]
    return [{"feature": FEATURE_NAMES[i], "value": round(vec[i], 3),
             "importance": round(float(imps[i]), 3)} for i in order]
