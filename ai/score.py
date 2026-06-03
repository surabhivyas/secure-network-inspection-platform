"""score.py — Computes risk score and confidence from a feature file."""

import logging
import os
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

WEIGHTS: dict[str, float] = {
    "is_insecure_protocol": 0.20,
    "is_risky_file": 0.25,
    "is_large_payload": 0.10,
    "is_suspicious_domain": 0.15,
    "is_privileged_execution_risk": 0.20,
    "is_admin": 0.05,
    "is_unencrypted": 0.05,
    "is_data_exfiltration": 0.35,  # fixed typo
    "is_ioc_match": 0.75,
}


def parse_features(file_path: str | Path) -> dict[str, int]:
    """
    Parse key=value feature pairs from a file.

    Args:
        file_path: Path to the feature file.

    Returns:
        Dict mapping feature names to integer values.

    Raises:
        FileNotFoundError: If the path does not exist or is not a file.
        PermissionError: If the file is not readable.
        ValueError: If a value cannot be parsed as an integer.
    """
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Feature file not found: {path}")
    if not path.is_file():
        raise FileNotFoundError(f"Path is not a file: {path}")
    if not os.access(path, os.R_OK):
        raise PermissionError(f"No read permission: {path}")

    features: dict[str, int] = {}

    with open(path, "r") as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, raw_value = line.split("=", 1)
            key = key.strip()
            raw_value = raw_value.strip()
            try:
                value = int(raw_value)
            except ValueError:
                raise ValueError(
                    f"Line {lineno}: expected integer for '{key}', got '{raw_value}'"
                )
            if value not in (0, 1):
                raise ValueError(
                    f"Line {lineno}: feature '{key}' must be 0 or 1, got {value}"
                )
            features[key] = value

    if not features:
        logger.warning("No features parsed from file: %s", path)

    return features


def compute_score(features: dict[str, int]) -> tuple[float, float]:
    """
    Compute risk score and confidence from binary features.

    Args:
        features: Dict of feature name to 0/1 value.

    Returns:
        Tuple of (risk_score, confidence), both in [0.0, 1.0].

    Raises:
        TypeError: If features is not a dict.
        ValueError: If features is empty.
    """
    if not isinstance(features, dict):
        raise TypeError(f"Expected dict, got {type(features).__name__}")
    if not features:
        raise ValueError("Features dict is empty")

    score = sum(features.get(key, 0) * weight for key, weight in WEIGHTS.items())

    # Bonus for critical indicators
    if features.get("is_data_exfiltration", 0):
        score += 0.8
    if features.get("is_ioc_match", 0):
        score += 0.3

    score = min(score, 1.0)

    # Confidence: independent additive heuristic
    confidence = sum(features.get(key, 0) * weight for key, weight in WEIGHTS.items())
    if features.get("is_data_exfiltration", 0):
        confidence += 0.1
    if features.get("is_ioc_match", 0):
        confidence += 0.3

    confidence = min(confidence, 1.0)

    return round(score, 2), round(confidence, 2)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python score.py <feature_file>")
        sys.exit(1)

    try:
        features = parse_features(sys.argv[1])
        score, confidence = compute_score(features)
    except (FileNotFoundError, PermissionError, ValueError, TypeError) as e:
        logger.error("%s", e)
        sys.exit(1)

    print(f"RISK_SCORE={score}")
    print(f"CONFIDENCE={confidence}")
