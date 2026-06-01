import sys

def parse_features(file_path):
    features = {}
    with open(file_path, "r") as f:
        for line in f:
            if "=" in line:
                key, value = line.strip().split("=")
                features[key] = int(value)

    return features

def compute_score(features):
    weights = {
        "is_insecure_protocol": 0.20,
        "is_risky_file": 0.25,
        "is_large_payload": 0.10,
        "is_suspicious_domain": 0.15,
        "is_privileged_execution_risk": 0.20,
        "is_admin": 0.05,
        "is_unencrypted": 0.05,
        "is_data_exfilteration": 0.35,
        "is_ioc_match": 0.75
    }

    score = 0.0

    for key, weight in weights.items():
        score += features.get(key, 0) * weight

    if features.get("is_data_exfiltration", 0):
        score +=0.8
    score = min(score, 1.0)

    if features.get("is_ioc_match", 0):
        score +=0.3
    score = min(score, 1.0)

    #confidence heuristic
    confidence = score
    
    if features.get("is_data_exfiltration", 0):
        confidence +=0.1
    
    if features.get("is_ioc_match", 0):
        confidence +=0.3

    confidence = min(confidence, 1.0)

    return round(score, 2), round(confidence, 2)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python score.py <feature_file>")
        sys.exit(1)

    features = parse_features(sys.argv[1])
    score, confidence = compute_score(features)

    print(f"RISK_SCORE={score}")
    print(f"CONFIDENCE={confidence}")

