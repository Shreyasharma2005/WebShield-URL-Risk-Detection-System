import re

def extract_features(url):
    url = url.lower()

    features = []
    features.append(len(url))
    features.append(url.count("."))
    features.append(url.count("-"))
    features.append(1 if "https" in url else 0)

    keywords = ["login", "verify", "secure", "account", "bank", "update", "password"]
    features.append(sum(word in url for word in keywords))

    features.append(1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0)

    return features