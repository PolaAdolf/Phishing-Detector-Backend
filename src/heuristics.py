import re
import urllib.parse

# Common typosquatting patterns for major popular domains
TYPOSQUATTING_PATTERNS = [
    r"g[0-9]ogle",             # g0ogle, g00gle
    r"g[0o]{2}gle",            # g0ogle, go0gle
    r"payp[1a-z0-9]*l-",       # paypa1-
    r"payp[a1]l",              # paypa1
    r"m[i1]cr[o0]s[o0]ft",     # m1crosoft
    r"nbe-[a-z0-9]+-verify",   # fake NBE portals
    r"nbe-[a-z0-9]+-bank",
    r"cib-[a-z0-9]+-online",
    r"qnb-[a-z0-9]+-verify",
    r"@[a-zA-Z0-9]+",          # @ symbol inside URL path
    r"//.+//",                 # Multiple double slashes in URL
]

# Highly abused top-level domains frequently associated with phishing
SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".work", ".click", ".loan", ".win", ".bid"
]

def check_heuristics(url: str) -> tuple[bool, str]:
    """
    Evaluates a URL against rule-based heuristic patterns.
    Returns (is_suspicious: bool, reason: str).
    """
    url_lower = url.lower().strip()

    # 1. Check for IP address used as hostname
    parsed = urllib.parse.urlparse(url_lower if url_lower.startswith(('http://', 'https://')) else f'http://{url_lower}')
    host = parsed.netloc.split(':')[0]
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host):
        return True, "Heuristic Rule: Direct IP address host detected"

    # 2. Check for typosquatting regex patterns
    for pattern in TYPOSQUATTING_PATTERNS:
        if re.search(pattern, url_lower):
            return True, f"Heuristic Rule: Suspicious pattern match ({pattern})"

    # 3. Check suspicious TLDs
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            return True, f"Heuristic Rule: High-risk TLD detected ({tld})"

    return False, ""
