BURST = "burst"
FAST_DELTA = "fast_delta"
HONEYPOT = "honeypot"
API_TOKEN = "api_token"
QUICK_SOLVE = "quick_solve"
AUTO_HIDE = "auto_hide"
MANUAL = "manual"
RESET = "reset"
UNHIDE = "unhide"
WHITELIST = "whitelist"
UNWHITELIST = "unwhitelist"
SHAME = "shame"
UNSHAME = "unshame"

# Kinds produced by the detector. Everything else is an admin action.
SIGNALS = (BURST, FAST_DELTA, HONEYPOT, API_TOKEN, QUICK_SOLVE)

LABELS = {
    BURST: "Mass solving",
    FAST_DELTA: "Short interval between flags",
    HONEYPOT: "Honeypot flag",
    API_TOKEN: "Submitted with an API token",
    QUICK_SOLVE: "Quick solve after opening",
    AUTO_HIDE: "Auto-hidden",
    MANUAL: "Manual adjustment",
    RESET: "Score reset",
    UNHIDE: "Restored to the scoreboard",
    WHITELIST: "Trusted",
    UNWHITELIST: "No longer trusted",
    SHAME: "Wall of shame",
    UNSHAME: "Removed from the wall of shame",
}


def label(kind):
    return LABELS.get(kind, kind)
