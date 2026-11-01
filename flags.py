import re

from CTFd.models import Flags
from CTFd.plugins.flags import BaseFlag, FlagException

HONEYPOT_FLAG_TYPE = "honeypot"

# Values of Flags.data for honeypot flags
MATCH_MODES = {
    "": "Exact match",
    "case_insensitive": "Exact match, case-insensitive",
    "regex": "Regular expression",
    "regex_case_insensitive": "Regular expression, case-insensitive",
}


def _matches(content, data, provided):
    saved = (content or "").strip()
    data = data or ""
    if data.startswith("regex"):
        flags = re.IGNORECASE if data.endswith("case_insensitive") else 0
        try:
            res = re.match(saved, provided, flags)
        except re.error as e:
            raise FlagException("Regex parse error occured") from e
        return bool(res) and res.group() == provided

    if data == "case_insensitive":
        saved, provided = saved.lower(), provided.lower()
    if len(saved) != len(provided):
        return False
    result = 0
    for x, y in zip(saved, provided):
        result |= ord(x) ^ ord(y)
    return result == 0


class HoneypotFlag(BaseFlag):
    """
    A flag that is a valid solution of its challenge but is also a trap for AI solvers.
    Organizers hide it where a human is unlikely to look; submitting it raises the
    account's AI-risk score.
    """

    name = HONEYPOT_FLAG_TYPE
    templates = {
        "create": "/plugins/ai_guard/assets/flag/create.html",
        "update": "/plugins/ai_guard/assets/flag/edit.html",
    }

    @staticmethod
    def compare(chal_key_obj, provided):
        return _matches(chal_key_obj.content, chal_key_obj.data, provided)


def find_honeypot(challenge_id, submission):
    """Return the honeypot flag matching the submission, preferring the challenge's own ones."""
    if not submission:
        return None
    honeypots = Flags.query.filter_by(type=HONEYPOT_FLAG_TYPE).all()
    honeypots.sort(key=lambda f: (str(f.challenge_id) != str(challenge_id), f.id))
    for flag in honeypots:
        try:
            if _matches(flag.content, flag.data, submission):
                return flag
        except FlagException:
            continue
    return None
