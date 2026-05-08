"""
detector.py — Core fraud pattern detection engine

Scans text messages for known scam indicators using weighted keyword patterns,
regex rules, and simple heuristics. Not ML-based — rules are hand-crafted from
real scam message patterns common in Nigeria/West Africa.

TODO: Consider adding a small trained classifier later (e.g. logistic regression
on TF-IDF features) to improve recall on novel phrasings. For now, rules suffice
for MVP.
"""

import re
from dataclasses import dataclass, field
from typing import List, Tuple


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class DetectionSignal:
    """A single matched fraud signal with its category, weight, and explanation."""
    category: str
    weight: float
    matched_text: str
    explanation: str


@dataclass
class DetectionResult:
    """Full output for one analyzed message."""
    raw_message: str
    signals: List[DetectionSignal] = field(default_factory=list)
    raw_score: float = 0.0  # sum of weights before normalization


# ---------------------------------------------------------------------------
# Rule definitions
# Each rule is: (pattern, category, weight, explanation)
# Weights are 1–10. Higher = stronger signal of fraud.
# Patterns are compiled at module load to avoid repeated re.compile() costs.
# ---------------------------------------------------------------------------

# NOTE: weights are somewhat arbitrary right now — tuned by manual inspection
# of ~50 real scam messages. Should be revisited with more data.

_RAW_RULES: List[Tuple[str, str, float, str]] = [

    # --- Urgency manipulation ---
    (r"\bact now\b", "urgency_manipulation", 7.0, "Urgency phrase 'act now'"),
    (r"\blimited time\b", "urgency_manipulation", 6.5, "Limited time pressure"),
    (r"\bexpires (today|tonight|soon|in \d+ hours?)\b", "urgency_manipulation", 7.5, "Explicit expiry deadline"),
    (r"\b(within|in) \d+ (hours?|minutes?|days?)\b", "urgency_manipulation", 5.0, "Short time window specified"),
    (r"\bdo not (ignore|delay|wait)\b", "urgency_manipulation", 6.0, "Urgency command phrase"),
    (r"\bimmediately\b", "urgency_manipulation", 4.5, "Urgency word: immediately"),
    (r"\b(final|last) (notice|warning|chance|opportunity)\b", "urgency_manipulation", 7.0, "Final warning language"),
    (r"\burgent(ly)?\b", "urgency_manipulation", 4.0, "Urgency marker: urgent"),
    (r"\byour account will be (suspended|blocked|closed|deactivated)\b", "urgency_manipulation", 8.0, "Account suspension threat"),
    (r"\bfailure to (respond|comply|verify|confirm)\b", "urgency_manipulation", 6.5, "Threat of consequence"),

    # --- OTP / credential harvesting ---
    (r"\b(send|share|provide|enter|confirm|submit) (your )?(otp|pin|password|passcode|code)\b", "otp_harvesting", 9.0, "Request for OTP or PIN"),
    (r"\bone.?time.?(password|code|pin)\b", "otp_harvesting", 9.0, "One-time password request"),
    (r"\bdo not share (this|your) (otp|code|pin|password) with (anyone|anybody)\b", "otp_harvesting", 6.0, "OTP warning (often prepended to harvest attempts)"),
    (r"\bverification code\b", "otp_harvesting", 7.0, "Verification code mention"),
    (r"\benter (the|your) code\b", "otp_harvesting", 6.5, "Code entry instruction"),
    (r"\b(your )?(bank )?bvn\b", "otp_harvesting", 8.5, "BVN (Bank Verification Number) request — sensitive"),
    (r"\bprovide your (account number|card number|cvv|expiry)\b", "otp_harvesting", 9.0, "Financial credential request"),
    (r"\b\d{4,8}[\s\-]?\d{4,8}\b.*\b(is your|as your) (otp|code|pin)\b", "otp_harvesting", 8.0, "Numeric code presented as OTP"),

    # --- Bank / financial impersonation ---
    (r"\b(access bank|gtb|gtbank|zenith bank|first bank|uba|fidelity|sterling|union bank|polaris|keystone|ecobank|wema)\b", "bank_impersonation", 6.0, "Nigerian bank name mentioned"),
    (r"\bfrom (the )?(bank|gtb|access|zenith|uba|first bank)\b", "bank_impersonation", 7.0, "Claim of message being from a bank"),
    (r"\byour (bank )?account has been (flagged|suspended|blocked|limited)\b", "bank_impersonation", 8.5, "False bank account alert"),
    (r"\bcredit alert\b", "bank_impersonation", 5.0, "Credit alert mention (could be fake alert scam)"),
    (r"\bdebit alert\b", "bank_impersonation", 4.5, "Debit alert mention"),
    (r"\binternet banking\b.*\b(suspended|blocked|disabled)\b", "bank_impersonation", 8.0, "Internet banking suspension claim"),
    (r"\bcbN\b|\bcentral bank of nigeria\b", "government_impersonation", 7.5, "CBN impersonation attempt"),
    (r"\byour (bvn|account) (has been|is) linked\b", "bank_impersonation", 6.5, "BVN link manipulation"),

    # --- Government impersonation ---
    (r"\b(efcc|icpc|firs|dss|ncc|nimc|ndlea|immigration)\b", "government_impersonation", 6.5, "Nigerian government agency name"),
    (r"\bfederal government of nigeria\b", "government_impersonation", 7.0, "Federal government impersonation"),
    (r"\bnin (verification|update|enrollment)\b", "government_impersonation", 7.0, "NIN-related manipulation"),
    (r"\b(police|army|military|interpol) (has|have) (placed|issued|filed)\b", "government_impersonation", 8.0, "Law enforcement threat"),
    (r"\byou (have been|are) (under investigation|wanted|arrested)\b", "government_impersonation", 9.0, "False arrest/investigation claim"),
    (r"\bpresidential (package|grant|relief|fund)\b", "government_impersonation", 8.0, "Fake presidential scheme"),
    (r"\bministry of (finance|health|education|trade)\b", "government_impersonation", 6.0, "Government ministry reference"),

    # --- Fake investment / crypto ---
    (r"\b(double|triple|multiply) your (money|investment|capital|funds)\b", "fake_investment", 9.5, "Too-good returns promise"),
    (r"\b\d{2,4}%\s*(return|profit|roi|interest)\b", "fake_investment", 8.0, "Unrealistically high return percentage"),
    (r"\b(guaranteed|risk.?free) (profit|return|income|earnings)\b", "fake_investment", 9.0, "Guaranteed profit claim (red flag)"),
    (r"\binvest (as little as|just|only) (ngn|₦|naira)?\s*[\d,]+\b", "fake_investment", 7.5, "Low entry investment pitch"),
    (r"\bcrypto(currency)? (investment|trading|platform|signal)\b", "fake_investment", 6.0, "Crypto investment pitch"),
    (r"\bforex (trading|signal|expert|manager)\b", "fake_investment", 7.0, "Forex trading pitch"),
    (r"\bpyramid\b|\bponzi\b", "fake_investment", 8.5, "Pyramid/Ponzi structure hint"),
    (r"\b(passive|residual) income\b", "fake_investment", 5.0, "Passive income promise"),
    (r"\bwithdraw (your )?(profit|earning|fund|money) anytime\b", "fake_investment", 7.5, "Withdrawal promise (common in investment scams)"),
    (r"\brefer (and earn|friends|others)\b", "fake_investment", 6.0, "Referral earnings scheme"),

    # --- Fake job offers ---
    (r"\b(earn|make|get paid) (up to|between)?\s*(ngn|₦|naira)?\s*[\d,]+ (daily|weekly|per day|per week)\b", "fake_job_offer", 8.0, "Unrealistic daily earning claim"),
    (r"\bwork from home\b.*\b(earn|income|pay)\b", "fake_job_offer", 6.5, "Work from home earning pitch"),
    (r"\bno experience (required|needed)\b", "fake_job_offer", 5.5, "No-experience job (often fake)"),
    (r"\b(urgent|immediate(ly)?) (hiring|recruitment|employment)\b", "fake_job_offer", 6.0, "Urgent hiring urgency"),
    (r"\bsend (your )?(cv|resume|details|biodata) (to|via|on) (whatsapp|telegram|email)\b", "fake_job_offer", 7.0, "Informal CV collection method"),
    (r"\bregistration fee\b", "fake_job_offer", 8.5, "Registration fee (advance fee scam)"),
    (r"\btraining (fee|material|kit)\b", "fake_job_offer", 7.5, "Training material fee request"),

    # --- Giveaway / lottery ---
    (r"\b(you have|you've) (won|been selected|been chosen)\b", "giveaway_lottery", 8.0, "Winner notification"),
    (r"\b(cash prize|gift card|prize money|winning)\b", "giveaway_lottery", 7.0, "Prize mention"),
    (r"\bclaim (your )?(prize|reward|gift|winnings|package)\b", "giveaway_lottery", 8.5, "Prize claim instruction"),
    (r"\blottery\b", "giveaway_lottery", 7.5, "Lottery mention"),
    (r"\b(lucky|selected) (winner|beneficiary|recipient)\b", "giveaway_lottery", 8.0, "Lucky winner language"),
    (r"\bpromo(tion)? (winner|code|reward)\b", "giveaway_lottery", 6.0, "Promotion winner claim"),
    (r"\bmtn|airtel|glo|9mobile.*\b(promo|giveaway|reward|data)\b", "giveaway_lottery", 6.5, "Telecom brand giveaway impersonation"),

    # --- Account verification scams ---
    (r"\b(verify|update|confirm|reactivate) (your )?(account|profile|details|information)\b", "account_verification", 7.0, "Account verification request"),
    (r"\bclick (the |this )?(link|button|here)\b", "account_verification", 5.0, "Generic click link instruction"),
    (r"\bhttps?://\S+\b", "account_verification", 3.5, "URL present in message"),
    (r"\bbit\.ly|tinyurl|t\.co|rebrand\.ly\b", "account_verification", 6.0, "Shortened URL (often used to hide malicious links)"),
    (r"\byour account (will be|has been) (suspended|verified|updated|closed)\b", "account_verification", 7.5, "Account status manipulation"),
    (r"\blog(in|on) (to|now|immediately)\b", "account_verification", 5.0, "Login instruction"),

    # --- Romance / social engineering ---
    (r"\bmy (dear|darling|love|sweetheart|honey)\b", "romance_scam", 5.5, "Romantic endearment (unsolicited)"),
    (r"\bi (have|need to) (tell|share|confess) something (important|serious|urgent)\b", "romance_scam", 6.0, "Emotional setup phrase"),
    (r"\bi am (a )?(soldier|doctor|engineer|diplomat|contractor) (stationed|working|based)\b", "romance_scam", 8.0, "Classic romance scam profession claim"),
    (r"\bsend (me )?(money|funds|airtime|credit|recharge)\b", "romance_scam", 8.5, "Direct money request"),
    (r"\bi (am|will be) coming to (see|meet|visit) you\b", "romance_scam", 5.5, "Romance visit setup"),
    (r"\bpackage (is|has been) (seized|held|detained) (at )?(customs|airport|border)\b", "romance_scam", 9.0, "Customs package scam (common romance/delivery variant)"),

    # --- Fake delivery / logistics ---
    (r"\byour (parcel|package|shipment|order|delivery) (has|is)\b", "delivery_scam", 5.0, "Package status message"),
    (r"\b(dhl|fedex|ups|courier|pos agent).*\b(pending|awaiting|held|detained)\b", "delivery_scam", 7.5, "Delivery company with package hold"),
    (r"\bdelivery fee\b|\bclearance fee\b|\bcustoms duty\b", "delivery_scam", 8.0, "Fee to release package"),
    (r"\btrack (your )?(order|shipment|parcel)\b", "delivery_scam", 3.5, "Tracking instruction (low signal alone)"),

    # --- Nigerian Pidgin patterns ---
    # These are lower-weight because pidgin phrasing is less precise
    # and risks more false positives. Still worth catching.
    (r"\b(don|don't) (notice|see|find)\b.*\b(account|card|bvn|otp)\b", "bank_impersonation", 5.5, "Pidgin bank alert phrasing"),
    (r"\b(you don win|you win|you don collect)\b", "giveaway_lottery", 7.0, "Pidgin winner claim"),
    (r"\b(send|dey send) (your )?(otp|pin|code|password|bvn)\b", "otp_harvesting", 8.0, "Pidgin OTP request"),
    (r"\b(make you|abeg) (send|transfer|pay)\b", "romance_scam", 6.5, "Pidgin money request"),
    (r"\b(earn|collect|collect am|make) ₦[\d,]+ (daily|weekly|per day)\b", "fake_job_offer", 7.5, "Pidgin earning claim"),
    (r"\b(no be scam|na legit|i swear)\b", "information_control", 6.0, "Legitimacy insistence (common in scam messages)"),
    (r"\b(wetin you get to lose|e no go cost you|e easy)\b", "fake_investment", 5.5, "Pidgin low-risk investment pitch"),
    (r"\b(your account don|account don) (get|reach|exceed)\b", "bank_impersonation", 6.0, "Pidgin account status alert"),
    (r"\b(abeg|pls|plz).{0,30}(send|transfer|pay|share)\b", "romance_scam", 5.0, "Pleading money request"),

    # --- Generic red flags / cross-category ---
    (r"\bdo not tell anyone\b|\bkeep this (secret|confidential|between us)\b", "information_control", 8.0, "Secrecy instruction — major red flag"),
    (r"\bcontact (me|us|him|her) (on|via|through) (whatsapp|telegram|signal)\b", "information_control", 5.5, "Redirect to private channel"),
    (r"\bpay(ment)? (via|through|using) (bitcoin|btc|eth|usdt|crypto|gift card)\b", "payment_method_red_flag", 8.5, "Untraceable payment method"),
    (r"\bgift card\b", "payment_method_red_flag", 7.5, "Gift card payment request"),
    (r"\brecharge card\b|\bairtime\b.*\bsend\b", "payment_method_red_flag", 7.0, "Airtime/recharge as payment"),
    (r"\bwestern union\b|\bmoneygram\b|\bwave\b.*\btransfer\b", "payment_method_red_flag", 7.5, "Informal/untraceable money transfer service"),
]

# Pre-compile all patterns. Case-insensitive matching throughout.
RULES: List[Tuple[re.Pattern, str, float, str]] = [
    (re.compile(pattern, re.IGNORECASE | re.MULTILINE), cat, weight, expl)
    for pattern, cat, weight, expl in _RAW_RULES
]


# ---------------------------------------------------------------------------
# Detector function
# ---------------------------------------------------------------------------

def analyze_message(message: str) -> DetectionResult:
    """
    Run all rules against the message. Returns a DetectionResult with
    every matched signal.

    Note: we deliberately allow a single message to match multiple signals
    in the same category — additive scoring is intentional. A message that
    hits 3 urgency patterns is more suspicious than one that hits 1.
    """
    result = DetectionResult(raw_message=message)

    for pattern, category, weight, explanation in RULES:
        matches = pattern.findall(message)
        if matches:
            # Flatten match tuples (from groups) to strings for display
            matched_text = _flatten_match(matches[0])
            signal = DetectionSignal(
                category=category,
                weight=weight,
                matched_text=matched_text,
                explanation=explanation,
            )
            result.signals.append(signal)
            result.raw_score += weight

    return result


def _flatten_match(match) -> str:
    """Turn a regex match (string or tuple of groups) into a readable string."""
    if isinstance(match, tuple):
        return " ".join(p for p in match if p)
    return str(match)


# ---------------------------------------------------------------------------
# Quick test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    test = (
        "Dear customer, your Access Bank account has been suspended. "
        "Send your OTP and BVN immediately to verify. Act now or your "
        "account will be closed within 24 hours. Do not ignore this message."
    )
    result = analyze_message(test)
    print(f"Signals found: {len(result.signals)}")
    for s in result.signals:
        print(f"  [{s.category}] weight={s.weight} — {s.explanation}")
    print(f"Raw score: {result.raw_score}")
