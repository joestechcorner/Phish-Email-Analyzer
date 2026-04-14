# Phishing Email Analyzer

A Python-based tool for detecting phishing emails using weighted scoring and multiple analysis techniques.

## Overview

This tool analyzes email files (.txt and .eml formats) for phishing indicators using a sophisticated weighted scoring system. It checks for suspicious URLs, keywords, sender authenticity, and other red flags to determine the likelihood of an email being a phishing attempt.

## Files Included

- **analyzer.py** - Backend analysis engine with all detection logic
- **main.py** - Frontend interface with color-coded output
- **hard_keywords.txt** - High-risk keywords (significant score increase)
- **soft_keywords.txt** - Moderate-risk keywords (smaller score increase)
- **top-10000-domains.txt** - Whitelist of trusted domains (sample, expand as needed)
- **sample_phishing.txt** - Example phishing email for testing
- **sample_benign.txt** - Example legitimate email for testing

## Installation

### Requirements
- Python 3.6 or higher
- No external dependencies required (uses standard library only)

### Setup
1. Ensure all files are in the same directory
2. Make sure the keyword and domain files are present
3. You can expand the domain whitelist with actual top 10,000 domains

## Usage

### Command Line Mode
```bash
python main.py path/to/email.txt
```

### Interactive Mode
```bash
python main.py
```
Then enter file paths when prompted.

## Weighted Scoring System

The analyzer uses a carefully calibrated weighted scoring system to calculate a risk score from 0-100:

### Scoring Weights

| Detection Type | Points | Description |
|---------------|--------|-------------|
| **Sender Not Whitelisted** | +25 | Sender domain not in trusted domains list |
| **Hard Keyword Match** | +15 each | Each high-risk keyword found (e.g., "password", "ssn") |
| **Soft Keyword Match** | +5 each | Each moderate-risk keyword found (e.g., "urgent", "verify") |
| **Suspicious URL** | +10 each | Each URL with non-whitelisted domain |
| **Urgent Language** | +8 each | Each urgent phrase detected ("act now", "expires today") |
| **Email Spoofing** | +20 | Spoofing indicators detected |
| **No Sender** | +30 | Missing sender address (highly suspicious) |
| **Multiple URLs Bonus** | +5 each | Bonus for 3+ suspicious URLs |

### Risk Classification

**Score 0-30: BENIGN (Green)**
- Low risk, appears legitimate
- No immediate action required
- Standard security practices apply
- Recommendations: Verify sender if requesting sensitive info

**Score 31-60: SUSPICIOUS (Yellow)**
- Medium risk, potentially dangerous
- Recommendations:
  - Quarantine for manual review
  - Do not click links or download attachments
  - Verify sender through alternative channel
  - Contact sender directly using known contact info
  - Report to IT security team

**Score 61-100: MALICIOUS (Red)**
- High risk, likely phishing attempt
- Recommendations:
  - BLOCK immediately
  - DO NOT INTERACT
  - DELETE without opening
  - REPORT to security team
  - ALERT other users if widely distributed
  - Scan system if already interacted with
  - Change passwords if credentials entered

## Analysis Features

### 1. Sender Analysis
- Extracts sender email address from .eml or .txt files
- Checks if sender domain is in whitelist
- Detects email spoofing attempts
- Identifies mismatched sender claims (e.g., claims to be from PayPal but domain doesn't match)

### 2. URL Analysis
- Extracts all URLs from email body
- Checks each URL domain against whitelist
- Identifies suspicious non-whitelisted URLs
- Adds bonus points for multiple suspicious URLs

### 3. Keyword Analysis (Word-by-Word)
- Analyzes each word individually
- Matches against hard keywords (high risk)
- Matches against soft keywords (moderate risk)
- Counts unique matches to avoid duplicate scoring

### 4. Urgent Language Detection
- Built-in patterns for urgent/pressure tactics
- Detects phrases like:
  - "urgent", "immediately", "action required"
  - "account suspended", "verify now", "expires today"
  - "unusual activity", "security alert", "act now"

### 5. Spoofing Detection
- Checks if body mentions major companies but sender doesn't match
- Detects potential homograph attacks (lookalike characters)
- Identifies brand impersonation attempts

## Customization

### Adding Keywords

**Hard Keywords** (hard_keywords.txt):
- Add one keyword per line
- Use for high-risk terms (credentials, financial info, threats)
- Each match adds 15 points

**Soft Keywords** (soft_keywords.txt):
- Add one keyword per line
- Use for suspicious but not necessarily malicious terms
- Each match adds 5 points

### Expanding Domain Whitelist

The `top-10000-domains.txt` file should contain trusted domains:
- Add one domain per line
- Use base domain format (example.com, not www.example.com)
- You can download actual top domains lists online
- Common sources: Alexa Top Sites, Cisco Umbrella, etc.

### Adjusting Weights

Edit the `WEIGHTS` dictionary in `analyzer.py`:
```python
self.WEIGHTS = {
    'sender_not_whitelisted': 25,
    'hard_keyword': 15,
    'soft_keyword': 5,
    # ... adjust values as needed
}
```

### Adding Urgent Patterns

Edit the `urgent_patterns` list in `analyzer.py`:
```python
self.urgent_patterns = [
    'urgent',
    'your custom pattern here',
    # ... add more patterns
]
```

## Output Example

```
======================================================================
PHISHING EMAIL ANALYZER
======================================================================

Analyzing: sample_phishing.txt

Processing...

======================================================================

PHISHING RISK SCORE:

  ╔═══════════════════════════════╗
  ║                               ║
  ║         SCORE: 100/100        ║
  ║                               ║
  ║      [  MALICIOUS   ]         ║
  ║                               ║
  ╚═══════════════════════════════╝

Risk Meter: [██████████████████████████████████████████████████] 100%

0-30: BENIGN | 31-60: SUSPICIOUS | 61-100: MALICIOUS
──────────────────────────────────────────────────────────────────────

DETAILED FINDINGS:

⚠️ Sender domain 'paypa1-secure.com' not in trusted domains list (+25 points)
⚠️ Email spoofing detected: Claims to be from paypal but sender domain doesn't match (+20 points)
⚠️ Found 1 suspicious URL(s) not in whitelist (+10 points)
🚨 Found 6 HIGH-RISK keyword(s): password, banking, suspended, ssn, social, security (+90 points)
⚠️ Found 4 moderate-risk keyword(s): urgent, verify, immediately, activity (+20 points)
⚠️ Found 3 urgent language pattern(s): unusual activity, immediately, act now (+24 points)
```

## Testing

Test with the included sample files:

```bash
# Test with phishing email (should score high)
python main.py sample_phishing.txt

# Test with benign email (should score low)
python main.py sample_benign.txt
```

## Best Practices

1. **Keep whitelists updated** - Regularly update your trusted domains list
2. **Monitor false positives** - Adjust weights if legitimate emails score too high
3. **Review manually** - Always manually review suspicious emails (31-60 range)
4. **Update keywords** - Add new phishing terms as they emerge
5. **Train users** - Use results to educate users about phishing indicators

## Limitations

- Does not analyze image-based phishing
- Cannot detect zero-day phishing campaigns
- Requires manual updates to keyword lists
- May produce false positives for legitimate marketing emails
- Does not check actual URL reputation (only domain whitelist)

## Future Enhancements Coming

- Machine learning integration
- Live URL reputation checking
- Image analysis for embedded text
- Header analysis for SPF/DKIM/DMARC
- Integration with threat intelligence feeds
- Database logging for pattern analysis
- Web interface
- API endpoint for automated scanning

## License

This tool is provided as-is for educational and security purposes.

## Author

Created for email security analysis and phishing detection.
