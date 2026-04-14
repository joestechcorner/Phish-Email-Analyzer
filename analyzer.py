"""
Phishing Email Analyzer - Backend Module
Analyzes email files for phishing indicators using weighted scoring
"""

import re
import email
from email import policy
from urllib.parse import urlparse
from typing import List, Tuple, Dict


class PhishingAnalyzer:
    """Main analyzer class for detecting phishing emails"""
    
    def __init__(self, top_domains_file: str, hard_keywords_file: str, soft_keywords_file: str):
        """
        Initialize the analyzer with keyword and domain lists
        
        Args:
            top_domains_file: Path to file containing top 10000 trusted domains
            hard_keywords_file: Path to file containing high-risk keywords
            soft_keywords_file: Path to file containing moderate-risk keywords
        """
        self.top_domains = self._load_domains(top_domains_file)
        self.hard_keywords = self._load_keywords(hard_keywords_file)
        self.soft_keywords = self._load_keywords(soft_keywords_file)
        
        # Built-in urgent language patterns (can be extended)
        self.urgent_patterns = [
            'urgent', 'immediately', 'action required', 'account suspended',
            'verify now', 'click here', 'confirm your', 'suspended account',
            'unusual activity', 'security alert', 'expires today', 'act now',
            'limited time', 'verify your account', 'update required'
        ]
        
        # Scoring weights - carefully calibrated for accuracy
        self.WEIGHTS = {
            'sender_not_whitelisted': 25,  # Sender domain not in top domains
            'hard_keyword': 15,             # Each hard keyword match
            'soft_keyword': 5,              # Each soft keyword match
            'suspicious_url': 10,           # Each non-whitelisted URL
            'urgent_language': 8,           # Each urgent phrase
            'email_spoofing': 20,           # Spoofing indicators
            'no_sender': 30,                # Missing sender (highly suspicious)
            'multiple_urls': 5,             # Bonus for multiple suspicious URLs
        }
        
        self.score = 0
        self.details = []  # Store detailed findings
    
    def _load_domains(self, filepath: str) -> set:
        """
        Load trusted domains from file into a set for fast lookup
        
        Args:
            filepath: Path to domains file
            
        Returns:
            Set of domain names (lowercase)
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                # Remove whitespace and convert to lowercase
                return {line.strip().lower() for line in f if line.strip()}
        except FileNotFoundError:
            print(f"Warning: {filepath} not found. Creating empty domain list.")
            return set()
    
    def _load_keywords(self, filepath: str) -> set:
        """
        Load keywords from file into a set
        
        Args:
            filepath: Path to keywords file
            
        Returns:
            Set of keywords (lowercase)
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return {line.strip().lower() for line in f if line.strip()}
        except FileNotFoundError:
            print(f"Warning: {filepath} not found. Creating empty keyword list.")
            return set()
    
    def _extract_urls(self, text: str) -> List[str]:
        """
        Extract all URLs from text using regex pattern
        
        Args:
            text: Text to search for URLs
            
        Returns:
            List of found URLs
        """
        # Regex pattern to match URLs (http/https)
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        return re.findall(url_pattern, text, re.IGNORECASE)
    
    def _extract_domain(self, url: str) -> str:
        """
        Extract domain name from URL
        
        Args:
            url: Full URL string
            
        Returns:
            Domain name without subdomain (e.g., example.com)
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            # Remove 'www.' prefix if present
            if domain.startswith('www.'):
                domain = domain[4:]
            # Extract base domain (last two parts)
            parts = domain.split('.')
            if len(parts) >= 2:
                return '.'.join(parts[-2:])
            return domain
        except Exception:
            return ""
    
    def _check_email_spoofing(self, sender: str, body: str) -> Tuple[bool, str]:
        """
        Check for email spoofing indicators
        
        Args:
            sender: Sender email address
            body: Email body text
            
        Returns:
            Tuple of (is_spoofed, reason)
        """
        if not sender:
            return False, ""
        
        # Extract sender domain
        sender_lower = sender.lower()
        sender_domain = ""
        if '@' in sender_lower:
            sender_domain = sender_lower.split('@')[1]
        
        # Check for common spoofing patterns
        spoofing_indicators = []
        
        # Check if sender claims to be from major companies but domain doesn't match
        major_companies = ['paypal', 'amazon', 'microsoft', 'google', 'apple', 
                          'facebook', 'bank', 'irs', 'fedex', 'ups', 'dhl']
        
        for company in major_companies:
            # If email body mentions company but sender domain doesn't match
            if company in body.lower():
                if company not in sender_domain:
                    spoofing_indicators.append(f"Claims to be from {company} but sender domain doesn't match")
        
        # Check for lookalike domains (homograph attacks)
        suspicious_chars = ['1' if 'l' in sender_domain else '',
                           '0' if 'o' in sender_domain else '',
                           'rn' if 'm' in sender_domain else '']
        
        if any(suspicious_chars):
            spoofing_indicators.append("Possible homograph attack (lookalike characters)")
        
        if spoofing_indicators:
            return True, "; ".join(spoofing_indicators)
        
        return False, ""
    
    def analyze_file(self, filepath: str) -> Dict:
        """
        Main analysis function for email files
        
        Args:
            filepath: Path to .eml or .txt file
            
        Returns:
            Dictionary containing score, risk level, and detailed findings
        """
        # Reset score and details for new analysis
        self.score = 0
        self.details = []
        
        # Determine file type and extract content
        if filepath.endswith('.eml'):
            sender, body = self._parse_eml(filepath)
        else:
            # Treat as plain text
            sender, body = self._parse_txt(filepath)
        
        # Convert body to lowercase for case-insensitive matching
        body_lower = body.lower()
        
        # 1. ANALYZE SENDER ADDRESS
        if not sender:
            # No sender found - highly suspicious
            self.score += self.WEIGHTS['no_sender']
            self.details.append(f"⚠️ No sender address found (+{self.WEIGHTS['no_sender']} points)")
        else:
            # Extract sender domain
            sender_domain = self._extract_domain(f"http://{sender.split('@')[1]}") if '@' in sender else ""
            
            # Check if sender domain is in whitelist
            if sender_domain and sender_domain not in self.top_domains:
                self.score += self.WEIGHTS['sender_not_whitelisted']
                self.details.append(f"⚠️ Sender domain '{sender_domain}' not in trusted domains list (+{self.WEIGHTS['sender_not_whitelisted']} points)")
            
            # Check for email spoofing
            is_spoofed, spoof_reason = self._check_email_spoofing(sender, body)
            if is_spoofed:
                self.score += self.WEIGHTS['email_spoofing']
                self.details.append(f"⚠️ Email spoofing detected: {spoof_reason} (+{self.WEIGHTS['email_spoofing']} points)")
        
        # 2. ANALYZE URLs IN EMAIL BODY
        urls = self._extract_urls(body)
        suspicious_urls = []
        
        for url in urls:
            domain = self._extract_domain(url)
            if domain and domain not in self.top_domains:
                suspicious_urls.append(url)
                self.score += self.WEIGHTS['suspicious_url']
        
        if suspicious_urls:
            self.details.append(f"⚠️ Found {len(suspicious_urls)} suspicious URL(s) not in whitelist (+{len(suspicious_urls) * self.WEIGHTS['suspicious_url']} points)")
            # Add bonus for multiple suspicious URLs
            if len(suspicious_urls) > 2:
                bonus = (len(suspicious_urls) - 2) * self.WEIGHTS['multiple_urls']
                self.score += bonus
                self.details.append(f"⚠️ Multiple suspicious URLs detected (+{bonus} bonus points)")
        
        # 3. ANALYZE HARD KEYWORDS (word-by-word analysis)
        words = re.findall(r'\b\w+\b', body_lower)  # Extract individual words
        hard_matches = []
        
        for word in words:
            if word in self.hard_keywords:
                hard_matches.append(word)
        
        # Count unique hard keyword matches
        unique_hard = set(hard_matches)
        if unique_hard:
            points = len(unique_hard) * self.WEIGHTS['hard_keyword']
            self.score += points
            self.details.append(f"🚨 Found {len(unique_hard)} HIGH-RISK keyword(s): {', '.join(list(unique_hard)[:5])}{'...' if len(unique_hard) > 5 else ''} (+{points} points)")
        
        # 4. ANALYZE SOFT KEYWORDS (word-by-word analysis)
        soft_matches = []
        
        for word in words:
            if word in self.soft_keywords:
                soft_matches.append(word)
        
        # Count unique soft keyword matches
        unique_soft = set(soft_matches)
        if unique_soft:
            points = len(unique_soft) * self.WEIGHTS['soft_keyword']
            self.score += points
            self.details.append(f"⚠️ Found {len(unique_soft)} moderate-risk keyword(s): {', '.join(list(unique_soft)[:5])}{'...' if len(unique_soft) > 5 else ''} (+{points} points)")
        
        # 5. ANALYZE URGENT LANGUAGE PATTERNS
        urgent_found = []
        
        for pattern in self.urgent_patterns:
            if pattern in body_lower:
                urgent_found.append(pattern)
        
        if urgent_found:
            points = len(urgent_found) * self.WEIGHTS['urgent_language']
            self.score += points
            self.details.append(f"⚠️ Found {len(urgent_found)} urgent language pattern(s): {', '.join(urgent_found[:3])}{'...' if len(urgent_found) > 3 else ''} (+{points} points)")
        
        # Cap score at 100
        self.score = min(self.score, 100)
        
        # Determine risk level
        risk_level, recommendations = self._determine_risk_level(self.score)
        
        return {
            'score': self.score,
            'risk_level': risk_level,
            'details': self.details,
            'recommendations': recommendations,
            'sender': sender,
            'url_count': len(urls),
            'suspicious_url_count': len(suspicious_urls)
        }
    
    def _parse_eml(self, filepath: str) -> Tuple[str, str]:
        """
        Parse .eml email file and extract sender and body
        
        Args:
            filepath: Path to .eml file
            
        Returns:
            Tuple of (sender_address, body_text)
        """
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                msg = email.message_from_file(f, policy=policy.default)
            
            # Extract sender
            sender = msg.get('From', '')
            # Extract email address from "Name <email@domain.com>" format
            if '<' in sender and '>' in sender:
                sender = sender[sender.index('<')+1:sender.index('>')]
            
            # Extract body
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
            else:
                body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
            
            return sender, body
        except Exception as e:
            print(f"Error parsing .eml file: {e}")
            return "", ""
    
    def _parse_txt(self, filepath: str) -> Tuple[str, str]:
        """
        Parse .txt file and extract content
        
        Args:
            filepath: Path to .txt file
            
        Returns:
            Tuple of (sender_address, body_text)
        """
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Try to extract sender from common patterns
            sender = ""
            sender_patterns = [
                r'From:\s*<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>?',
                r'from:\s*<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>?',
            ]
            
            for pattern in sender_patterns:
                match = re.search(pattern, content)
                if match:
                    sender = match.group(1)
                    break
            
            return sender, content
        except Exception as e:
            print(f"Error parsing .txt file: {e}")
            return "", ""
    
    def _determine_risk_level(self, score: int) -> Tuple[str, List[str]]:
        """
        Determine risk level and recommendations based on score
        
        Args:
            score: Calculated phishing score
            
        Returns:
            Tuple of (risk_level_label, recommendations_list)
        """
        if score <= 30:
            # BENIGN: Low risk
            return "BENIGN", [
                "✓ Email appears to be legitimate",
                "✓ No immediate action required",
                "✓ Standard security practices apply",
                "• Still verify sender if requesting sensitive information",
                "• Be cautious with links and attachments"
            ]
        elif score <= 60:
            # SUSPICIOUS: Medium risk
            return "SUSPICIOUS", [
                "⚠️ QUARANTINE this email for manual review",
                "⚠️ DO NOT click any links or download attachments",
                "⚠️ Verify sender through alternative communication channel",
                "• Contact sender directly using known contact information",
                "• Check email headers for authenticity",
                "• Report to IT security team if in corporate environment"
            ]
        else:
            # MALICIOUS: High risk
            return "MALICIOUS", [
                "🚨 BLOCK this email immediately",
                "🚨 DO NOT INTERACT with this email in any way",
                "🚨 DELETE without opening links or attachments",
                "🚨 REPORT to security team/email provider",
                "🚨 ALERT other users if sent to multiple recipients",
                "• Scan system for malware if any links were clicked",
                "• Change passwords if credentials were entered",
                "• Monitor accounts for suspicious activity"
            ]
