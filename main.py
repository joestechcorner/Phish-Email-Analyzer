"""
Phishing Email Analyzer - Frontend Interface
Command-line interface with color-coded risk display
"""

import sys
import os
from analyzer import PhishingAnalyzer


# ANSI color codes for terminal output
class Colors:
    """Terminal color codes for formatted output"""
    RED = '\033[91m'        # High risk (malicious)
    YELLOW = '\033[93m'     # Medium risk (suspicious)
    GREEN = '\033[92m'      # Low risk (benign)
    BLUE = '\033[94m'       # Info
    BOLD = '\033[1m'        # Bold text
    RESET = '\033[0m'       # Reset to default


def print_header():
    """Print application header"""
    print("\n" + "="*70)
    print(f"{Colors.BOLD}{Colors.BLUE}PHISHING EMAIL ANALYZER{Colors.RESET}")
    print("="*70 + "\n")


def print_score_display(score: int, risk_level: str):
    """
    Print large, color-coded risk score
    
    Args:
        score: Phishing score (0-100)
        risk_level: Risk category (BENIGN/SUSPICIOUS/MALICIOUS)
    """
    # Determine color based on score
    if score <= 30:
        color = Colors.GREEN
    elif score <= 60:
        color = Colors.YELLOW
    else:
        color = Colors.RED
    
    # ASCII art for large score display
    score_str = str(score)
    
    print(f"\n{Colors.BOLD}PHISHING RISK SCORE:{Colors.RESET}")
    print(f"{color}{Colors.BOLD}")
    print(f"  ╔═══════════════════════════════╗")
    print(f"  ║                               ║")
    print(f"  ║         SCORE: {score_str:>3}/100       ║")
    print(f"  ║                               ║")
    print(f"  ║      [{risk_level:^13}]      ║")
    print(f"  ║                               ║")
    print(f"  ╚═══════════════════════════════╝")
    print(f"{Colors.RESET}\n")


def print_risk_bar(score: int):
    """
    Print visual risk meter bar
    
    Args:
        score: Phishing score (0-100)
    """
    # Create 50-character progress bar
    bar_length = 50
    filled = int((score / 100) * bar_length)
    
    # Determine colors for different sections
    bar = ""
    for i in range(bar_length):
        if i < filled:
            if score <= 30:
                bar += f"{Colors.GREEN}█{Colors.RESET}"
            elif score <= 60:
                bar += f"{Colors.YELLOW}█{Colors.RESET}"
            else:
                bar += f"{Colors.RED}█{Colors.RESET}"
        else:
            bar += "░"
    
    print(f"Risk Meter: [{bar}] {score}%\n")
    print(f"{Colors.GREEN}0-30: BENIGN{Colors.RESET} | {Colors.YELLOW}31-60: SUSPICIOUS{Colors.RESET} | {Colors.RED}61-100: MALICIOUS{Colors.RESET}")
    print("─" * 70 + "\n")


def print_analysis_details(details: list):
    """
    Print detailed findings from analysis
    
    Args:
        details: List of finding strings
    """
    print(f"{Colors.BOLD}DETAILED FINDINGS:{Colors.RESET}\n")
    
    if not details:
        print(f"{Colors.GREEN}✓ No significant threats detected{Colors.RESET}\n")
    else:
        for detail in details:
            # Color-code based on severity indicators
            if '🚨' in detail or 'HIGH-RISK' in detail:
                print(f"{Colors.RED}{detail}{Colors.RESET}")
            elif '⚠️' in detail:
                print(f"{Colors.YELLOW}{detail}{Colors.RESET}")
            else:
                print(detail)
    
    print()


def print_recommendations(recommendations: list, risk_level: str):
    """
    Print recommended actions based on risk level
    
    Args:
        recommendations: List of recommendation strings
        risk_level: Risk category for color coding
    """
    # Determine color based on risk level
    if risk_level == "BENIGN":
        color = Colors.GREEN
    elif risk_level == "SUSPICIOUS":
        color = Colors.YELLOW
    else:
        color = Colors.RED
    
    print(f"{color}{Colors.BOLD}RECOMMENDED ACTIONS:{Colors.RESET}\n")
    
    for rec in recommendations:
        if rec.startswith('🚨'):
            print(f"{Colors.RED}{Colors.BOLD}{rec}{Colors.RESET}")
        elif rec.startswith('⚠️'):
            print(f"{Colors.YELLOW}{rec}{Colors.RESET}")
        elif rec.startswith('✓'):
            print(f"{Colors.GREEN}{rec}{Colors.RESET}")
        else:
            print(f"{color}{rec}{Colors.RESET}")
    
    print()


def print_summary(result: dict):
    """
    Print summary statistics
    
    Args:
        result: Analysis result dictionary
    """
    print(f"{Colors.BOLD}SUMMARY:{Colors.RESET}")
    print(f"• Sender: {result['sender'] if result['sender'] else 'Not found'}")
    print(f"• Total URLs found: {result['url_count']}")
    print(f"• Suspicious URLs: {result['suspicious_url_count']}")
    print(f"• Risk Score: {result['score']}/100")
    print(f"• Classification: {result['risk_level']}")
    print()


def analyze_email(filepath: str, analyzer: PhishingAnalyzer):
    """
    Analyze email file and display results
    
    Args:
        filepath: Path to email file
        analyzer: PhishingAnalyzer instance
    """
    # Check if file exists
    if not os.path.exists(filepath):
        print(f"{Colors.RED}Error: File '{filepath}' not found{Colors.RESET}")
        return
    
    # Check file extension
    if not (filepath.endswith('.txt') or filepath.endswith('.eml')):
        print(f"{Colors.YELLOW}Warning: File should be .txt or .eml format{Colors.RESET}")
    
    print(f"{Colors.BLUE}Analyzing: {filepath}{Colors.RESET}\n")
    print("Processing...")
    
    # Perform analysis
    result = analyzer.analyze_file(filepath)
    
    # Display results
    print("\n" + "="*70)
    print_score_display(result['score'], result['risk_level'])
    print_risk_bar(result['score'])
    print_analysis_details(result['details'])
    print_recommendations(result['recommendations'], result['risk_level'])
    print_summary(result)
    print("="*70 + "\n")


def main():
    """Main entry point for the application"""
    print_header()
    
    # Define paths to required files
    TOP_DOMAINS_FILE = "top-100000-domains.txt"
    HARD_KEYWORDS_FILE = "hard_keywords.txt"
    SOFT_KEYWORDS_FILE = "soft_keywords.txt"
    
    # Check if required files exist
    missing_files = []
    for file in [TOP_DOMAINS_FILE, HARD_KEYWORDS_FILE, SOFT_KEYWORDS_FILE]:
        if not os.path.exists(file):
            missing_files.append(file)
    
    if missing_files:
        print(f"{Colors.YELLOW}Warning: The following files are missing:{Colors.RESET}")
        for file in missing_files:
            print(f"  • {file}")
        print(f"\n{Colors.YELLOW}The analyzer will continue with reduced functionality.{Colors.RESET}\n")
    
    # Initialize analyzer
    analyzer = PhishingAnalyzer(TOP_DOMAINS_FILE, HARD_KEYWORDS_FILE, SOFT_KEYWORDS_FILE)
    
    # Check for command-line argument
    if len(sys.argv) > 1:
        # File path provided as argument
        filepath = sys.argv[1]
        analyze_email(filepath, analyzer)
    else:
        # Interactive mode
        print(f"{Colors.BOLD}Interactive Mode{Colors.RESET}")
        print("Enter the path to an email file (.txt or .eml) to analyze")
        print(f"Type 'quit' to exit\n")
        
        while True:
            filepath = input(f"{Colors.BLUE}Enter file path: {Colors.RESET}").strip()
            
            if filepath.lower() in ['quit', 'exit', 'q']:
                print(f"\n{Colors.GREEN}Thank you for using Phishing Email Analyzer!{Colors.RESET}\n")
                break
            
            if filepath:
                analyze_email(filepath, analyzer)
                print(f"\n{'-'*70}\n")


if __name__ == "__main__":
    main()
