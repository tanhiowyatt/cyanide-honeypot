
import re
from typing import List

class SecurityRuleEngine:
    """
    Component 1: Security Rule Engine
    Detects known attack patterns via regex with confidence scoring.
    """
    
    def __init__(self):
        # Format: (Regex Pattern, Severity, Description, TechniqueID, Confidence)
        # Severity: LOW=1, MEDIUM=2, HIGH=3, CRITICAL=4
        # Confidence: 0.0-1.0 (Probability of malicious intent)
        self.rules = self._load_rules()
        self.compiled_rules = self._compile_rules()

    def _load_rules(self) -> List[dict]:
        return [
            # --- Privilege Escalation (T1548) ---
            {
                'category': 'privesc',
                'pattern': r'\bsudo\s+su\b',
                'severity': 'HIGH',
                'description': 'Sudo su execution',
                'technique': 'T1548.003',
                'confidence': 1.0
            },
            {
                'category': 'privesc',
                'pattern': r'\bsudo\s+-i\b',
                'severity': 'HIGH',
                'description': 'Sudo interactive execution',
                'technique': 'T1548.003',
                'confidence': 1.0
            },
             {
                'category': 'privesc',
                'pattern': r'chmod\s+.*[+]s',
                'severity': 'HIGH',
                'description': 'SetUID bit setting',
                'technique': 'T1548.001',
                'confidence': 0.9
            },
            
            # --- Credential Access (T1003, T1552) ---
            {
                'category': 'cred_access',
                'pattern': r'/etc/shadow',
                'severity': 'CRITICAL',
                'description': 'Shadow file access',
                'technique': 'T1003.008',
                'confidence': 1.0
            },
            {
                'category': 'cred_access',
                'pattern': r'cat\s+.*\.ssh/id_rsa',
                'severity': 'CRITICAL',
                'description': 'SSH private key access',
                'technique': 'T1552.004',
                'confidence': 1.0
            },
             {
                'category': 'cred_access',
                'pattern': r'grep\s+password',
                'severity': 'HIGH',
                'description': 'Searching for passwords',
                'technique': 'T1552.001',
                'confidence': 0.8
            },

            # --- Persistence (T1546, T1053) ---
            {
                'category': 'persistence',
                'pattern': r'echo\s+.*\s+>>\s+\.bashrc',
                'severity': 'HIGH',
                'description': 'Shell config modification (.bashrc)',
                'technique': 'T1546.004',
                'confidence': 0.95
            },
            {
                'category': 'persistence',
                'pattern': r'crontab\s+-e',
                'severity': 'HIGH',
                'description': 'Crontab editing',
                'technique': 'T1053.003',
                'confidence': 0.9
            },

            # --- Reconnaissance (T1082, T1087) ---
            {
                'category': 'recon',
                'pattern': r'\buname\s+-a',
                'severity': 'LOW',
                'description': 'System information discovery',
                'technique': 'T1082',
                'confidence': 0.7
            },
            {
                'category': 'recon',
                'pattern': r'cat\s+/etc/passwd',
                'severity': 'MEDIUM',
                'description': 'Account discovery',
                'technique': 'T1087.001',
                'confidence': 0.8
            },
            {
                'category': 'recon',
                'pattern': r'\bid\b',
                'severity': 'LOW',
                'description': 'User discovery',
                'technique': 'T1033',
                'confidence': 0.6
            },
             {
                'category': 'recon',
                'pattern': r'\bwhoami\b',
                'severity': 'LOW',
                'description': 'User discovery',
                'technique': 'T1033',
                'confidence': 0.6
            },

            # --- Defense Evasion (T1070) ---
            {
                'category': 'defense_evasion',
                'pattern': r'rm\s+/var/log',
                'severity': 'MEDIUM',
                'description': 'Log deletion',
                'technique': 'T1070.002',
                'confidence': 0.9
            },
            {
                'category': 'defense_evasion',
                'pattern': r'history\s+-c',
                'severity': 'MEDIUM',
                'description': 'History clearing',
                'technique': 'T1070.003',
                'confidence': 0.9
            },
            
             # --- Network/Download (T1105) ---
            {
                'category': 'command_c2',
                'pattern': r'\bwget\b',
                'severity': 'MEDIUM',
                'description': 'File download (wget)',
                'technique': 'T1105',
                'confidence': 0.95
            },
            {
                'category': 'command_c2',
                'pattern': r'\bcurl\b',
                'severity': 'MEDIUM',
                'description': 'File download (curl)',
                'technique': 'T1105',
                'confidence': 0.95
            },
            {
                'category': 'command_c2',
                'pattern': r'\bnc\b',
                'severity': 'HIGH',
                'description': 'Netcat usage',
                'technique': 'T1059',
                'confidence': 0.95
            },
            # --- Additional Coverage (Gaps from Testing) ---
            {
                'category': 'privesc',
                'pattern': r'\bsudo\s+-s\b',
                'severity': 'HIGH',
                'description': 'Sudo shell execution',
                'technique': 'T1548.003',
                'confidence': 1.0
            },
            {
                'category': 'privesc',
                'pattern': r'chmod\s+.*4[0-7]{3}',
                'severity': 'HIGH',
                'description': 'SetUID bit setting (numeric)',
                'technique': 'T1548.001',
                'confidence': 0.9
            },
            {
                'category': 'recon',
                'pattern': r'\bnetstat\b',
                'severity': 'LOW',
                'description': 'Network connection discovery',
                'technique': 'T1049',
                'confidence': 0.7
            },
            {
                'category': 'recon',
                'pattern': r'\bss\s+',
                'severity': 'LOW',
                'description': 'Network connection discovery',
                'technique': 'T1049',
                'confidence': 0.7
            },
            {
                'category': 'execution',
                'pattern': r'(?:bash|sh|zsh|dash)\s+-i',
                'severity': 'HIGH',
                'description': 'Interactive shell',
                'technique': 'T1059.004',
                'confidence': 0.8
            }
        ]

    def _compile_rules(self):
        compiled = []
        for rule in self.rules:
            # We add a compiled regex object to the rule dict
            c_rule = rule.copy()
            c_rule['regex'] = re.compile(rule['pattern'], re.IGNORECASE)
            compiled.append(c_rule)
        return compiled

    def evaluate(self, command: str) -> dict:
        """
        Evaluates command against all rules.
        Returns result dict with highest confidence match.
        """
        matches = []
        pass

        for rule in self.compiled_rules:
            if rule['regex'].search(command):
                matches.append(rule)
        
        if not matches:
            return {'matched': False}
        
        # Sort matches by (Confidence DESC, Severity DESC)
        # Severity mapping
        sev_map = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        
        best_match = sorted(matches, key=lambda x: (x['confidence'], sev_map.get(x['severity'], 0)), reverse=True)[0]
        
        return {
            'matched': True,
            'rule_type': best_match['category'],
            'pattern': best_match['pattern'],
            'severity': best_match['severity'],
            'technique': best_match['technique'],
            'confidence': best_match['confidence'],
            'description': best_match['description'],
            'match_method': 'rule_based'
        }
