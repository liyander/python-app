from flask import Flask
import unittest
from src.models.detector import Detector  # Assuming Detector is the class to be tested

class TestDetector(unittest.TestCase):

    def setUp(self):
        self.detector = Detector()

    def test_phishing_detection(self):
        # Example test case for phishing detection
        result = self.detector.detect("example phishing text")
        self.assertTrue(result)  # Adjust based on expected outcome

    def test_non_phishing_detection(self):
        # Example test case for non-phishing detection
        result = self.detector.detect("example safe text")
        self.assertFalse(result)  # Adjust based on expected outcome

if __name__ == '__main__':
    unittest.main()