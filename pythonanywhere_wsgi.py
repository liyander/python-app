import sys
import os
path = '/home/yourusername/phishing-detector'
if path not in sys.path:
    sys.path.append(path)
from app import app as application
