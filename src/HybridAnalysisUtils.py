"""
Description:
-------------------------------
This Script will handle all methods and Functions
needed to Communicate with Hybrid Analysis
"""

# *===========================================
# * Import Section
# *===========================================

import requests
import pandas as pd

# *===========================================
# * Classes Section
# *===========================================

class HybridAnalysis:
    """
    Wrapper for the Hybrid Analysis Modules
    """

    # Initialization to the Variables within the Module
    def __init__(self,
        Headers: dict):
        self.Headers = Headers

    # Function to reach out to the Live Feed
    def get_live_feed(self):
        """
        Description:
            Will get a Live Feed of the Most Recent Malware
        """
        # The Live Feed URL 
        Live_Feed_URL = "https://www.hybrid-analysis.com/api/v2/feed/latest"
