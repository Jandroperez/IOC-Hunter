"""
Description:
----------------------------------------------------------------
This will handle all the Functions and methods needed to communicate with
the ThreatFox API.
"""

# *================================================================
# * Import Section
# *================================================================

import requests
import json
import pandas as pd
from pandas import json_normalize

# *================================================================
# * Classes Section
# *================================================================

# ThreatFox Class
class ThreatFox:
    """ 
    Wrapper for the ThreatFox API
    """ 

    def __init__(self, APIKey: str):
        self.APIKey = APIKey

    # Function to Query the IOC Database
    @classmethod
    def query_ioc_database(cls, number_of_days=90) -> json:
        """
        Args:
            number_of_days: The number of days of Historical Data (Default: 90, min: 1, Max: 90)

        Returns:
            Will return the Data from ThreatFox in a JSON Format
        """

        # Building the Arguments needed to make the Query Work
        args = {
            "query": "get_iocs",
            "days": number_of_days
        }

        # Will handle the Request to Threat Fox
        try:
            ThreatFox_Request = requests.post(
                "https://threatfox-api.abuse.ch/api/v1",
                json=args
            )

            if ThreatFox_Request.ok:
                ThreatFox_Data = ThreatFox_Request.json()['data']
                return ThreatFox_Data

        except requests.RequestException as error:
            return f"Error: {error}"


