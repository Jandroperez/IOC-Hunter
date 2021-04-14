"""
Description:
----------------------------------------------------------------
This module will handle all methods with Virus Total
"""

# *================================================================
# * Import Section
# *================================================================

import requests
import json
import pandas as pd
from pandas.io.json import json_normalize


# *================================================================
# * Classes Section
# *================================================================


# The Class for Virus Total
class VirusTotal:
    """Wrapper for the VirusTotal"""

    def __init__(self, ApiKey: str):
        self.ApiKey = ApiKey

    # Function to gather information on a File
    def get_file_information(self, FileHash=''):
        """
        Args:
            FileHash: The target Hash that will draw report from

        Returns:
            Will return a JSON of the Information from the report
        """

        # The try loop 
        try:
            VT_File_Report_URL = f"https://www.virustotal.com/api/v3/files/{FileHash}"

            VT_Request = requests.get(
                VT_File_Report_URL,
                headers={
                    'x-apikey': self.ApiKey
                }
            )
            
            # Checks if the request is ok
            if VT_Request.ok:
                return VT_Request.json()['data']['attributes']
            else:
                return f"Error: {VT_Request.status_code}: {VT_Request.content}"
        
        except requests.RequestException as error:
            return f"Error: {error}"

    # Functions to handle all the Methods
    def get_file_relationships(self, FileHash='', Relationship='') -> json:
        """
        Args:
            FileHash: The Target Hash that is wanted to be found within VirusTotal
            Relationship: The Relationship that is wanted for the VirusTotal

        Returns:
            will return the JSON of the data that is requested
        """

        # Instantiating the File Relationships
        File_Relationships = [
            'behaviours',
            'bundled_files',
            'clues',
            'comments',
            'compressed_parents',
            'contacted_domains',
            'contacted_ips',
            'contacted_urls',
            'dropped_files',
            'execution_parents',
            'graphs'
        ]

        # Runs the check to ensure that the Relationship is within the Parameters
        if Relationship in File_Relationships:
            # Instantiating the File Relationship URL
            VT_File_Relationship_URL = f"https://www.virustotal.com/api/v3/files/{FileHash}/{Relationship}"

            try:
                VT_File_Request = requests.get(
                    VT_File_Relationship_URL,
                    headers= {
                        'x-apikey': self.ApiKey
                    }
                )
                # Checking if the Request made it through okay
                if VT_File_Request.ok:
                    VT_File_Relationship_Data = VT_File_Request.json()
                    return VT_File_Relationship_Data
                else:
                    return "Error: Something went wrong, check payload"

            except requests.RequestException as error:
                return f"Error: {error}"





