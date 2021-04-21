"""
Description:
----------------------------------------------------------------
This module will handle all methods with Virus Total API
"""

# *=====================================================================
# * Import Section
# *=====================================================================
import requests
import json
import pandas as pd
from pandas import json_normalize


# *=====================================================================
# * Classes Section
# *=====================================================================

# ----------------------------------------------------------------------
# VirusTotalReporting Class Description and Versioning:
#
# This class was built to help initialize a reporting structure of the
# Data that is returned via VirusTotal API by gathering the column names
# that are wanted to and then proceed to create cleaner reports
# *---------------------------------------------------------------------
# VirusTotal Reporting Class
class VirusTotalReporting:
    # This function will convert a dictionary to a JSON
    @classmethod
    def Convert_Dict_to_JSON(cls, dictionary):
        Target = json.dumps(dictionary)
        JsonObj = json.loads(Target)
        return JsonObj

    # *=================== FILE CLASSES ====================================
    # Parses the VirusTotal
    @classmethod
    def Parse_VT_File_Information(cls, JSON="") -> pd.DataFrame:
        """
        Args:
            JSON: The Provided JSON Object to parse and return as a Dataframe

        returns a Cleaner Dataframe
        """
        # Column List that is wanted
        VT_File_Columns = [
            'first_submission_date', 'last_analysis_date', 'sha256',
            'meaningful_name', 'names', 'times_submitted', 'malicious_detections',
            'magic', 'type_description'
        ]

        # Calculating How many Scans resulted in Malicious
        JSON['malicious_detections'] = JSON['last_analysis_stats']['malicious']
        # Creates a Dictionary by parsing via the VT_File_Columns list
        Parsed_Dict = {key: JSON[key] for key in VT_File_Columns}
        # Uses the class function from above to create it into a JSON
        VT_Json = cls.Convert_Dict_to_JSON(Parsed_Dict)
        # This will flatten the Json into a Dataframe
        Dataframe = json_normalize(VT_Json)
        # Converts  the _Date columns into a an actual Time stamp due to the UTC formatting
        Dataframe['first_submission_date'] = pd.to_datetime(Dataframe['first_submission_date'], unit='s', utc=True)
        Dataframe['last_analysis_date'] = pd.to_datetime(Dataframe['last_analysis_date'], unit='s', utc=True)
        # Returns the Dataframe
        return Dataframe

    # This function will handle the parsing of the information of the VirusTotal File Relationships
    @classmethod
    def Parse_VT_File_Relationships(cls, JSON='') -> pd.DataFrame:
        """
        Args:
            JSON: The Json that will be parsed

        Returns:
            Will return a pd.Dataframe
        """
        # Builds the Dictionary for reference to the Columns specified by the type of relationship
        VT_File_Relationship_Columns_Dictionary = {
            'file_behaviour': ['command_executions', 'processes_created', 'processes_tree','registry_keys_set', 'modules_loaded'],
        }

        if JSON['meta']['count'] == 0:
            return "No Data available for this relationship"
        elif JSON['meta']['count'] == 1:
            # Capture the Relationship type in the Data to specify via the Dictionary
            RelationshipType = JSON['data'][0]['type']

            # will begin the Data to convert to
            if RelationshipType in VT_File_Relationship_Columns_Dictionary:
                TargetColumnList = VT_File_Relationship_Columns_Dictionary[RelationshipType]

                Parsed_Relationship_Dictionary = {key: JSON['data'][0]['attributes'][key] for key in TargetColumnList}
                # Converts the Dictionary into a JSON
                VT_Relationship_Json = cls.Convert_Dict_to_JSON(Parsed_Relationship_Dictionary)
                Dataframe = json_normalize(VT_Relationship_Json)
                return Dataframe
        else:
            print("Nothing")

# The Class for Virus Total
class VirusTotal:
    """Wrapper for the VirusTotal"""
    # Initializes the object for Virus Total API key
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
                # Takes the Class object of File Informatio parsing and then applies it to the Data
                return VirusTotalReporting.Parse_VT_File_Information(VT_Request.json()['data']['attributes'])
            else:
                if VT_Request.status_code == 404:
                    return f"Error: {VT_Request.status_code}: The Requested Resource is not found. Please try again"
                elif VT_Request.status_code == 401:
                    return f"Error: {VT_Request.status_code}: User not authenticated. Check if API Key is provided or Incorrect API Key is used"
                elif VT_Request.status_code == 403:
                    return f"Error: {VT_Request.status_code}: Not allowed to perform the requested operation"
        
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
                    return VirusTotalReporting.Parse_VT_File_Relationships(VT_File_Relationship_Data)
                else:
                    if VT_File_Request.status_code == 404:
                        return f"Error: {VT_File_Request.status_code}: The Requested Resource is not found. Please try again"
                    elif VT_File_Request.status_code == 401:
                        return f"Error: {VT_File_Request.status_code}: User not authenticated. Check if API Key is provided or Incorrect API Key is used"
                    elif VT_File_Request.status_code == 403:
                        return f"Error: {VT_File_Request.status_code}: Not allowed to perform the requested operation"

            except requests.RequestException as error:
                return f"Error: {error}"





