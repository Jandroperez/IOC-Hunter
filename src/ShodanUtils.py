"""
Description:
------------------------------------
This Module will hold all the Methods and classes
needed to work with Shodan
"""

# *================================
# * Import Section
# *================================

import requests
import json
import pandas as pd
from pandas import json_normalize
import ipaddress

# *================================
# * Classes Section
# *================================

class Shodan:
    """
    Wrapper for Interacting with the Shodan API
    """

    def __init__(self, ApiKey: str):
        self.ApiKey = ApiKey

    def Parse_DNS_Records(self, JSONData='') -> pd.DataFrame:
        """
        :param JSONData: The JSON Data that will be parsed
        :return: Will return a Dataframe
        """

        # Building the Configuration of the Dataframe
        DataframeConfig = []
        # Iterating over the JSON Payload that is fed to the function
        for key, value in JSONData.items():
            Object = {}
            if value is None or key is None:
                pass
            else:
                Object['IP Address'] = key
                Object['Hostname'] = value[0]
            # Append the JSON Row
            DataframeConfig.append(Object)

        # Converts the New JSON into a Dataframe
        Dataframe = json_normalize(DataframeConfig)

        # Drops any Null Values so no Noise shows in the Scan.
        Dataframe = Dataframe.dropna()

        # Returns Dataframe
        return Dataframe

    # Function to search for specified target
    def search_shodan(self, query, facets='') -> json:
        """
        Description:
            This Method will search for any term or target within the Shodan Database

        Args:
            query: The Target Query that will be used for the search

        Returns:
            Will return a JSON of the data that is found
        """

        # Shodan Search URL
        ShodanSearchURL = f'https://api.shodan.io/shodan/host/search?key={self.ApiKey}&query={query}&facets={facets}'

        # The Handler for the Request to send out
        try:
            Shodan_Request = requests.get(
                ShodanSearchURL
            )

            if Shodan_Request.ok:
                Shodan_Data = Shodan_Request.json()
                if Shodan_Data['total'] == 0:
                    return "No Data Found..."
                else:
                    return Shodan_Data
            else:
                return "Error: Something went wrong"
        except requests.RequestException as error:
            return f"Error: {error}"

    # DNS Network Resolver
    def Reverse_DNS_Network_Resolver(self,  Target_IPV4_Network='')-> pd.DataFrame:
        """
        Args:
            Target_IPV4_Network: The Provided IPv4 Network Suffix

        Returns: a Dataframe of all the records found
        """

        # Building the Network Object and converting into a comma seperated list
        Target_Network = ipaddress.IPv4Network(Target_IPV4_Network)
        # Using list Comprehension
        Target_Network_Conversion = [str(addr) for addr in Target_Network]
        # Crreates the String
        Target_Network_List = ",".join(Target_Network_Conversion)

        # Reverse DNS Network URL
        Reverse_DNS_Network_URL = f"https://api.shodan.io/dns/reverse?ips={Target_Network_List}&key={self.ApiKey}"

        # Will handle the Request
        try:
            # Sending out the Request to Shodan
            Reverse_DNS_Network_Request = requests.get(
                Reverse_DNS_Network_URL
            )
            # If the Request Success code is 200, and OK, Proceed
            if Reverse_DNS_Network_Request.ok:
                Reverse_DNS_Network_Data = Reverse_DNS_Network_Request.json()
                # Will parse the DNS Records into a Dataframe
                return self.Parse_DNS_Records(Reverse_DNS_Network_Data)

        except requests.RequestException as error:
            return f"Error: {error}"
