"""
Description:
-------------------------
This Module will handle all the modules with GreyNoise

Api Description:
-------------------------
'riot': Rule-it-Out- IP Belongs to business service such as (O365, cloudflare, etc)
'noise': Internet Background Noise - Directly observed by GreyN
"""

# *=============== IMPORT SECTION ======================
import requests

class Greynoise:
    """Wrapper for Greynoise"""

    @classmethod
    def lookup_IP(cls, IP_Address):
        """
        This Function will gather the IP Context Data from Greynoise

        Arguments:
            IP_Address: The target IP Address that is wanted to be gathered

        Returns:
            Will return a JSON of the Data
        """

        # Grey Noise Community API URL for IP Context
        Greynoise_IP_URL = f"https://api.greynoise.io/v3/community/{IP_Address}"

        try:
            Greynoise_Request = requests.get(
                Greynoise_IP_URL
            )
            return Greynoise_Request.json()

        except requests.RequestException as error:
            return f"Error: {error}"