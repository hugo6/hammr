__author__ = 'UshareSoft'
import os
import json
import getpass

from hammr.utils import printer, generics_utils

class Credential:
    '''
    This class get user credentials fron command line or config file
    It also check if the mandatory info are present
    '''
    def __init__(self):
        self.sslAutosigned = True
        self.password = None
        self.url = None
        self.username = None
        self.publicKey = None
        self.secretKey = None
        self.credfile = None

    @property
    def sslAutosigned(self):
        """Get the current sslAutosigned"""
        return self.sslAutosigned

    @property
    def password(self):
        """Get the current password"""
        return self.password

    @property
    def url(self):
        """Get the current url"""
        return self.url

    @property
    def username(self):
        """Get the current username"""
        return self.username

    @property
    def publicKey(self):
        """Get the current publicKey"""
        return self.publicKey

    @property
    def secretKey(self):
        """Get the current secretKey"""
        return self.secretKey

    @property
    def credfile(self):
        """Get the current credfile"""
        return self.credfile

    def isApiKey(self):
        if self.publicKey is not None and self.secretKey is not None:
            return True
        else:
            return False

    def fill_credentials_from_credfile(self):
        self.credfile = "credentials.json"
        printer.out("no username provided on command line, trying credentials file", printer.INFO)
        credpath = check_credfile(self.credfile)
        if credpath is None:
            raise CredentialException("credentials file " + self.credfile + " not found\n")
        printer.out("Using credentials file: " + credpath, printer.INFO)
        json_data = open(credpath)
        data = json.load(json_data)
        json_data.close()

        if "url" in data and self.url is None:
            self.url = data["url"]
        elif "url" not in data and self.url is None:
            raise CredentialException("url not found in commands nor in credentials file")
        printer.out("Using url " + self.url, printer.INFO)
        if "user" in data:
            self.username = data["user"]
        else:
            raise CredentialException("username not found in credentials file")
        if "publicKey" in data and "secretKey" in data:
            printer.out("public and secret key provided, using the api key mode", printer.INFO)
            self.publicKey = data["publicKey"]
            self.secretKey = data["secretKey"]
        elif "password" in data and self.password is None:
            self.password = data["password"]
        elif "publicKey" not in data and "secretKey" not in data and "password" not in data and self.password is None:
            raise CredentialException("no password or no public-secret api key found in credentials file")
        if "acceptAutoSigned" in data:
            self.sslAutosigned = data["acceptAutoSigned"]

    def check_url_presence(self):
            if self.url is None:
                raise CredentialException("url not found in commands nor in credentials file")

    def check_password_and_set_it(self):
        if self.password is None:
            self.password = getpass.getpass()

def check_credfile(credfile):
    if os.path.isfile(credfile):
        return credfile
    if not credfile.endswith(".json") and os.path.isfile(credfile + ".json"):
        return credfile + ".json"
    if os.path.isfile(generics_utils.get_hammr_dir()+os.sep+credfile):
        return generics_utils.get_hammr_dir()+os.sep+credfile
    if not credfile.endswith(".json") and os.path.isfile(generics_utils.get_hammr_dir()+os.sep+credfile+".json"):
        return generics_utils.get_hammr_dir()+os.sep+credfile+".json"
    return None

class CredentialException(Exception):
    def __init__(self,reason):
        self.reason = reason

    def __str__(self):
        return self.reason