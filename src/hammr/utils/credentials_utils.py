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
        self.userpassAuthentication = False
        self.apikeysAuthentication = False
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
    def userpassAuthentication(self):
        """Get the current userpassAuthentication"""
        return self.userpassAuthentication

    @property
    def apikeysAuthentication(self):
        """Get the current apikeysAuthentication"""
        return self.apikeysAuthentication

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


    def fill_credentials_from_cmd_apiKey(self, mainArgs):
        self.check_url_presence_and_set_it(mainArgs.url)
        printer.out("Using url " + self.url, printer.INFO)
        self.username = mainArgs.user
        self.publicKey = mainArgs.publicKey
        self.secretKey = mainArgs.secretKey
        self.apikeysAuthentication = True
        printer.out("public and secret key provided, using the api key mode", printer.INFO)

    def check_url_presence_and_set_it(self, url):
        if url:
            self.url = url
        else:
            printer.out("url not found in commands nor in credentials file", printer.ERROR)
            exit(1)

    def fill_credentials_from_cmd_user_password(self, mainArgs):
        self.check_url_presence_and_set_it(mainArgs.url)
        printer.out("Using url " + self.url, printer.INFO)
        printer.out("no public and secret key provided, using the user+password mode", printer.INFO)
        self.username = mainArgs.user
        self.check_password_and_set_it(mainArgs.password)
        self.userpassAuthentication = True

    def check_password_and_set_it(self, pw):
        if not pw:
            self.password = getpass.getpass()
        else:
            self.password = pw

    def fill_credentials_from_credfile(self, mainArgs):
        self.credfile = "credentials.json"
        if mainArgs.credentials is not None:
            self.credfile = mainArgs.credentials
        printer.out("no username provided on command line, trying credentials file", printer.INFO)
        credpath = check_credfile(self.credfile)
        if credpath is None:
            printer.out("credentials file " + self.credfile + " not found\n", printer.ERROR)
            exit(1)
        printer.out("Using credentials file: " + credpath, printer.INFO)
        json_data = open(credpath)
        data = json.load(json_data)
        json_data.close()

        if mainArgs.url:
            self.url = mainArgs.url
        elif "url" in data:
            self.url = data["url"]
        else:
            printer.out("url not found in commands nor in credentials file", printer.ERROR)
            exit(1)
        printer.out("Using url " + self.url, printer.INFO)
        if "user" in data:
            self.username = data["user"]
        else:
            printer.out("username not found in credentials file", printer.ERROR)
            exit(1)
        if "publicKey" in data and "secretKey" in data:
            printer.out("public and secret key provided, using the api key mode", printer.INFO)
            self.publicKey = data["publicKey"]
            self.secretKey = data["secretKey"]
            self.apikeysAuthentication = True
        elif mainArgs.password:
            self.password = mainArgs.password
            self.userpassAuthentication = True
        elif "password" in data:
            self.password = data["password"]
            self.userpassAuthentication = True
        else:
            printer.out("no password or no public+secret api key found in credentials file", printer.ERROR)
            exit(1)
        if "acceptAutoSigned" in data:
            self.sslAutosigned = data["acceptAutoSigned"]


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