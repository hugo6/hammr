'''
    hammr
'''

try:
    from termcolor import colored
except ImportError:
    def colored(string, a=None, b=None, attrs=None):
        return string
try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

import argparse
import getpass
import os
import json
import sys
import pkg_resources

try:
	pkg_resources.require("uforge_python_sdk>=3.5.1.2")
except Exception as e:
	print e
	exit(10)

from lib.cmdHamr import Cmd, CmdUtils
from lib.argumentParser import HammrArgumentParser, ArgumentParser, ArgumentParserError
import commands as cmds

from uforge.application import Api
from utils import printer
from utils import generics_utils
from utils import constants
import httplib2

__author__ = "UShareSoft"
__license__ = "Apache License 2.0"

class CmdBuilder(object):
    @staticmethod
    def generateCommands(class_):
        # Create subCmds if not exist
        if not hasattr(class_, 'subCmds'):
            class_.subCmds = {} 
        # Add commands                
        user = cmds.user.User()
        class_.subCmds[user.cmd_name] = user
        template = cmds.template.Template()
        class_.subCmds[template.cmd_name] = template
        _os = cmds.os.Os()
        class_.subCmds[_os.cmd_name] = _os
        format = cmds.format.Format()
        class_.subCmds[format.cmd_name] = format
        image = cmds.image.Image()
        class_.subCmds[image.cmd_name] = image
        account = cmds.account.Account()
        class_.subCmds[account.cmd_name] = account                
        bundle = cmds.bundle.Bundle()
        class_.subCmds[bundle.cmd_name] = bundle
        scan = cmds.scan.Scan()
        class_.subCmds[scan.cmd_name] = scan
        quota = cmds.quota.Quota()
        class_.subCmds[quota.cmd_name] = quota

## Main cmd
class Hammr(Cmd):
#    subCmds = {
#        'tools': CmdUtils
#    }
    def __init__(self):
        super(Hammr, self).__init__()
        self.prompt = 'hammr> '

    def do_exit(self, args):
            return True

    def do_quit(self, args):
            return True

    def arg_batch(self):
            doParser = ArgumentParser("batch", add_help = True, description="Execute hammr batch command from a file (for scripting)")
            mandatory = doParser.add_argument_group("mandatory arguments")
            mandatory.add_argument('--file', dest='file', required=True, help="hammr batch file commands")
            return doParser      

    def do_batch(self, args):
        try:
            doParser = self.arg_batch()
            try:
                doArgs = doParser.parse_args(args.split())
            except SystemExit as e:
                return
            with open(doArgs.file) as f:             
                for line in f:
                    try:
                        self.run_commands_at_invocation([line])
                    except:
                        printer.out("bad command '"+line+"'", printer.ERROR)
                    print "\n"
        except IOError as e:
            printer.out("File error: "+str(e), printer.ERROR)
            return
        except ArgumentParserError as e:
            printer.out("In Arguments: "+str(e), printer.ERROR)
            self.help_batch()

    def help_batch(self):
        doParser = self.arg_batch()
        doParser.print_help()

    def cmdloop(self, args):
        if len(args):
            code = self.run_commands_at_invocation([str.join(' ', args)])
            sys.exit(code)
        else:
            self._cmdloop() 

def generate_base_doc(app, hamm_help):
    myactions=[]
    cmds= sorted(app.subCmds)
    for cmd in cmds:
        myactions.append(argparse._StoreAction(
         option_strings=[],
         dest=str(cmd),
         nargs=None,
         const=None,
         default=None,
         type=str,
         choices=None,
         required=False,
         help=str(app.subCmds[cmd].__doc__),
         metavar=None))
    return myactions
    
def set_globals_cmds(subCmds):
    for cmd in subCmds:
        if hasattr(subCmds[cmd], 'set_globals'):
            subCmds[cmd].set_globals(api, login, password)
            if hasattr(subCmds[cmd], 'subCmds'):
                set_globals_cmds(subCmds[cmd].subCmds)

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

#Generate hammr base command + help base command
CmdBuilder.generateCommands(Hammr)
app = Hammr()
myactions=generate_base_doc(app, hamm_help="")

# Args parsing
mainParser = HammrArgumentParser(add_help=False)
HammrArgumentParser.hammr_actions=myactions
mainParser.add_argument('-a', '--url', dest='url', type=str, help='the UForge server URL endpoint to use', required = False)
mainParser.add_argument('-u', '--user', dest='user', type=str, help='the user name used to authenticate to the UForge server', required = False)
mainParser.add_argument('-p', '--password', dest='password', type=str, help='the password used to authenticate to the UForge server', required = False)
mainParser.add_argument('-k', '--publicKey', dest='publicKey', type=str, help='the public key to authenticate to the Uforge server', required = False)
mainParser.add_argument('-s', '--secretKey', dest='secretKey', type=str, help='the secret key to authenticate to the Uforge server', required = False)
mainParser.add_argument('-c', '--credentials', dest='credentials', type=str, help='the credential file used to authenticate to the UForge server (default to ~/.hammr/credentials.json)', required = False)
mainParser.add_argument('-v', action='version', help='displays the current version of the hammr tool', version="%(prog)s version '"+constants.VERSION+"'")
mainParser.add_argument('-h', '--help', dest='help', action='store_true', help='show this help message and exit', required = False)
mainParser.set_defaults(help=False)
mainParser.add_argument('cmds', nargs='*', help='Hammr cmds')
mainArgs, unknown = mainParser.parse_known_args()

if mainArgs.help and not mainArgs.cmds:
    mainParser.print_help()
    exit(0)

userpassAuthentication = False
apikeysAuthentication = False
sslAutosigned=True
password = None

if mainArgs.user is not None and mainArgs.publicKey is not None and mainArgs.secretKey is not None:
    #using API key cmd lines
    if mainArgs.url:
        url=mainArgs.url
    else:
        printer.out("url not found in commands nor in credentials file", printer.ERROR, 1)
        exit(1)
    printer.out("Using url " + url, printer.INFO)
    username=mainArgs.user
    publicKey = mainArgs.publicKey
    secretKey = mainArgs.secretKey
    apikeysAuthentication = True
    printer.out("public and secret key provided, using the api key mode", printer.INFO)
elif mainArgs.user is not None:
    #using userpass in cmd lines
    if mainArgs.url:
        url=mainArgs.url
    else:
        printer.out("url not found in commands nor in credentials file", printer.ERROR, 1)
        exit(1)
    printer.out("Using url " + url, printer.INFO)
    printer.out("no public and secret key provided, using the user+password mode", printer.INFO)
    username=mainArgs.user
    if not mainArgs.password:
        password = getpass.getpass()
    else:
        password=mainArgs.password
    userpassAuthentication=True
else:
    credfile="credentials.json"
    if mainArgs.credentials is not None:
        credfile=mainArgs.credentials
    printer.out("no username provided on command line, trying credentials file", printer.INFO)
    credpath=check_credfile(credfile)
    if credpath is None:
        printer.out("credentials file " + credfile + " not found\n", printer.ERROR)
        exit(1)
    printer.out("Using credentials file: " + credpath, printer.INFO)
    try:
        json_data=open(credpath)
        data = json.load(json_data)
        json_data.close()

        if mainArgs.url:
            url=mainArgs.url
        elif "url" in data:
            url=data["url"]
        else:
            printer.out("url not found in commands nor in credentials file", printer.ERROR, 1)
            exit(1)
        printer.out("Using url " + url, printer.INFO)

        if"user" in data:
            username=data["user"]
        else:
            printer.out("username not found in credentials file", printer.ERROR, 1)
            exit(1)
        if "publicKey" in data and "secretKey" in data:
            printer.out("public and secret key provided, using the api key mode", printer.INFO)
            publicKey=data["publicKey"]
            secretKey=data["secretKey"]
            apikeysAuthentication = True
        elif mainArgs.password:
            password=mainArgs.password
            userpassAuthentication = True
        elif "password" in data:
            password=data["password"]
            userpassAuthentication = True
        else:
            printer.out("no password or no public+secret api key found in credentials file", printer.ERROR, 1)
            exit(1)

        if "acceptAutoSigned" in data:
            sslAutosigned=data["acceptAutoSigned"]
    except ValueError as e:
        printer.out("JSON parsing error in credentials file: "+str(e), printer.ERROR, 1)
    except IOError as e:
        printer.out("File error in credentials file: "+str(e), printer.ERROR, 1)

apikeys = {}
if apikeysAuthentication is True:
    apikeys['publickey'] = publicKey
    apikeys['secretkey'] = secretKey

#UForge API instantiation
api = Api(url, username = username, password = password, headers = None, disable_ssl_certificate_validation = sslAutosigned, timeout = constants.HTTP_TIMEOUT, apikeys = apikeys)
if generics_utils.is_superviser_mode(username):
    login = generics_utils.get_target_username(username)
else:
    login = username
set_globals_cmds(app.subCmds)

if mainArgs.help and len(mainArgs.cmds)>=1:
    argList=mainArgs.cmds + unknown;
    argList.insert(len(mainArgs.cmds)-1, "help")
    app.cmdloop(argList)
elif mainArgs.help:
    app.cmdloop(mainArgs.cmds + unknown + ["-h"])
else:
    app.cmdloop(mainArgs.cmds + unknown)
