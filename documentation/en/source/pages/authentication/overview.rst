.. Copyright (c) 2007-2016 UShareSoft, All rights reserved

.. _authentication-methods:

Authentication
==============

Communication between hammr and the UForge server is done via HTTPS. To send requests to the UForge server, you can use one of the following methods:

* Authentication by password
* API keys

Authentication by Password
--------------------------

For authentication by password, hammr needs the following information:

* UForge Server URL endpoint
* Your account user name
* Your password

This information can be passed to hammr either from command-line options or from a file.

Command-line Parameters
~~~~~~~~~~~~~~~~~~~~~~~

Authentication information can be passed to hammr via command-line options.  These options are:

* ``-a`` or ``--url``: the UForge Server URL endpoint.  If the URL uses HTTPS, then the connection will be done securely (recommended), otherwise connection will be done via HTTP
* ``-u`` or ``--user``: the user name to use for authentication
* ``-p`` or ``--password``: the password to use for authentication

For example

.. code-block:: shell

	$ hammr os list --url https://uforge.usharesoft.com/api -u username -p password

These parameters need to be passed each time you want to use the command-line.

Authentication using API Keys
-----------------------------

For authentication using API key, hammr needs the following information:

* UForge Server URL endpoint
* Your account user name
* Your public key and secret key (from UForge)

This information can be passed to hammr either from command-line options or from a file.

Command-line Parameters
~~~~~~~~~~~~~~~~~~~~~~~

Authentication information can be passed to hammr via command-line options.  These options are:

* ``-a`` or ``--url``: the UForge Server URL endpoint.  If the URL uses HTTPS, then the connection will be done securely (recommended), otherwise connection will be done via HTTP
* ``-u`` or ``--user``: the user name to use for authentication
* ``-k`` or ``--publicKey``: the public key to authenticate to the UForge server
* ``-s`` or ``--secretKey``: the secret key to authenticate to the UForge server

For example

.. code-block:: shell

      $ hammr os list --url https://uforge.usharesoft.com/api -u username -k wbG7rl402wgTrSd_Enga9HpnxE-PQxtxeMnruyoUIqduaQ9UFmYxfI1l0gf05cgoWfZAd6V_aOyQAlUnYQ -s P7LFcJKFm9mrchZQfPo2DX7ECeVO-Tlen0nU7qf2YR0HOuwO9ZjQJJbQV7Nr7pyfrq-iUrlNinwiBpAth7

These parameters need to be passed each time you want to use the command-line.


Using a Credential File
=======================

Rather than passing the authentication information as part of the command-line, you can instead store this information in a credential file (``credentials.json``) that will be used every time hammr is launched.  Hammr searches for this file in a sub-directory named ``.hammr`` located in the home directory of the user launching hammr.

To use a credential file, go to the ``.hammr`` sub-directory and create the file ``credentials.json``.

.. code-block:: shell

	$ cd ~/.hammr
	$ vi credentials.json

For authentication using password, add the authentication and UForge URL endpoint to this file using the following format:

.. code-block:: json

	{
	  "user" : "root",
	  "password" : "password",
	  "url" : "https://uforge.usharesoft.com/api"
	}

For authentication using API keys, add the authentication and UForge URL endpoint to this file using the following format:

.. code-block:: json

      {
        "user" : "root",
        "publicKey" : "P7LFcJKFm9mrchZQfPo2DX7ECeVO-Tlen0nU7qf2YR0HOuwO9ZjQJJbQV7Nr7pyfrq-iUrlNinwiBpAth7",
        "secretKey" : "wbG7rl402wgTrSd_Enga9HpnxE-PQxtxeMnruyoUIqduaQ9UFmYxfI1l0gf05cgoWfZAd6V_aOyQAlUnYQ",
        "url" : "https://uforge.usharesoft.com/api"
      }

As this file contains security information, it is recommended to change the permissions on this file so that only you can read or write to it:

.. code-block:: shell

	$ chmod 600 credentials.json

Now every time hammr is launched, you no longer need to provide the authentication information as part of the command-line.  Hammr will automatically use the information contained in this file.
