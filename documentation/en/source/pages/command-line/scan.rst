.. Copyright (c) 2007-2016 UShareSoft, All rights reserved

.. _command-line-scan:

scan
====

Manages all the scans executed on live systems. The usage is:

.. code-block:: shell

	usage: hammr scan [sub-command] [options]


Sub Commands
------------

``build`` sub-command
~~~~~~~~~~~~~~~~~~~~~

Builds a machine image from a scan. The options are:

	* ``--id`` (mandatory): the ID of the scan to generate the machine image from
	* ``--file`` (mandatory): json or yaml file providing the builder parameters

``delete`` sub-command
~~~~~~~~~~~~~~~~~~~~~~

Deletes an existing scan. The options are:

	* ``--id`` (mandatory): the ID of the scan to delete

``import`` sub-command
~~~~~~~~~~~~~~~~~~~~~~

Imports (or transforms) the scan to a template.

	* ``--id`` (mandatory): the ID of the scan to import
	* ``--name`` (mandatory): the name to use for the template created from the scan
	* ``--version`` (mandatory): the version to use for the template created from the scan

``list`` sub-command
~~~~~~~~~~~~~~~~~~~~

Displays all the scans for the user.

``run`` sub-command
~~~~~~~~~~~~~~~~~~~

Executes a deep scan of a running system.

	* ``--ip`` (mandatory): the IP address or fully qualified hostname of the running system
	* ``--scan-login`` (mandatory): the root user name (normally root)
	* ``--name`` (mandatory): the scan name to use when creating the scan meta-data
	* ``--scan-password`` (optional): the root password to authenticate to the running system
	* ``--dir`` (optional): the directory where to install the uforge-scan.bin binary used to execute the deep scan
	* ``--exclude`` (optional): a list of directories or files to exclude during the deep scan
