.. Copyright (c) 2007-2016 UShareSoft, All rights reserved

.. _command-line-image:

image
=====

Manages all of the machine images you have built and/or published. The usage is:

.. code-block:: shell

	usage: hammr image [sub-command] [options]


Sub Commands
------------

``cancel`` sub-command
~~~~~~~~~~~~~~~~~~~~~~

Cancels a machine image build or publish. The options are:

	* ``--id`` (mandatory): the ID of the machine image to cancel

``delete`` sub-command
~~~~~~~~~~~~~~~~~~~~~~

Deletes a machine image or publish information. The options are:

	* ``--id`` (mandatory): the ID of the machine image to delete

``download`` sub-command
~~~~~~~~~~~~~~~~~~~~~~~~

Downloads a machine image to the local filesystem. The options are:

	* ``--id`` (mandatory): the ID of the machine image to delete
	* ``--file`` (mandatory): the pathname where to store the machine image

``list`` sub-command
~~~~~~~~~~~~~~~~~~~~

Displays all the machine images built and publish information of those machine images to their respective target platforms.

``publish`` sub-command
~~~~~~~~~~~~~~~~~~~~~~~

Publish (upload and register) a built machine image to a target environment. The options are:

	* ``--file`` (mandatory): json file providing the cloud account parameters required for upload and registration