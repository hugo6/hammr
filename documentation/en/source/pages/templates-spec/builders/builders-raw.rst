.. Copyright (c) 2007-2016 UShareSoft, All rights reserved

.. _builder-raw:

Raw
===

Default builder type: ``Raw Virtual Disk``
Require Cloud Account: No

The Raw builder provides information for building a Raw Virtual Disk compatible machine images.
This builder type is the default name provided by UForge AppCenter.

.. note:: This builder type name can be changed by your UForge administrator. To get the available builder types, please refer to :ref:`command-line-format`

The Raw builder section has the following definition when using YAML:

.. code-block:: yaml

	---
	builders:
	- type: Raw Virtual Disk
		# the rest of the definition goes here.

If you are using JSON:

.. code-block:: javascript

	{
	  "builders": [
		{
		  "type": "Raw Virtual Disk",
		  ...the rest of the definition goes here.
		}
	  ]
	}

Building a Machine Image
------------------------

For building an image, the valid keys are:

* ``type`` (mandatory): a string providing the machine image type to build. Default builder type for RAW: ``Raw Virtual Disk``. To get the available builder type, please refer to :ref:`command-line-format`
* ``installation`` (optional): an object providing low-level installation or first boot options. These override any installation options in the :ref:`template-stack` section. The following valid keys for installation are:
	* ``diskSize`` (mandatory): an integer providing the disk size of the machine image to create. Note, this overrides any disk size information in the stack. This cannot be used if an advanced partitioning table is defined in the stack.

Example
-------


The following examples shows a Raw builder.

If you are using YAML:

.. code-block:: yaml

	---
	builders:
	- type: Raw Virtual Disk
	  hardwareSettings:
	    memory: 1024

If you are using JSON:

.. code-block:: json

	{
	  "builders": [
		{
		  "type": "Raw Virtual Disk",
		  "hardwareSettings": {
			"memory": 1024
		  }
		}
	  ]
	}