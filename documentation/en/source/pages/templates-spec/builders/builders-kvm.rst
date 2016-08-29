.. Copyright (c) 2007-2016 UShareSoft, All rights reserved

.. _builder-kvm:

KVM
===

Default builder type: ``KVM``

Require Cloud Account: No

This builder type is the default name provided by UForge AppCenter.

.. note:: This builder type name can be changed by your UForge administrator. To get the available builder types, please refer to :ref:`command-line-format`

The KVM builder provides information for building KVM (Kernel-based Virtual Machine) compatible machine images.
The KVM builder section has the following definition, when using YAML. You can also use JSON.

.. code-block:: javascript

	---
	builders:
	- type: KVM

Building a Machine Image
------------------------

For building an image, the valid keys are:

* ``type`` (mandatory): a string providing the machine image type to build. Default builder type for KVM: ``KVM``. To get the available builder type, please refer to :ref:`command-line-format`
* ``hardwareSettings`` (mandatory): an object providing hardware settings to be used for the machine image. The following valid keys for hardware settings are:
	* ``memory`` (mandatory): an integer providing the amount of RAM to provide to an instance provisioned from the machine image (in MB).
* installation (optional): an object providing low-level installation or first boot options. These override any installation options in the :ref:`template-stack` section. The following valid keys for installation are:
	* ``diskSize`` (mandatory): an integer providing the disk size of the machine image to create. Note, this overrides any disk size information in the stack. This cannot be used if an advanced partitioning table is defined in the stack.

Example
-------

The following example shows a YAML KVM builder. 

.. note:: You can also use JSON.

.. code-block:: yaml

	---
	builders:
	- type: KVM
	  hardwareSettings:
	    memory: 1024
