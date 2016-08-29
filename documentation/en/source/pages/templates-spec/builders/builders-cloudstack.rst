.. Copyright (c) 2007-2016 UShareSoft, All rights reserved

.. _builder-cloudstack:

CloudStack
==========

Default builder type: ``CloudStack VMware (OVA)``, ``CloudStack KVM (QCOW2)`` or ``CloudStack Citrix Xen (VHD)``

Require Cloud Account: Yes

`cloudstack.apache.org <http://cloudstack.apache.org>`_

The CloudStack builder provides information for building and publishing the machine image to the CloudStack cloud platform. This builder supports KVM (``CloudStack KVM (QCOW2)``), Xen (``CloudStack Citrix Xen (VHD)``) or VMware (``CloudStack VMware (OVA)``) based images for CloudStack.
These builder types are the default names provided by UForge AppCenter.

.. note:: These builder type names can be changed by your UForge administrator. To get the available builder types, please refer to :ref:`command-line-format`


The CloudStack builder requires cloud account information to upload and register the machine image to the CloudStack platform.

The CloudStack builder section has the following definition, when using YAML. You can also use JSON.

.. code-block:: javascript

  ---
  builders:
  - type: CloudStack KVM (QCOW2)

Building a Machine Image
------------------------

For building an image, the valid keys are:

* ``type`` (mandatory): a string providing the machine image type to build. Default builder type for CloudStack: ``CloudStack VMware (OVA)``, ``CloudStack KVM (QCOW2)`` or ``CloudStack Citrix Xen (VHD)``. To get the available builder type, please refer to :ref:`command-line-format`
* ``hardwareSettings`` (mandatory): an object providing hardware settings to be used for the machine image. If an OVF machine image is being built, then the hardware settings are mandatory. The following valid keys for hardware settings are:
* ``memory`` (mandatory): an integer providing the amount of RAM to provide to an instance provisioned from the machine image (in MB).
* ``installation`` (optional): an object providing low-level installation or first boot options. These override any installation options in the :ref:`template-stack` section. The following valid keys for installation are:
* ``diskSize`` (mandatory): an integer providing the disk size of the machine image to create. Note, this overrides any disk size information in the stack. This cannot be used if an advanced partitioning table is defined in the stack.

Publishing a Machine Image
--------------------------

To publish an image, the valid keys are:

* ``type`` (mandatory): a string providing the machine image type to build. Default builder type for CloudStack: ``CloudStack VMware (OVA)``, ``CloudStack KVM (QCOW2)`` or ``CloudStack Citrix Xen (VHD)``. To get the available builder type, please refer to :ref:`command-line-format`
* ``account`` (mandatory): an object providing the CloudStack cloud account information required to publish the built machine image.
* ``imageName`` (mandatory): a string providing the displayed name of the machine image.
* ``zone`` (mandatory): a string providing the zone to publish the machine image
* ``publicImage`` (optional): a boolean flag to determine in the machine image is to be public
* ``featured`` (optional): a boolean flag to determine in the machine image is to be "featured"

CloudStack Cloud Account
------------------------

Key: ``account``
Used to authenticate the CloudStack platform.

The CloudStack cloud account has the following valid keys:

* ``type`` (mandatory): a string providing the cloud account type. Default platform type for CloudStack is ``CloudStack``. To get the available platform type, please refer to :ref:`command-line-platform`
* ``name`` (mandatory): a string providing the name of the cloud account. This name can be used in a builder section to reference the rest of the cloud account information.
* ``publicApiKey`` (mandatory): a string providing your public API key. If you do not have a public/secret key pair, please refer to the CloudStack documentation to generate them, or contact your cloud administrator
* ``secretApiKey`` (mandatory): a string providing your secret API key. If you do not have a public/secret key pair, please refer to the CloudStack documentation to generate them, or contact your cloud administrator
* ``endpointUrl`` (mandatory): a string providing the API URL endpoint of the cloudstack management console to upload the machine image to. For example: http://cloudstackhostname:8080/client/api
* ``file`` (optional): a string providing the location of the account information. This can be a pathname (relative or absolute) or an URL.

.. note:: In the case where ``name`` or ``file`` is used to reference a cloud account, all the other keys are no longer required in the account definition for the builder.

Example
-------

The following example shows a YAML CloudStack builder with all the information to build and publish a machine image to CloudStack.

.. note:: You can also use JSON.

.. code-block:: yaml

---
builders:
- type: CloudStack KVM (QCOW2)
  account:
    type: CloudStack
    name: My CloudStack account
    publicApiKey: mypublicapikey
    secretApiKey: mysecretapiKey
    endpointUrl: myendpointurl
  imageName: CentOS Core
  zone: zone1


Referencing the Cloud Account
-----------------------------

To help with security, the cloud account information can be referenced by the builder section. This example is the same as the previous example but with the account information in another file. Create a yaml file ``cloudstack-account.yaml``.

.. code-block:: yaml

---
  accounts:
  - type: CloudStack
    name: My CloudStack account
    publicApiKey: mypublicapikey
    secretApiKey: mysecretapiKey
    endpointUrl: myendpointurl

The builder section can either reference by using ``file`` or ``name``.

Reference by file:

.. code-block:: yaml

---
  builders:
  - type: CloudStack KVM (QCOW2)
    account:
      file: "/path/to/cloudstack-account.yaml"
    imageName: CentOS Core
    zone: zone1


Reference by name, note the cloud account must already be created by using ``account create``.

.. code-block:: yaml

---
  builders:
  - type: CloudStack KVM (QCOW2)
    account:
      name: My CloudStack Account
    imageName: CentOS Core
    zone: zone1
