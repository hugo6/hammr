.. Copyright (c) 2007-2016 UShareSoft, All rights reserved

.. _stack-os-pkgs:

pkgs
====

Within the :ref:`stack-os` section, the ``pkgs`` sub-section is an array of objects describing any extra packages that should be installed as part of the machine image build. Any package information provided in this section must exist in the corresponding operating system repository, otherwise this will result in a build failure.

The definition of a pkgs section is:

.. code-block:: javascript

  "pkgs": [
      ...the list of packages goes here.
  ]

The valid keys to use within the pkgs object are:

* ``arch`` (optional): a string providing architecture to use
* fullName (optional): a string providing the name, version, release and architecture information. If used, the mandatory name key is not required.
* ``name`` (mandatory): a string providing the name of the package to use
* ``release`` (optional): a string providing the release of the package to use
* ``version`` (optional): a string providing the version of the package to use

When ``name`` is used on its own, the version, release and arch is determined when the machine image is being built. This information is determined during the package dependency phase of the build. The package dependency phase uses the created date of the stack within the UForge server to calculate the correct versions of packages. This date can be overridden by the ``updateTo`` key in the os section. Any missing packages required by the stack are also added to ensure any dependencies are met.

In the case where ``version``, ``release`` and ``arch`` (or ``fullName``) is used, then the version determined by the created stack date (or updateTo date) is overridden by the version details provided. This is known as making the package sticky. Note, that any updates available for this package will NOT be used in this case.

Examples
--------

Basic Example
~~~~~~~~~~~~~

The following example uses CentOS 6.4 64 bit operating system for the template and adding the packages ``php``, ``php-cli``, ``php-common`` and ``php-mysql``. Note that only the name is provided. The final version and release of these packages is determined during the build of the machine image.

.. code-block:: json

  {
    "os": {
      "name": "CentOS",
      "version": "6.4",
      "arch": "x86_64",
      "profile": "Minimal",
      "pkgs": [
        {
          "name": "php"
        },
        {
          "name": "php-cli"
        },
        {
          "name": "php-common"
        },
        {
          "name": "php-mysql"
        }
      ]
    }
  }

Adding a Version and Release
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

By adding ``version``, ``release`` and ``arch`` or ``fullName`, during the build this specific version is used regardless of any build date (``updateTo``) set in the ``os`` section. This is called making the package "sticky".

.. code-block:: json

  {
    "os": {
      "name": "CentOS",
      "version": "6.4",
      "arch": "x86_64",
      "profile": "Minimal",
      "pkgs": [
        {
          "name": "php",
          "version": "5.5.3",
          "release": "23.el6_4",
          "arch": "i686"
        },
        {
          "name": "php-cli",
          "version": "5.5.3",
          "release": "23.el6_4",
          "arch": "i686"
        },
        {
          "fullName": "php-common-5.5.3-23.el6_4-i686.rpm"
        },
        {
          "fullName": "php-mysql-5.5.3-23.el6_4-i686.rpm"
        }
      ]
    }
  }