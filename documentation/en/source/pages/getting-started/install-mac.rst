.. Copyright (c) 2007-2016 UShareSoft, All rights reserved

.. _install-mac:

For Mac
=======

For Mac users, you need to have ``XCode`` installed (or any other C compiler).

You can download the latest version of Xcode from the Apple developer website or get it using the Mac App Store

Run the following command:

.. code-block:: shell

	$ xcode-select --install
	$ sudo easy_install pip
	$ sudo easy_install readline
	$ sudo easy_install progressbar==2.3
	$ sudo pip install hammr-3.6

If you already have hammr installed and want to upgrade to the latest version you can run:

.. code-block:: shell

	$ pip install --upgrade hammr
