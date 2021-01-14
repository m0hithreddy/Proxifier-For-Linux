# Proxifier-For-Linux

**proxifier - Proxifier For Linux**

## Overview

* proxifier acts as an intermediate between the proxy servers and client programs.
 
* proxifier works through the proxy servers on behalf of the other programs.

* proxifier acts as a global point for configuring proxy rules, which will be applied to every program in the system.

* For now, proxifier supports HTTP_PROXY.

## Dependencies

The list of dependencies required for compiling, running and building from the sources of Proxifier-For-Linux are given along with the possible installation steps (OS dependent)

##### Build and Install dependencies

* [```autoconf```](https://github.com/autotools-mirror/autoconf) [```$ sudo apt install autoconf```]
* [```automake```](https://github.com/autotools-mirror/automake) [```$ sudo apt install automake```]
* [```txt2man```](https://github.com/mvertes/txt2man) [```$ sudo apt install txt2man```]

## Downloading

Obtain the latest stable Proxifier sources by cloning from GitHub mirror

    $ git clone https://github.com/m0hithreddy/Proxifier-For-Linux.git && cd Proxifier-For-Linux

## Build and Install

After installing dependencies, obtaining Proxifier sources, and changing to the source directory:

    $ autoreconf -vfi
    $ ./configure
    $ make all
    $ sudo make uninstall
    $ sudo make install

## Usage
Proxifier service can be enabled as follows:

    $ sudo systemctl daemon-reload # Reload the service units
    $ sudo systemctl start proxifier

See the man page, ```$ man proxifier``` for more information. ```/usr/local/etc/proxifier.conf``` can be used for configuring the proxifier.

## Reporting

As a user, you can help the project by reporting any undefined, undesired, and unexpected behavior. Please, see [Reporting.md](https://github.com/m0hithreddy/Proxifier-For-Linux/blob/master/Reporting.md)

## Contributing

[Proxifier](https://github.com/m0hithreddy/Proxifier-For-Linux) works! But Proxifier requires many feature additions, improvements, and surveillance. If you are a budding developer like me, it is high time
you can get into some serious development by contributing to Proxifier. Please, see [Contributing.md](https://github.com/m0hithreddy/Proxifier-For-Linux/blob/master/Contributing.md)

## License
[GNU GPLv3](https://choosealicense.com/licenses/gpl-3.0/)
