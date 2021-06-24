Prelude + ELK
======================

This repository contains a dockerized version of Prelude OSS.


Requirements
------------

This repository relies on the following dependencies:

* docker.io >= 1.13.1
* docker-compose >= 1.11.0

It has been tested on Debian 10.0 (Buster) against the following
versions of these dependencies:

* docker.io 19.03.12
* docker-compose 1.25.0

In addition, the host should have at least 6 GB of available RAM.


Installation and start/stop instructions
----------------------------------------

Using git and docker-compose
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Clone this repository:

..  sourcecode:: console

    git clone -b master https://github.com/Kekere/prelude-elk.git

To start the SIEM, go to the newly created folder and run ``docker-compose``:

..  sourcecode:: console

    cd prelude-elk

    # Replace "Europe/Paris" with the appropriate timezone for your location.
    SYSLOG_TIMEZONE=Europe/Paris docker-compose up -f docker-compose.yml -f docker-composer.prod.yml \
                      --build --force-recreate --abort-on-container-exit
    # or if "make" is installed on your system, you can just run "make SYSLOG_TIMEZONE=..."

``docker-compose`` will recreate the containers, start them and wait for
further instructions.

The following containers will be spawned during this process:


    • prewikka: Prelude's web user interface
    • prewikka-crontab: periodic scheduler used by prewikka
    • manager: Prelude's manager
    • kibana: ELK’s data visualization
    • elasticsearch: ELK’s log storage
    • correlator: alert correlator
    • injector: entrypoint for logs
    • lml: Prelude's log management servant
    • db-alerts: database server for Prelude’s alerts
    • db-gui: database server for Prewikka
    • logstashalert: ingestor of alerts 

To stop the SIEM, hit Ctrl+C in the terminal where ``docker-compose``
was run.

Usage
-----

To access the SIEM, open a web browser and go to http://localhost/

To start analyzing syslog entries, send them to port 514 (TCP, unless you
also exposed the UDP port).

You can also use external sensors. In that case, the sensor must first
be registered against the manager container (see
https://www.prelude-siem.org/projects/prelude/wiki/InstallingAgentThirdparty
for instructions on how to do that for the most commonly used sensors).

When asked for a password during the registration process, input the
contents from the file at ``secrets/sensors``.

..  note::

    Since the containers are meant to be ephemeral, information about
    the external sensors' registrations is lost when the ``manager``
    container is stopped and restarted. You may need to register
    the sensors again in that case.


Exposed services
----------------

The following services get exposed to the host:

* ``514/tcp`` (``injector`` container): syslog receiver

* ``514/udp`` (``injector`` container): syslog receiver
  (Note: you may need to disable this port if is conflicts with the host's
  own syslog server)

* ``80/tcp`` (``prewikka`` container): web interface

* ``5553/tcp`` (``manager`` container): sensors' registration server
  (to connect external sensors like Suricata, OSSEC, ...)

* ``4690/tcp`` (``manager`` container): IDMEF alert receiver
  (for external sensors)

Depending on your use case, you may need to allow these ports inside the host's
firewall if you want to process logs from remote servers.


Test the SIEM
-------------

To test the SIEM, send syslog entries to ``localhost:514`` (TCP).

For example, the following command will produce a ``Remote Login`` alert
using the predefined rules:

..  sourcecode:: console

    logger --stderr -i -t sshd --tcp --port 514 --priority auth.info --rfc3164 --server localhost Failed password for root from ::1 port 45332 ssh2


Customizations
--------------

Detection rules
~~~~~~~~~~~~~~~

You can customize the detection rules used by mounting your own folder inside
the ``lml`` container at ``/etc/prelude-lml/ruleset/``.

See https://github.com/Prelude-SIEM/prelude-lml-rules/tree/master/ruleset
to get a sense of the contents of this folder.

Correlation rules
~~~~~~~~~~~~~~~~~

You can enable/disable/customize the correlation rules by mounting your own
folder containing the rules' configuration files inside the ``correlator``
container at ``/etc/prelude-correlator/conf.d/``.

See https://github.com/Prelude-SIEM/prelude-correlator/tree/master/rules
for more information about the default rules.


Known caveats
-------------

The following limitations have been observed while using this project:

* The sensors are re-registered every time the containers are restarted,
  meaning new entries get created on the ``Agents`` page every time a
  sensor is restarted.


Developer mode
--------------

In developer mode, the containers will use fresh images rebuilt against this
repository's Dockerfiles, rather than reusing pre-built images published on
Docker Hub.

This mode is only useful for myself and others who may want to fork this
repository.

To start Prelude OSS in developer mode, use this command:

..  sourcecode:: console

    make run ENVIRONMENT=dev


License
-------

This project is released under the MIT license.
See `LICENSE`_ for more information.

..  _`LICENSE`:
    https://github.com/fpoirotte/docker-prelude-siem/blob/master/LICENSE