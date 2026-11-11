=======================
pgmoneta-mcp-users.conf
=======================

------------------------------------------
Users configuration file for pgmoneta-mcp
------------------------------------------

:Manual section: 5

DESCRIPTION
===========

pgmoneta-mcp-users.conf is the users configuration file for pgmoneta-mcp.

The file is split into different sections specified by the ``[`` and ``]`` characters. 
Users are defined in the ``[pgmoneta-mcp-users]`` section.

The format is:

``username = "password_hash"``

Where the password hash is generated using SCRAM-SHA-256 (usually via the ``pgmoneta-mcp-admin`` utility).

OPTIONS
=======

username
  The name of the user.

password_hash
  The SCRAM-SHA-256 hash of the user's password.

REPORTING BUGS
==============

pgmoneta-mcp is maintained on GitHub at https://github.com/pgmoneta/pgmoneta-mcp

COPYRIGHT
=========

pgmoneta-mcp is licensed under the GNU General Public License v3.0

SEE ALSO
========

pgmoneta-mcp-server(1), pgmoneta-mcp-admin(1), pgmoneta-mcp.conf(5)
