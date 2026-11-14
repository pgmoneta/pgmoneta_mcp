=================
pgmoneta-mcp.conf
=================

----------------------------------------
Main configuration file for pgmoneta-mcp
----------------------------------------

:Manual section: 5

DESCRIPTION
===========

pgmoneta-mcp.conf is the main configuration file for pgmoneta-mcp.

The configuration of pgmoneta-mcp is split into sections using the ``[`` and ``]`` characters.

The main section is called ``[pgmoneta_mcp]``, where you configure the overall properties of the MCP server.
The other section is called ``[pgmoneta]``, where you configure the connection with the pgmoneta server.

OPTIONS
=======

The options for the ``[pgmoneta_mcp]`` section are:

port
  The port the MCP server starts on. Default is 8000.

log_type
  The logging type (console, file, syslog). Default is console.

log_level
  The logging level, any of the strings ``trace``, ``debug``, ``info``, ``warn`` and ``error``. Default is info.

log_path
  The log file location. Default is pgmoneta_mcp.log.

log_mode
  Append to or create the log file, any of the strings (``append``, ``create``). Default is append.

log_rotation_age
  The time after which log file rotation is triggered. Used when log_type is file and log_mode is append. Any of the chars (``0``) for never rotate, (``m``, ``M``) for minutely rotation, (``h``, ``H``) for hourly rotation, (``d``, ``D``) for daily rotation and (``w``, ``W``) for weekly rotation. Default is 0.

The options for the ``[pgmoneta]`` section are:

host
  The address of the pgmoneta instance. Mandatory.

port
  The port of the pgmoneta instance. Mandatory.

compression
  The compression used for the traffic to pgmoneta, any of the strings (``none``, ``gzip``, ``zstd``, ``lz4``, ``bzip2``). Default is zstd.

encryption
  The encryption used for the traffic to pgmoneta, any of the strings (``none``, ``aes_256_gcm``, ``aes_192_gcm``, ``aes_128_gcm``). Default is aes_256_gcm.

REPORTING BUGS
==============

pgmoneta-mcp is maintained on GitHub at https://github.com/pgmoneta/pgmoneta-mcp

COPYRIGHT
=========

pgmoneta-mcp is licensed under the GNU General Public License v3.0

SEE ALSO
========

pgmoneta-mcp-server(1), pgmoneta-mcp-admin(1)
