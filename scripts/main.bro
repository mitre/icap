#
# File: main.bro
# Date: 20161024
#
# Copyright 2016 The MITRE Corporation.  All rights reserved.
# Approved for public release.  Distribution unlimited.  Case number 16-3871.
#

#
# Bro Internet Content Adaptation Protocol (ICAP) Analyzer.
#
# See RFC 3507, dated April 2003, for more information about ICAP.
#
#  - https://tools.ietf.org/html/rfc3507
#  - https://tools.ietf.org/html/draft-stecher-icap-subid-00
#  - https://www.icap-forum.org/documents/specifications/draft-icap-ext-partial-content-07.txt
#


#! Implements base functionality for ICAP analysis.
#! Generates the ICAP.log file.

@load base/bif/reporter.bif.bro
@load base/protocols/http/main.bro

module ICAP;

export {
	redef enum Log::ID += { LOG };

	type Info : record {
		## Timestamp for when the event happened.
		ts			: time		&log;

		## Unique ID for the connection.
		uid			: string	&log;

		## The connection's 4-tuple of endpoint addresses/ports.
		orig_h			: addr		&log;
		orig_p			: port		&log;
		resp_h			: addr		&log;
		resp_p			: port		&log;

	#
	# Header fields in ICAP request message
	#
		## ICAP Method: REQMOD | RESPMOD | OPTIONS		
		method			: string	&log &optional;

		## Should be "ICAP/1.0"
		req_version		: string	&log &optional;

		## ICAP URI: icap://<host>/<stuff>
		uri			: string	&log &optional;

		## Host: ICAP Server
		host			: string	&optional;

		## IP addresses of original HTTP client & server
		x_client_ip		: addr		&log &optional;
		x_server_ip		: addr		&log &optional;

		## User ID that authenticated to the web proxy/ICAP client
		x_authenticated_user	: string	&log &optional;

		## ICAP REQUEST Encapsulated HTTP Req Hdr, Req Body, Resp Hdr, or Resp Body
		req_encapsulated_header	: string	&log &optional;

	#
	# Header fields in ICAP response message
	#
		## Should be "ICAP/1.0"
		rsp_version		: string	&log &optional;

		## Typically: "204 No modifications needed"
		status_code		: int		&log &optional;
		reason			: string	&log &optional;

		## ICAP RESPONSE Encapsulated HTTP Req Hdr, Req Body, Resp Hdr, or Resp Body
		rsp_encapsulated_header	: string	&log &optional;

	#
	# Header fields in ICAP options message
	#
		# Ignore the OPTIONS header fields
	};


	## A list of ICAP Methods.  Other methods will generate a weird.
	const icap_methods : set[string] = {
		# RFC Defined Methods
		"REQMOD",
		"RESPMOD",
		"OPTIONS",
	} &redef;


	## A list of ICAP headers common to both Request & Response messages.
	const icap_common_header_names : set[string] = {
		"Cache-Control",
		"Connection",
		"Date",
		"Encapsulated",
		"Expires",
		"Pragma",
		"Trailer",
		"Upgrade",
	} &redef;


	## A list of ICAP headers used within Request messages.
	## Other headers will generate a weird.
	const icap_request_header_names : set[string] = {
		# RFC Defined Header Names
		"Allow",
		"Authorization",
		"From",
		"Host",
		"Preview",
		"Referer",
		"User-Agent",

		# Extensions
		"X-Authenticated-User",
		"X-Client-IP",
		"X-Server-IP",
		"X-Scan-Progress-Interval",
		"X-Client-Abandon-Supported",
		"X-Threat-Risk-Level",

		# Common to both Requests & Responses
		icap_common_header_names,
	} &redef;


	## A list of ICAP headers used within Response messages.
	## Other headers will generate a weird.
	const icap_response_header_names : set[string] = {
		# RFC Defined Header Names
		"ISTag",
		"Server",
		"Service",
		"Service-ID",

		# Extensions
		"X-Apparent-Data-Types",
		"X-Scan-Progress",

		# Common to both Requests & Responses
		icap_common_header_names,
	} &redef;


	## A list of ICAP headers used within Options messages.
	## Other headers will generate a weird.
	const icap_options_header_names : set[string] = {
		# RFC Defined Header Names
		"Allow",
		"Date",
		"Encapsulated",
		"ISTag",
		"Max-Connections",
		"Methods",
		"Opt-body-type",
		"Options-TTL",
		"Preview",
		"Service",
		"Service-ID",
		"Transfer-Preview",
		"Transfer-Ignore",
		"Transfer-Complete",

	} &redef;


	## A list of ICAP status codes.
	## Other status codes will generate a weird.
	const icap_status_codes : set[string] = {
		# RFC Defined Status Codes
		"100", "101",
		"200", "201", "202", "203", "204", "205", "206",
		"300", "301", "302", "303", "304", "305", "306", "307",
		"400", "401", "402", "403", "404", "405", "406", "407", "408", "409",
		"410", "411", "412", "413", "414", "415", "416", "417",
		"500", "501", "502", "503", "504", "505",

	} &redef;


	## Event that can be handled to access the ICAP record as it is sent on
	## to the logging framework.
	global log_icap : event(rec: Info);


	## Add new element to HTTP::Info record, corresponding to the
	## user ID that originated the connection; Derived from the 
	## ICAP Header 'x_authenticated_user'.
	redef record HTTP::Info += {
		orig_x_authenticated_user_name	: string	&log &optional;
	};
}


# # #
# #   E X T E N D   C O N N E C T I O N   R E C O R D
# # #

redef record connection += {
	icap		: Info &optional;
};


# # #
# #   I C A P   P O R T
# # # 

const	icap_port		= 1344/tcp	&redef;
redef	likely_server_ports	+= { icap_port };


# # #
# #   H E L P E R   F U N C T I O N S
# # #

function get_user_name_from_icap_header( x_authenticated_user : string ) : string
{
	#
	# The format of the ICAP header field 'x_authenticated_user' is
	# derived from reference below.
	#
	#     https://tools.ietf.org/html/draft-stecher-icap-subid-00
	#
	# <authentication_scheme>://<authentication_path>
	#
	#     <authentication_scheme> = "WinNT" | "LDAP" | "Radius" | "Local"
	#
	#     <authentication_path> varies based on the scheme; contains user name.
	#

	local x_auth_scheme : string;
	local x_auth_user_path : string;
	local x_auth_user_name : string;
	local y : vector of string;

	local x = split_string(x_authenticated_user, /(:\/\/)/);

	x_auth_scheme = x[0];
	x_auth_user_path = x[1];

	switch( x_auth_scheme )
	{
	  case "WinNT":
		y = split_string(x_auth_user_path, /\//);
		x_auth_user_name = y[1];
		break;

	  case "LDAP":
		y = split_string(x_auth_user_path, /cn=/);
		x_auth_user_name = y[1];
		break;

	  case "Radius":
		y = split_string(x_auth_user_path, /\//);
		x_auth_user_name = y[1];
		break;

	  case "Local":
		x_auth_user_name = x_auth_user_path;
		break;

	  #end switch
	}

	return x_auth_user_name;

  #end get_user_name_from_icap_header()
}


function new_icap_session(c : connection) : ICAP::Info
{
	local tmp	: Info;

	tmp$ts		= c$start_time;
	tmp$uid		= c$uid;

	tmp$orig_h	= c$id$orig_h;
	tmp$orig_p	= c$id$orig_p;
	tmp$resp_h	= c$id$resp_h;
	tmp$resp_p	= c$id$resp_p;

	return tmp;

  #end new_icap_session()
}


function new_http_session_from_icap_payload(c : connection) : HTTP::Info
{
	local tmp	: HTTP::Info;

	tmp$ts		= c$icap$ts;
	tmp$uid		= c$icap$uid;
	tmp$id		= c$id;
	
	return tmp;

  #end new_http_session_from_icap_payload()
}


# # #
# #   E V E N T   H A N D L E R S
# # #

event bro_init() &priority=5
{
	Log::create_stream(ICAP::LOG, [$columns=Info, $ev=log_icap, $path="icap"]);
	Analyzer::register_for_port (Analyzer::ANALYZER_ICAP, icap_port);

  #end bro_init()
}


event icap_request_line(
	c		: connection,
	method		: string,
	original_URI	: string,
	version_name	: string,
	version_value	: string
					) &priority=5
{
	# Set-up for new ICAP transaction
	if (!c?$icap) {	c$icap = new_icap_session(c); }

	c$icap$method		= method;
	c$icap$uri		= original_URI;
	c$icap$req_version	= fmt("%s%s", version_name, version_value);

	if ( method !in icap_methods )
	{
		event conn_weird("ICAP_WEIRD: unknown ICAP method", c, method);
	}

	if ( version_name != "ICAP/" ||
	     version_value != "1.0" )
	{
		event conn_weird("ICAP_WEIRD: unknown ICAP version", c, c$icap$req_version);
	}

  #end icap_request_line()
}


event icap_response_line(
	c		: connection,
	status_code	: string,
	reason		: string,
	version_name	: string,
	version_value	: string
					) &priority=5
{
	# Set-up for new ICAP transaction
	if (!c?$icap) {	c$icap = new_icap_session(c); }

	c$icap$status_code	= to_int(status_code);
	c$icap$reason		= reason;
	c$icap$rsp_version	= fmt("%s%s", version_name, version_value);

	if ( status_code !in icap_status_codes )
	{
		event conn_weird("ICAP_WEIRD: unknown ICAP status code", c, status_code);
	}

	if ( version_name != "ICAP/" ||
	     version_value != "1.0" )
	{
		event conn_weird("ICAP_WEIRD: unknown ICAP version", c, c$icap$rsp_version);
	}

  #end icap_response_line()
}


event icap_header(
	c		: connection,
	is_orig		: bool,
	name		: string,
	value		: string
					) &priority=5
{
	# Set-up for new HTTP transaction
	if (!c?$http) { c$http = new_http_session_from_icap_payload(c); }

	local is_weird : bool = F;

	switch ( c$icap$method )
	{
	case "REQMOD":
		fallthrough;
	case "RESPMOD":

		if ( is_orig )
		{
			# # #
			# #   I C A P  R E Q U E S T
			# #
			# #   Check header NAMES
			# #   Store the VALUES we care about
			# # #

			switch ( name )
			{
			case "Host":
				c$icap$host = value;
				break;

			case "X-Client-IP":
				c$icap$x_client_ip = to_addr(value);

				# Set HTTP orig_h to that of ICAP x_client_ip
				c$http$id$orig_h = c$icap$x_client_ip;
				break;

			case "X-Server-IP":
				c$icap$x_server_ip = to_addr(value);

				# Set HTTP resp_h to that of ICAP x_server_ip
				c$http$id$resp_h = c$icap$x_server_ip;
				break;

			case "X-Authenticated-User":
				c$icap$x_authenticated_user = decode_base64(value);
				break;

			case "Encapsulated":
				c$icap$req_encapsulated_header = value;
				break;

			case "Preview":
				# Found 'Preview' ICAP header.  
				# The ICAP Analyzer code does not handle Preview at this time.
				# Log it as WEIRD and then analyze if/when we encounter it.

				is_weird = T;
				break;

			default:
				# # #
				# #   Check for other valid header NAMES
				# # #
				if ( name !in icap_request_header_names )
				{
					# Found unrecognized ICAP header name in ICAP Request packet.
					# Log it as WEIRD and then analyze if/when we encounter it.

					is_weird = T;
				}
				else {
					#
					# We recognize the header NAME, but ignore it
					#
				}

				break;
			} #end switch
		}
		else
		{
			# # #
			# #   I C A P  R E S P O N S E
			# #
			# #   Check header NAMES
			# #   Store the VALUES we care about
			# # #

			switch ( name )
			{
			case "Encapsulated":
				c$icap$rsp_encapsulated_header = value;
				break;

			default:
				# # #
				# #   Check for other valid header NAMES
				# # #
				if ( name !in icap_response_header_names )
				{
					# Found unrecognized ICAP header name in ICAP Response packet.
					# Log it as WEIRD and then analyze if/when we encounter it.

					is_weird = T;
				}
				else
				{
					#
					# We recognize the header NAME, but ignore it
					#
				}

				break;
			} #end switch
		} # end else

		break;

	case "OPTIONS":
		# # #
		# #   I C A P  O P T I O N S
		# # #

		if ( name !in icap_options_header_names )
		{
			# Found unrecognized ICAP header name in ICAP Options packet.
			# Log it as WEIRD and then analyze if/when we encounter it.

			is_weird = T;
		}

		break;

	} #end switch


	if (is_weird)
	{
		local z = fmt("header: %s: %s :: method: %s :: is_orig: %d", 
			name, value, c$icap$method, is_orig);
		event conn_weird("ICAP_WEIRD", c, z);
	}

  #end icap_header()
}


event icap_body_weird(
	c		: connection,
	is_orig		: bool,
	req_hdr_flag	: bool,
	req_body_flag	: bool,
	rsp_hdr_flag	: bool,
	rsp_body_flag	: bool,
	options_flag	: bool,
	null_body_flag	: bool
					) &priority=4
{
	local encap_hdr : string;

	if (is_orig)
		encap_hdr = c$icap$req_encapsulated_header;
	else
		encap_hdr = c$icap$rsp_encapsulated_header;


	local z = fmt("%s :: method: %s :: is_orig: %d", encap_hdr, c$icap$method, is_orig);
	event conn_weird("ICAP_WEIRD: unknown ICAP body format", c, z);

  #end icap_body_weird
}


event icap_chunk_weird(
	c				: connection,
	is_orig				: bool,
	content_length_from_hdr		: int,
	content_length_all_chunks	: int,
	http_hdr			: string,
	http_hdr_len			: int
						) &priority=4
{
	local z = fmt("is_orig: %d :: HTTP Content-Length (from header): %d :: HTTP Body Length (actual): %d :: HTTP Headers (all): %s", is_orig, content_length_from_hdr, content_length_all_chunks, http_hdr);

	event conn_weird("ICAP_WEIRD: HTTP Body Length (after reassembling the ICAP Chunks) does not equal HTTP Content-Length", c, z);

  #end icap_chunk_weird
}


event icap_options(
	c			: connection,
	is_orig			: bool,
	options_body		: string,
	options_body_len	: int
					) &priority=5
{
	# Don't know what to do with OPTIONS yet.
	# Just log it as WEIRD and then analyze if/when we encounter it.

	local z = fmt( "options_body_len: %d :: options_body: %s :: method: %s :: is_orig: %d", 
			options_body_len, options_body, c$icap$method, is_orig);

	event conn_weird("ICAP_WEIRD: OPTIONS packet found", c, z);

  #end icap_options()
}


event icap_done(
	c		: connection,
	is_orig		: bool
					) &priority=5
{
	Log::write(ICAP::LOG, c$icap);

  #end icap_done
}


event icap_error(
	c		: connection,
	is_orig		: bool,
	error_type	: string,
	error_detail	: string
					) &priority=5
{
	# Set-up for new ICAP transaction
	if (!c?$icap) {	c$icap = new_icap_session(c); }

	local z = fmt("ICAP_ERROR :: %s :: %s", error_type, error_detail);
	Reporter::error(z);

  #end icap_error
}


event http_request(
	c		: connection,
	method		: string,
	original_URI	: string,
	unescaped_URI	: string,
	version		: string
				) &priority=5
{
	if ( c?$icap && c$icap?$x_authenticated_user )
	{
		c$http$orig_x_authenticated_user_name = get_user_name_from_icap_header(c$icap$x_authenticated_user);
	}
}

#end main.bro
