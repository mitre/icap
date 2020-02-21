#
# File: icap.pac
# Date: 20161024
#
# Copyright 2016 The MITRE Corporation.  All rights reserved.
# Approved for public release.  Distribution unlimited.  Case number 16-3871.
#

#
# Bro Internet Content Adaptation Protocol (ICAP) Analyzer.
#
#  - icap-protocol.pac: Describes the ICAP protocol messages, per RFC 3507.
#  - icap-analyzer.pac: ICAP analyzer code, throws ICAP events.
#  - icap-analyzer-http.pac: Additional code to asssist processing and invoking the HTTP analyzer.
#  - icap-analyzer-utils.pac: Additional code to perform useful functions in both ICAP and HTTP pac.
#
#
# See RFC 3507, dated April 2003, for more information about ICAP.
#
#  - https://tools.ietf.org/html/rfc3507
#  - https://tools.ietf.org/html/draft-stecher-icap-subid-00
#  - https://www.icap-forum.org/documents/specifications/draft-icap-ext-partial-content-07.txt
#

%include binpac.pac
%include bro.pac

%extern{

#include "events.bif.h"
#include "ICAP.h"

// #define ICAP_DEBUG	/* Uncomment this line to enable DEBUG print statements */ 
%}


# # #
# #   Globals
# # #

enum IcapMessageBodyTypes
{
	BODY_TYPE_NONE,		# ICAP message body not present (e.g., status code 204 ``No
				# modifications needed`` response does not have a body section.)
				#
	BODY_TYPE_ACD,		# RESPMOD: (a)req-hdr, (c)rsp-hdr, (d)rsp-body
	BODY_TYPE_AC,		# RESPMOD: (a)req-hdr, (c)rsp-hdr, (f)null-body
	BODY_TYPE_CD,		# RESPMOD: (c)rsp-hdr, (d)rsp-body
	BODY_TYPE_D,		# RESPMOD: (d)rsp-body
				#
	BODY_TYPE_AB,		# REQMOD:  (a)req-hdr, (b)req-body
	BODY_TYPE_A,		# REQMOD:  (a)req-hdr, (f)null-body
	BODY_TYPE_B,		# REQMOD:  (b)req-body
				#
	BODY_TYPE_OPTS,		# OPTIONS: (e)opt-body
				#
	BODY_TYPE_WEIRD,	# Unexpected body format.  Flag it as wierd and investigate if
				# it ever pops up.

	# Be mindful of ``null-body`` field, given it may appear within the ICAP header.
	# It is a valid field, per RFC 3507, and it may (or may not) get flagged as
	# ``weird`` if we have not accounted for it in all possible cases.
	#
	# During testing, 'null-body' fields encountered in pcap data.  Added the 
	# following body types to accommodate:
	# 	BODY_TYPE_AC
	#	BODY_TYPE_A
};


let body_ : int=BODY_TYPE_NONE;		# BinPAC Bug: This 'body_' global is defined to fix a compile 
					# error in 'icap_pac.cc::ICAP_Message::ParseBuffer'.
					#
					# BinPAC automagically created the variable 'body_' in the 
					# icap_pac.cc file but never defined it in icap_pac.h file.

# # #
# #   Analyzer / Connection / Flow
# # #

analyzer ICAP withcontext
{
	connection	: ICAP_Conn;
	flow		: ICAP_Flow;
};

connection ICAP_Conn(bro_analyzer : BroAnalyzer)
{
	upflow		= ICAP_Flow(true);
	downflow	= ICAP_Flow(false);
};


%include icap-protocol.pac


flow ICAP_Flow(is_orig : bool)
{
	flowunit = ICAP_PDU(is_orig) withcontext(connection, this);
};


%include icap-analyzer.pac
%include icap-analyzer-http.pac
%include icap-analyzer-utils.pac


# end icap.pac
