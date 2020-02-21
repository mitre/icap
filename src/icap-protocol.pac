#
# File: icap-protocol.pac
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

# # #
# #   REG-EX Patterns
# # #

type IcapTokenRegex	= RE/[^()<>@,;:\\"\/\[\]?={} \t]+/;
type IcapWhitespaceRegex= RE/[ \t]*/;
type IcapUriRegex	= RE/[[:alnum:][:punct:]]+/;
type IcapStatusRegex	= RE/[0-9]{3}/;
type IcapVersionRegex	= RE/[0-9]+\.[0-9]+/;


# # # 
# #   Packet Formats
# # #

type ICAP_Version = record {
	name		: "ICAP/";
	value		: IcapVersionRegex;
};


type ICAP_Request_Line = record {
	method		: IcapTokenRegex;
			: IcapWhitespaceRegex;	# anonymous field has no name
	uri		: IcapUriRegex;
			: IcapWhitespaceRegex;
	version		: ICAP_Version;
} &oneline;


type ICAP_Response_Line = record {
	version		: ICAP_Version;
			: IcapWhitespaceRegex;
	status_code	: IcapStatusRegex;
			: IcapWhitespaceRegex;
	reason		: bytestring &restofdata;
} &oneline;


type ICAP_Header(is_orig : bool) = record {
	name		: IcapTokenRegex;
			: ":";
			: IcapWhitespaceRegex;
	value		: bytestring &restofdata;
} &oneline;


type ICAP_Headers(is_orig : bool) = ICAP_Header(is_orig)[] &until($input.length() == 0);


type ICAP_Encapsulated_Http_Header = record {
	hdr		: bytestring &restofdata;
} &oneline;


type ICAP_Encapsulated_Http_Headers = ICAP_Encapsulated_Http_Header[] &until($input.length() == 0);


type ICAP_Chunk_Size_Field = record {		# BinPAC Bug: See Bro Issue Tracker #BIT-1500.  Must
	size_str	: bytestring &oneline;	# keep this record type separate from ICAP_Chunk.
};


type ICAP_Chunk_Data_Field(chunk_size : int) = record {
	data_str	: bytestring &length = chunk_size;
};


type ICAP_Chunk(is_orig : bool) = record {
	chunk_size_field: ICAP_Chunk_Size_Field;
	chunk_data_field: ICAP_Chunk_Data_Field(chunk_size);
	crlf		: bytestring &length=2;
} &let {
	chunk_size	: int = bytestring_to_int(chunk_size_field.size_str, 16);	# hexadecimal
};


type ICAP_Chunks(is_orig : bool) = record {
	chunks		: ICAP_Chunk(is_orig)[] &until($element.chunk_size == 0);
};


type ICAP_Body_acd(is_orig : bool) = record {
	encap_req_hdr	: ICAP_Encapsulated_Http_Headers;
	encap_rsp_hdr	: ICAP_Encapsulated_Http_Headers;
	encap_rsp_bdy	: ICAP_Chunks(is_orig);
};


type ICAP_Body_ac(is_orig : bool) = record {
	encap_req_hdr	: ICAP_Encapsulated_Http_Headers;
	encap_rsp_hdr	: ICAP_Encapsulated_Http_Headers;
};


type ICAP_Body_cd(is_orig : bool) = record {
	encap_rsp_hdr	: ICAP_Encapsulated_Http_Headers;
	encap_rsp_bdy	: ICAP_Chunks(is_orig);
};


type ICAP_Body_d(is_orig : bool) = record {
	encap_rsp_bdy	: ICAP_Chunks(is_orig);
};


type ICAP_Body_ab(is_orig : bool) = record {
	encap_req_hdr	: ICAP_Encapsulated_Http_Headers;
	encap_req_bdy	: ICAP_Chunks(is_orig);
};


type ICAP_Body_a(is_orig : bool) = record {
	encap_req_hdr	: ICAP_Encapsulated_Http_Headers;
};


type ICAP_Body_b(is_orig : bool) = record {
	encap_req_bdy	: ICAP_Chunks(is_orig);
};


type ICAP_Body_options(is_orig : bool) = record {
	encap_opt_bdy	: bytestring &restofdata;
} &oneline;



type ICAP_Body_none(is_orig : bool) = record {
	none	: empty;
} &oneline;


	# The message body structure is indicated by the "Encapsulated" Header contents.
	#
	# Per RFC 3507, pg 17:
	# 
	# REQMOD request:	[req-hdr] req-body
	# REQMOD response:	{[req-hdr] req-body} || {[rsp-hdr] rsp-body} 
	#
	# RESPMOD request:	[req-hdr] [rsp-hdr] rsp-body
	# RESPMOD response:	[rsp-hdr] [rsp-body]
	#
	# OPTIONS response:	opt-body || null-body
	#
	# NOTE: RFC states only one (1) body can be encapsulated, so it should
	#       never contain both an HTTP Req Body and an HTTP Resp Body

type ICAP_Message(is_orig : bool) = record
{
	headers		: ICAP_Headers(is_orig);
	body		: case $context.flow.get_icap_body_type_from_encap_hdr(headers, is_orig) of
	{
		BODY_TYPE_ACD	-> acd	: ICAP_Body_acd(is_orig);	# RESPMOD: (a)req-hdr, (c)rsp-hdr, (d)rsp-body
		BODY_TYPE_AC	-> ac	: ICAP_Body_ac(is_orig);	# RESPMOD: (a)req-hdr, (c)rsp-hdr, (f)null-body
		BODY_TYPE_CD	-> cd	: ICAP_Body_cd(is_orig);	# RESPMOD: (c)rsp-hdr, (d)rsp-body
		BODY_TYPE_D	-> d	: ICAP_Body_d(is_orig);		# RESPMOD: (d)rsp-body

		BODY_TYPE_AB	-> ab	: ICAP_Body_ab(is_orig);	# REQMOD:  (a)req-hdr, (b)req-body
		BODY_TYPE_A	-> a	: ICAP_Body_a(is_orig);		# REQMOD:  (a)req-hdr, (f)null-body
		BODY_TYPE_B	-> b	: ICAP_Body_b(is_orig);		# REQMOD:  (b)req-body

		BODY_TYPE_OPTS	-> opts	: ICAP_Body_options(is_orig);	# OPTIONS:  opt-body

		default 	-> none	: empty; # ICAP message body not present (e.g., status code 204
						 # "No modifications needed" response does not have a
						 #  body section).
	}; # end case
};


type ICAP_Request(is_orig : bool) = record
{
	request_line	: ICAP_Request_Line;
	message		: ICAP_Message(is_orig);
};


type ICAP_Response(is_orig : bool) = record
{
	response_line	: ICAP_Response_Line;
	message		: ICAP_Message(is_orig);
};


type ICAP_PDU(is_orig : bool) = case is_orig of
{
	true	-> request	: ICAP_Request(is_orig);
	false	-> response	: ICAP_Response(is_orig);
};


# end icap-protocol.pac
