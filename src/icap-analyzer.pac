#
# File: icap-analyzer.pac
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


refine flow ICAP_Flow += {

	%member{
		bool	b_encap_hdr_found_;
		int	i_body_type_found_;

		analyzer::Analyzer* h;
	%}


	%init{
		b_encap_hdr_found_	= false;
		i_body_type_found_	= BODY_TYPE_NONE;
	%}


# # # # #
	# ICAP-Processing Functions:
	#
	#	proc_icap_request_line()
	#	proc_icap_response_line()
	#	proc_icap_header()
	#	proc_icap_body_acd()
	#	proc_icap_body_ac()
	#	proc_icap_body_cd()
	#	proc_icap_body_d()
	#	proc_icap_body_ab()
	#	proc_icap_body_a()
	#	proc_icap_body_b()
	#	proc_icap_options()
	#	proc_icap_pdu()
# # # # #

function proc_icap_request_line(req : ICAP_Request_Line) : bool
%{
	#ifdef ICAP_DEBUG
	const char* dbg_icap = "DEBUG <icap_analyzer.pac> proc_icap_request_line";
	cout << dbg_icap << "\n";
	cout << dbg_icap << " :: req->method :: " << req->method().begin() << "\n";
	cout << dbg_icap << " :: req->uri :: " << req->uri().begin() << "\n";
	#endif

	StringVal* a_ptr = 0;
	StringVal* b_ptr = 0;
	StringVal* c_ptr = 0;
	StringVal* d_ptr = 0;

	// Allocate memory via ``new``.
	a_ptr	= new StringVal((const char*)req->method().begin());
	b_ptr	= new StringVal((const char*)req->uri().begin());
	c_ptr 	= new StringVal((const char*)req->version()->name().begin());
	d_ptr	= new StringVal((const char*)req->version()->value().begin());

	BifEvent::generate_icap_request_line
	(
		connection()->bro_analyzer(),
		connection()->bro_analyzer()->Conn(),
		a_ptr,
		b_ptr,
		c_ptr,
		d_ptr
	);

	// When do these ``StringVal`` memory buffers get freed?

	return true;

   // proc_icap_request_line()
%}


function proc_icap_response_line(rsp : ICAP_Response_Line) : bool
%{
	#ifdef ICAP_DEBUG
	const char* dbg_icap = "DEBUG <icap_analyzer.pac> proc_icap_response_line";
	cout << dbg_icap << "\n";
	cout << dbg_icap << " :: rsp->status_code :: " << rsp->status_code().begin() << "\n";
	cout << dbg_icap << " :: rsp->reason :: " << rsp->reason().begin() << "\n";
	#endif

	StringVal* a_ptr = 0;
	StringVal* b_ptr = 0;
	StringVal* c_ptr = 0;
	StringVal* d_ptr = 0;

	// Allocate memory via ``new``.
	a_ptr	= new StringVal((const char*)rsp->status_code().begin());
	b_ptr	= new StringVal((const char*)rsp->reason().begin());
	c_ptr	= new StringVal((const char*)rsp->version()->name().begin());
	d_ptr	= new StringVal((const char*)rsp->version()->value().begin());

	BifEvent::generate_icap_response_line
	(
		connection()->bro_analyzer(),
		connection()->bro_analyzer()->Conn(),
		a_ptr,
		b_ptr,
		c_ptr,
		d_ptr
	);

	// When do these ``StringVal`` memory buffers get freed?

	return true;

   // proc_icap_response_line()
%}


function proc_icap_header
(
	hdr	: ICAP_Header,
	is_orig	: bool
								) : bool
%{
	#ifdef ICAP_DEBUG
	const char* dbg_icap = "DEBUG <icap_analyzer.pac> proc_icap_header";
	cout << dbg_icap << "\n";
	cout << dbg_icap << " :: is_orig :: " << is_orig << "\n";
	cout << dbg_icap << " :: hdr->name  :: " << hdr->name().begin() << "\n";
	cout << dbg_icap << " :: hdr->value :: " << hdr->value().begin() << "\n";
	#endif

	// Allocate memory via ``new``.
	StringVal* hdr_name = new StringVal((const char*)hdr->name().begin());
	StringVal* hdr_value = new StringVal((const char*)hdr->value().begin());

	BifEvent::generate_icap_header
	(
		connection()->bro_analyzer(),
		connection()->bro_analyzer()->Conn(),
		is_orig,
		hdr_name,
		hdr_value
	);

	// When do these ``StringVal`` memory buffers get freed?

	return true;

   // proc_icap_header()
%}


function proc_icap_body_acd
(
	body	: ICAP_Body_acd,
	is_orig	: bool
								) : bool
%{
	#ifdef ICAP_DEBUG
	const char* dbg_icap = "DEBUG <icap_analyzer.pac> proc_icap_body_acd";
	cout << dbg_icap << "\n";
	cout << dbg_icap << " :: is_orig :: " << is_orig << "\n";
	#endif

	bool http_chunked = false;
	int  http_content_length = -1;		// init to 'content_length unknown'

	//
	// Before invoking the HTTP Analyzer, determine if original HTTP message
	// was chunk-encoded or not.
	//
	// Per RFC 3507, we can use the "Transfer-Encoding: chunked" HTTP header field 
	// to determine the chunk-encoding state of the original HTTP Body.
	//

	http_chunked =	get_http_transfer_encoding_chunk_value_from_hdr
			(
				body->encap_rsp_hdr(),
				is_orig
			);

	if ( !http_chunked )
	{
		http_content_length =	get_http_content_length_value_from_hdr
					(
						body->encap_rsp_hdr(),
						is_orig
					);
	}
	else
	{
		http_content_length = -1;
	}

	//
	// Invoke HTTP Protocol Analyzer
	//

	proc_http_invoke_analyzer
	(
		body->encap_req_hdr(),
		0,
		body->encap_rsp_hdr(),
		body->encap_rsp_bdy(),
		http_chunked,
		http_content_length,
		BODY_TYPE_ACD,
		is_orig
	);

	return true;

   // proc_icap_body_acd()
%}


function proc_icap_body_ac
(
	body	: ICAP_Body_ac,
	is_orig	: bool
								) : bool
%{
	#ifdef ICAP_DEBUG
	const char* dbg_icap = "DEBUG <icap_analyzer.pac> proc_icap_body_ac";
	cout << dbg_icap << "\n";
	cout << dbg_icap << " :: is_orig :: " << is_orig << "\n";
	#endif

	bool http_chunked = false;
	int  http_content_length = -1;		// init to 'content_length unknown'

	//
	// Invoke HTTP Protocol Analyzer
	//

	proc_http_invoke_analyzer
	(
		body->encap_req_hdr(),
		0,
		body->encap_rsp_hdr(),
		0,
		http_chunked,
		http_content_length,
		BODY_TYPE_AC,
		is_orig
	);

	return true;

   // proc_icap_body_ac()
%}


function proc_icap_body_cd
(
	body	: ICAP_Body_cd,
	is_orig	: bool
								) : bool
%{
	#ifdef ICAP_DEBUG
	const char* dbg_icap = "DEBUG <icap_analyzer.pac> proc_icap_body_cd";
	cout << dbg_icap << "\n";
	cout << dbg_icap << " :: is_orig :: " << is_orig << "\n";
	#endif

	bool http_chunked = false;
	int  http_content_length = -1;		// init to 'content_length unknown'

	//
	// Before invoking the HTTP Analyzer, determine if original HTTP message
	// was chunk-encoded or not.
	//
	// Per RFC 3507, we can use the "Transfer-Encoding: chunked" HTTP header field 
	// to determine the chunk-encoding state of the original HTTP Body.
	//

	http_chunked =	get_http_transfer_encoding_chunk_value_from_hdr
			(
				body->encap_rsp_hdr(),
				is_orig
			);

	if ( !http_chunked )
	{
		http_content_length =	get_http_content_length_value_from_hdr
					(
						body->encap_rsp_hdr(),
						is_orig
					);
	}
	else
	{
		http_content_length = -1;
	}

	//
	// Invoke HTTP Protocol Analyzer
	//

	proc_http_invoke_analyzer
	(
		0,
		0,
		body->encap_rsp_hdr(),
		body->encap_rsp_bdy(),
		http_chunked,
		http_content_length,
		BODY_TYPE_CD,
		is_orig
	);

	return true;

   // proc_icap_body_cd()
%}


function proc_icap_body_d
(
	body	: ICAP_Body_d,
	is_orig	: bool
								) : bool
%{
	#ifdef ICAP_DEBUG
	const char* dbg_icap = "DEBUG <icap_analyzer.pac> proc_icap_body_d";
	cout << dbg_icap << "\n";
	cout << dbg_icap << " :: is_orig :: " << is_orig << "\n";
	#endif

	bool http_chunked = false;
	int  http_content_length = -1;		// init to 'content_length unknown'

	//
	// Invoke HTTP Protocol Analyzer
	//

	proc_http_invoke_analyzer
	(
		0,
		0,
		0,
		body->encap_rsp_bdy(),
		http_chunked,
		http_content_length,
		BODY_TYPE_D,
		is_orig
	);

	return true;

   // proc_icap_body_d()
%}


function proc_icap_body_ab
(
	body	: ICAP_Body_ab,
	is_orig	: bool
								) : bool
%{
	#ifdef ICAP_DEBUG
	const char* dbg_icap = "DEBUG <icap_analyzer.pac> proc_icap_body_ab";
	cout << dbg_icap << "\n";
	cout << dbg_icap << " :: is_orig :: " << is_orig << "\n";
	#endif

	bool http_chunked = false;
	int  http_content_length = -1;		// init to 'content_length unknown'

	//
	// Before invoking the HTTP Analyzer, determine if original HTTP message
	// was chunk-encoded or not.
	//
	// Per RFC 3507, we can use the "Transfer-Encoding: chunked" HTTP header field 
	// to determine the chunk-encoding state of the original HTTP Body.
	//

	http_chunked =	get_http_transfer_encoding_chunk_value_from_hdr
			(
				body->encap_req_hdr(),
				is_orig
			);

	if ( !http_chunked )
	{
		http_content_length =	get_http_content_length_value_from_hdr
					(
						body->encap_req_hdr(),
						is_orig
					);
	}
	else
	{
		http_content_length = -1;
	}

	//
	// Invoke HTTP Protocol Analyzer
	//

	proc_http_invoke_analyzer
	(
		body->encap_req_hdr(),
		body->encap_req_bdy(),
		0,
		0,
		http_chunked,
		http_content_length,
		BODY_TYPE_AB,
		is_orig
	);

	return true;

   // proc_icap_body_ab()
%}


function proc_icap_body_a
(
	body	: ICAP_Body_a,
	is_orig	: bool
								) : bool
%{
	#ifdef ICAP_DEBUG
	const char* dbg_icap = "DEBUG <icap_analyzer.pac> proc_icap_body_a";
	cout << dbg_icap << "\n";
	cout << dbg_icap << " :: is_orig :: " << is_orig << "\n";
	#endif

	bool http_chunked = false;
	int  http_content_length = -1;		// init to 'content_length unknown'

	//
	// Invoke HTTP Protocol Analyzer
	//

	proc_http_invoke_analyzer
	(
		body->encap_req_hdr(),
		0,
		0,
		0,
		http_chunked,
		http_content_length,
		BODY_TYPE_A,
		is_orig
	);

	return true;

   // proc_icap_body_a()
%}


function proc_icap_body_b
(
	body	: ICAP_Body_b,
	is_orig	: bool
								) : bool
%{
	#ifdef ICAP_DEBUG
	const char* dbg_icap = "DEBUG <icap_analyzer.pac> proc_icap_body_b";
	cout << dbg_icap << "\n";
	cout << dbg_icap << " :: is_orig :: " << is_orig << "\n";
	#endif

	bool http_chunked = false;
	int  http_content_length = -1;		// init to 'content_length unknown'

	//
	// Invoke HTTP Protocol Analyzer
	//

	proc_http_invoke_analyzer
	(
		0,
		body->encap_req_bdy(),
		0,
		0,
		http_chunked,
		http_content_length,
		BODY_TYPE_B,
		is_orig
	);

	return true;

   // proc_icap_body_b()
%}


function proc_icap_options
(
	body	: ICAP_Body_options,
	is_orig	: bool
								) : bool
%{
	#ifdef ICAP_DEBUG
	const char* dbg_icap = "DEBUG <icap_analyzer.pac> proc_icap_options";
	cout << dbg_icap << "\n";
	cout << dbg_icap << " :: is_orig :: " << is_orig << "\n";
	cout << dbg_icap << " :: body :: " << body->encap_opt_bdy().begin() << "\n";
	#endif

	// Allocate memory via ``new``.
	StringVal* opts_ptr = new StringVal((const char*)body->encap_opt_bdy().begin());
	int opts_len = opts_ptr->Len();

	//
	// Generate Event for ICAP Options
	//
	// We have not seen an OPTIONS packet yet within the sample data,
	// so this event may need to be revisited if/when we encouter it.
	//

	BifEvent::generate_icap_options 
	(
		connection()->bro_analyzer(),
		connection()->bro_analyzer()->Conn(),
		is_orig,
		opts_ptr,
		opts_len
	);

	// When do these ``StringVal`` memory buffers get freed?

	return true;

   // proc_icap_options()
%}


function proc_icap_pdu
(
	pdu	: ICAP_PDU,
	is_orig	: bool
								) : bool
%{
	#ifdef ICAP_DEBUG
	const char* dbg_icap = "DEBUG <icap_analyzer.pac> proc_icap_pdu";
	cout << dbg_icap << "\n";
	cout << dbg_icap << " :: is_orig :: " << is_orig << "\n";
	#endif

	//
	// Generated at end of processing a complete ICAP transaction, meaning an
	// ICAP request message followed by an ICAP response message.  This event
	// is generate after parsing the ICAP message body and after invoking the
	// HTTP protocol analyzer, indicating it is appropriate to write to the
	// ICAP log. 
	//

	if ( !is_orig )
	{
		BifEvent::generate_icap_done 
		(
			connection()->bro_analyzer(),
			connection()->bro_analyzer()->Conn(),
			is_orig
		);
	}

	return true;

   // proc_icap_pdu()
%}


# # # # #
	# The following functions were useful for DEBUG purposes,
	# but not needed for final product:
	#
	#	proc_icap_all_headers()
	#	proc_icap_encapsulated_http_header()
	#	proc_icap_encapsulated_http_all_headers()
	#	proc_icap_chunk()
	#	proc_icap_all_chunks()
	#	proc_icap_message()
	#	proc_icap_request()
	#	proc_icap_response()
# # # # #

function proc_icap_all_headers
(
	hdrs	: ICAP_Headers,
	is_orig	: bool
								) : bool
%{
	#ifdef ICAP_DEBUG
	const char* dbg_icap = "DEBUG <icap_analyzer.pac> proc_icap_all_headers";
	cout << dbg_icap << "\n";
	cout << dbg_icap << " :: is_orig :: " << is_orig << "\n";
	#endif

	return true;

   // proc_icap_all_headers()
%}


function proc_icap_encapsulated_http_header
(
	encap_hdr	: ICAP_Encapsulated_Http_Header,
	is_orig		: bool
								) : bool
%{
	#ifdef ICAP_DEBUG
	const char* dbg_icap = "DEBUG <icap_analyzer.pac> proc_icap_encapsulated_http_header";
	cout << dbg_icap << "\n";
	cout << dbg_icap << " :: is_orig :: " << is_orig << "\n";
	cout << dbg_icap << " :: encap_hdr :: " << encap_hdr->hdr().begin() << "\n";
	#endif

	return true;

   // proc_icap_encapsulated_http_header()
%}


function proc_icap_encapsulated_http_all_headers
(
	encap_hdrs	: ICAP_Encapsulated_Http_Headers,
	is_orig		: bool
								) : bool
%{
	#ifdef ICAP_DEBUG
	const char* dbg_icap = "DEBUG <icap_analyzer.pac> proc_icap_encapsulated_http_all_headers";
	cout << dbg_icap << "\n";
	cout << dbg_icap << " :: is_orig :: " << is_orig << "\n";
	#endif

	return true;

   // proc_icap_encapsulated_http_all_headers()
%}


function proc_icap_chunk
(
	chunk	: ICAP_Chunk,
	is_orig	: bool
								) : bool
%{
	#ifdef ICAP_DEBUG
	const char* dbg_icap = "DEBUG <icap_analyzer.pac> proc_icap_chunk";
	cout << dbg_icap << "\n";
	cout << dbg_icap << " :: is_orig :: " << is_orig << "\n";
	cout << dbg_icap << " :: chunk->chunk_size :: " << chunk->chunk_size() << "\n";
	#endif

	return true;

   // proc_icap_chunk()
%}


function proc_icap_all_chunks
(
	rsp	: ICAP_Chunks,
	is_orig	: bool
								) : bool
%{
	#ifdef ICAP_DEBUG
	const char* dbg_icap = "DEBUG <icap_analyzer.pac> proc_icap_all_chunks";
	cout << dbg_icap << "\n";
	cout << dbg_icap << " :: is_orig :: " << is_orig << "\n";
	#endif

	return true;

   // proc_icap_all_chunks()
%}


function proc_icap_message
(
	msg	: ICAP_Message,
	is_orig	: bool
								) : bool
%{
	#ifdef ICAP_DEBUG
	const char* dbg_icap = "DEBUG <icap_analyzer.pac> proc_icap_message";
	cout << dbg_icap << "\n";
	cout << dbg_icap << " :: is_orig :: " << is_orig << "\n";
	#endif

	return true;

   // proc_icap_message()
%}


function proc_icap_request(req : ICAP_Request) : bool
%{
	#ifdef ICAP_DEBUG
	const char* dbg_icap = "DEBUG <icap_analyzer.pac> proc_icap_request";
	cout << dbg_icap << "\n";
	#endif

	return true;

   // proc_icap_request()
%}


function proc_icap_response(rsp : ICAP_Response) : bool
%{
	#ifdef ICAP_DEBUG
	const char* dbg_icap = "DEBUG <icap_analyzer.pac> proc_icap_response";
	cout << dbg_icap << "\n";
	#endif

	return true;

   // proc_icap_response()
%}


   # end refine flow ICAP_Flow
};


#
# Re-define ICAP data structures to include a function call to do 
# additional processing and generate events
#
refine typeattr ICAP_Request_Line += &let {
	proc	: bool = $context.flow.proc_icap_request_line(this);

	## These routines get called *before* we process the next ICAP_Headers.
	## Initialize the globals to ensure a fresh start for the next ICAP_Request.

	flag_1	: bool = $context.flow.set_icap_encap_hdr_found_flag(false);
	flag_2	: int  = $context.flow.set_icap_body_type_found_flag(BODY_TYPE_NONE);
};

refine typeattr ICAP_Response_Line += &let {
	proc	: bool = $context.flow.proc_icap_response_line(this);

	## These routines get called *before* we process the next ICAP_Headers.
	## Initialize the globals to ensure a fresh start for the next ICAP_Response.

	flag_1	: bool = $context.flow.set_icap_encap_hdr_found_flag(false);
	flag_2	: int  = $context.flow.set_icap_body_type_found_flag(BODY_TYPE_NONE);
};

refine typeattr ICAP_Header += &let {
	proc	: bool = $context.flow.proc_icap_header(this, is_orig);
};

refine typeattr ICAP_Body_acd += &let {
	proc	: bool = $context.flow.proc_icap_body_acd(this, is_orig);
};

refine typeattr ICAP_Body_ac += &let {
	proc	: bool = $context.flow.proc_icap_body_ac(this, is_orig);
};

refine typeattr ICAP_Body_cd += &let {
	proc	: bool = $context.flow.proc_icap_body_cd(this, is_orig);
};

refine typeattr ICAP_Body_d += &let {
	proc	: bool = $context.flow.proc_icap_body_d(this, is_orig);
};

refine typeattr ICAP_Body_ab += &let {
	proc	: bool = $context.flow.proc_icap_body_ab(this, is_orig);
};

refine typeattr ICAP_Body_a += &let {
	proc	: bool = $context.flow.proc_icap_body_a(this, is_orig);
};

refine typeattr ICAP_Body_b += &let {
	proc	: bool = $context.flow.proc_icap_body_b(this, is_orig);
};

refine typeattr ICAP_Body_options += &let {
	proc	: bool = $context.flow.proc_icap_options(this, is_orig);
};

refine typeattr ICAP_PDU += &let {
	proc	: bool = $context.flow.proc_icap_pdu(this, is_orig);
};


#
# The following functions calls were useful for DEBUG purposes, but not needed 
# for final product. Therefore, de-activate the 'refine typeatttr' statements
# corresponding to these data elements.
#

# refine typeattr ICAP_Headers += &let {
#	proc	: bool = $context.flow.proc_icap_all_headers(this, is_orig);
# };

# refine typeattr ICAP_Encapsulated_Http_Header += &let {
#	proc	: bool = $context.flow.proc_icap_encapsulated_http_header(this);
# };

# refine typeattr ICAP_Encapsulated_Http_Headers += &let {
#	proc	: bool = $context.flow.proc_icap_encapsulated_http_all_headers(this);
# };

# refine typeattr ICAP_Chunk += &let {
#	proc	: bool = $context.flow.proc_icap_chunk(this, is_orig);
# };

# refine typeattr ICAP_Chunks += &let {
#	proc	: bool = $context.flow.proc_icap_all_chunks(this, is_orig);
# };

# refine typeattr ICAP_Message += &let {
# 	proc	: bool = $context.flow.proc_icap_message(this, is_orig);
# };

# refine typeattr ICAP_Request += &let {
#	proc	: bool = $context.flow.proc_icap_request(this);
# };

# refine typeattr ICAP_Response += &let {
#	proc	: bool = $context.flow.proc_icap_response(this);
# };


# end icap-analyzer.pac
