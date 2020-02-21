#
# File: icap-analyzer-utils.pac
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


# # # # #
	# ICAP & HTTP Helper Functions:
	#
	#	get_icap_encap_hdr_found_flag()
	#	set_icap_encap_hdr_found_flag()
	#	get_icap_body_type_found_flag()
	#	set_icap_body_type_found_flag()
	#	get_icap_body_type_from_encap_hdr()
	#	get_http_transfer_encoding_chunk_value_from_hdr()
	#	get_http_content_length_value_from_hdr()
# # # # #

function get_icap_encap_hdr_found_flag() : bool
%{
	return b_encap_hdr_found_;
%}


function set_icap_encap_hdr_found_flag(flag : bool) : bool
%{
	b_encap_hdr_found_ = flag;
	return b_encap_hdr_found_;
%}


function get_icap_body_type_found_flag() : int
%{
	return i_body_type_found_;
%}


function set_icap_body_type_found_flag(flag : int) : int
%{
	i_body_type_found_ = flag;
	return i_body_type_found_;
%}


function get_icap_body_type_from_encap_hdr
(
	hdrs	: ICAP_Headers,
	is_orig	: bool
								) : int
%{
	#ifdef ICAP_DEBUG
	const char* dbg_icap = "DEBUG <icap_analyzer_utils.pac> get_icap_body_type_from_encap_hdr";
	cout << dbg_icap << "\n";
	cout << dbg_icap << " :: is_orig :: " << is_orig << "\n";
	#endif

	// This routine gets called repeatedly for each ICAP_Chunk data structure.
	// No need to search for and parse the Encapsulated Header field each time.
	// Minimize CPU cycles by checking globals first to see if we already found it
	// for this connection.

	int body_type = get_icap_body_type_found_flag();

	bool encap_hdr_found = get_icap_encap_hdr_found_flag();
	if ( encap_hdr_found ) { return body_type; }


	ICAP_Header* hdr = 0;
	vector<ICAP_Header *> * hdr_v = 0;

	unsigned char* name_ptr		= 0;
	unsigned char* value_ptr	= 0;
	char* encap_ptr			= (char*)"Encapsulated";
	char* z_ptr			= 0;

	unsigned int total_hdr_count = 0;
	unsigned int name_len	= 0;
	unsigned int value_len	= 0;
	unsigned int encap_len	= strlen(encap_ptr);
	unsigned int z_len 	= 0;
	unsigned int i 		= 0;

	bool a = false;
	bool b = false;
	bool c = false;
	bool d = false;
	bool e = false;
	bool f = false;

	// Total count of all headers is same as
	// size of vector array

	total_hdr_count	= hdrs->size();
	hdr_v		= hdrs->val();

	#ifdef ICAP_DEBUG
	cout << dbg_icap << " :: total_hdr_count :: " << total_hdr_count << "\n";
	#endif

	//
	// Walk thru each ICAP Header field in order to find
	// the "Encapsulated" Header
	//

	for ( i = 0; i < total_hdr_count; i++ )
	{
		hdr = hdr_v->at(i);

		name_ptr	= hdr->name().data();
		value_ptr	= hdr->value().data();

		name_len	= strlen((char*)name_ptr);
		value_len	= strlen((char*)value_ptr);

		#ifdef ICAP_DEBUG
		cout << dbg_icap << " :: while :: loop[x]   :: " << i << "\n";
		cout << dbg_icap << " :: while :: name_ptr  :: " << name_ptr << "\n";
		cout << dbg_icap << " :: while :: value_ptr :: " << value_ptr << "\n";
		#endif

		//
		// Perform two sanity checks:
		// (a) Have we seen "Encapsulated" Header yet
		// (b) Does the length of the current Header Name match "Encapsulated"
		//

		if ( (!encap_hdr_found) && (name_len == encap_len) )
		{
			if ( memcmp(name_ptr, encap_ptr, encap_len) == 0 )
			{
				// Found "Encapsulated" Header
				encap_hdr_found = true;

				i = total_hdr_count;	// Exit for-loop
			}
		}
	} // end for-loop


	//
	// Walk thru the Encapsulated Header field in order to determine
	// the structure of the Encapsulated Body 
	//

	if ( encap_hdr_found )
	{
		char* start_ptr		= (char*)value_ptr;
		const char* end_ptr	= start_ptr + value_len;

		while (start_ptr < end_ptr)
		{
			// Check for the delimiter
			z_ptr = (char*)", ";
			z_len = strlen(z_ptr);
			if ( (start_ptr + z_len) < end_ptr ) 
			{
			   if ( memcmp(start_ptr, z_ptr, z_len) == 0 )
			   {	// Skip past the delimiter
				start_ptr += z_len;
			   	continue;
			   }
			}

			z_ptr = (char*)"req-hdr=";
			z_len = strlen(z_ptr);
			if ( !a && ((start_ptr + z_len) < end_ptr) ) 
			{
			   if ( memcmp(start_ptr, z_ptr, z_len) == 0 )
			   {
				a = true;
				start_ptr += z_len;
				continue;
			   }
			}

			z_ptr = (char*)"req-body=";
			z_len = strlen((char*)z_ptr);
			if ( !b && ((start_ptr + z_len) < end_ptr) ) 
			{
			   if ( memcmp(start_ptr, z_ptr, z_len) == 0 )
			   {
				b = true;
				start_ptr += z_len;
				continue;
			   }
			}

			z_ptr = (char*)"res-hdr=";
			z_len = strlen((char*)z_ptr);
			if ( !c && ((start_ptr + z_len) < end_ptr) ) 
			{
			   if ( memcmp(start_ptr, z_ptr, z_len) == 0 )
			   {
				c = true;
				start_ptr += z_len;
				continue;
			   }
			}

			z_ptr = (char*)"res-body=";
			z_len = strlen((char*)z_ptr);
			if ( !d && ((start_ptr + z_len) < end_ptr) ) 
			{
			   if ( memcmp(start_ptr, z_ptr, z_len) == 0 )
			   {
				d = true;
				start_ptr += z_len;
				continue;
			   }
			}

			z_ptr = (char*)"opt-body=";
			z_len = strlen((char*)z_ptr);
			if ( !e && ((start_ptr + z_len) < end_ptr) ) 
			{
			   if ( memcmp(start_ptr, z_ptr, z_len) == 0 )
			   {
				e = true;
				start_ptr += z_len;
				continue;
			   }
			}

			z_ptr = (char*)"null-body=";
			z_len = strlen((char*)z_ptr);
			if ( !f && ((start_ptr + z_len) < end_ptr) ) 
			{
			   if ( memcmp(start_ptr, z_ptr, z_len) == 0 )
			   {
				f = true;
				start_ptr += z_len;
				continue;
			   }
			}

			start_ptr++;

		} // end while-loop

	} // end if


	//
	// Set return value to define the ICAP Message Body type
	//

	if ( a && !b && c && d )
		body_type = BODY_TYPE_ACD;   // ICAP_Body_acd
	else if ( a && !b && c && !d && f )
		body_type = BODY_TYPE_AC;    // ICAP_Body_ac
	else if ( !a && !b && c && d )
		body_type = BODY_TYPE_CD;    // ICAP_Body_cd
	else if ( !a && !b && !c && d )
		body_type = BODY_TYPE_D;     // ICAP_Body_d
	else if ( a && b && !c && !d  )
		body_type = BODY_TYPE_AB;    // ICAP_Body_ab
	else if ( a && !b && !c && !d && f )
		body_type = BODY_TYPE_A;     // ICAP_Body_a
	else if ( !a && b && !c && !d  )
		body_type = BODY_TYPE_B;     // ICAP_Body_b
	else if ( e )
		body_type = BODY_TYPE_OPTS;  // ICAP_Body_options
	else if ( !a && !b && !c && !d && !e )
		body_type = BODY_TYPE_NONE;  // Message Body not present
	else {
		// Unexpected body format.
		// Flag it as wierd and investigate if it ever pops up. 
		//
		// Be mindful of 'null-body' field, given it may appear within the 
		// ICAP header.  It is a valid field, per RFC 3507, though it may
		// get flagged as 'weird' given how the code is currently written.
		//
		// During testing, 'null-body' fields encountered in pcap data.
		// Added the following body types to accommodate:
		// 	BODY_TYPE_AC
		//	BODY_TYPE_A

		body_type = BODY_TYPE_WEIRD;

		BifEvent::generate_icap_body_weird
		(
			connection()->bro_analyzer(),
			connection()->bro_analyzer()->Conn(),
			is_orig,
			a, b, c, d, e, f
		);
	}

	#ifdef ICAP_DEBUG
	cout << dbg_icap << " :: body_type :: " << body_type << "\n";
	#endif

	set_icap_encap_hdr_found_flag(encap_hdr_found);
	set_icap_body_type_found_flag(body_type);


	return body_type;

   // get_icap_body_type_from_encap_hdr()
%}


function get_http_content_length_value_from_hdr
(
	encap_hdrs	: ICAP_Encapsulated_Http_Headers,
	is_orig		: bool
								) : int
%{
	#ifdef ICAP_DEBUG
	const char* dbg_icap = "DEBUG <icap_analyzer_utils.pac> get_http_content_length_value_from_hdr";
	cout << dbg_icap << "\n";
	cout << dbg_icap << " :: is_orig :: " << is_orig << "\n";
	#endif

	ICAP_Encapsulated_Http_Header* encap_hdr = 0;
	vector<ICAP_Encapsulated_Http_Header *> * hdr_v = 0;

	unsigned char*	hdr_ptr		= 0;
	unsigned int	hdr_len		= 0;
	unsigned int	total_hdr_count	= 0;	// Number of header fields
	unsigned int	i = 0;

	char*		z_ptr	= (char*)"Content-Length: ";
	unsigned int	z_len	= strlen(z_ptr);

	bool  content_length_found	= false;
	int   content_length		= -1;

	// Total count of all headers is same as
	// size of vector array

	total_hdr_count	= encap_hdrs->size();
	hdr_v		= encap_hdrs->val();

	#ifdef ICAP_DEBUG
	cout << dbg_icap << " :: total_hdr_count :: " << total_hdr_count << "\n";
	#endif

	//
	// Walk thru each HTTP Header field, in order to:
	//
	// (a) Check for "Content-Length: " header, which indicates the
	//     length of the HTTP Body for messages NOT chunk-encoded
	//

	for ( i = 0; i < total_hdr_count; i++ )
	{
		encap_hdr	= hdr_v->at(i);

		hdr_ptr		= encap_hdr->hdr().data();
		hdr_len		= encap_hdr->hdr().length();

		//
		// Safe memcmp:
		// (a) Have we seen "Content-Length: " Header yet
		// (b) Is the length of the current Header string > "Content-Length: "
		//

		if ( (!content_length_found) && (hdr_len > z_len) )
		{
		    if ( strncasecmp((const char*)hdr_ptr, (const char*)z_ptr, z_len) == 0 )
		    {
			// Found "Content-Length: " Header
			content_length_found	= true;
			content_length		= strtol((const char*)(hdr_ptr + z_len), 0, 10);
			
			i = total_hdr_count;	// Exit for-loop
		    }
		}

	} // end for-loop

	#ifdef ICAP_DEBUG
	cout << dbg_icap << " :: http_content_length_found :: " << content_length_found << "\n";
	cout << dbg_icap << " :: http_content_length :: " << content_length << "\n";
	#endif


	return content_length;

   // get_http_content_length_value_from_hdr()
%}


function get_http_transfer_encoding_chunk_value_from_hdr
(
	encap_hdrs	: ICAP_Encapsulated_Http_Headers,
	is_orig		: bool
								) : bool
%{
	#ifdef ICAP_DEBUG
	const char* dbg_icap = "DEBUG <icap_analyzer_utils.pac> get_http_transfer_encoding_chunk_value_from_hdr";
	cout << dbg_icap << "\n";
	cout << dbg_icap << " :: is_orig :: " << is_orig << "\n";
	#endif

	// Per RFC 3507, we can use the "Transfer-Encoding: chunked" HTTP header field 
	// to determine the chunk-encoding state of the original HTTP Body.

	ICAP_Encapsulated_Http_Header* encap_hdr = 0;
	vector<ICAP_Encapsulated_Http_Header *> * hdr_v = 0;

	unsigned char*	hdr_ptr		= 0;
	unsigned int	hdr_len		= 0;
	unsigned int	total_hdr_count	= 0;	// Number of header fields
	unsigned int	i = 0;

	char*		z_ptr	= (char*)"Transfer-Encoding: ";
	unsigned int	z_len	= strlen(z_ptr);

	char*		y_ptr	= (char*)"chunked";
	unsigned int	y_len	= strlen(y_ptr);

	bool  transfer_encoding_found	= false;
	bool  transfer_encoding_chunked	= false;

	// Total count of all headers is same as
	// size of vector array

	total_hdr_count	= encap_hdrs->size();
	hdr_v		= encap_hdrs->val();

	#ifdef ICAP_DEBUG
	cout << dbg_icap << " :: total_hdr_count :: " << total_hdr_count << "\n";
	#endif

	//
	// Walk thru each HTTP Header field, in order to:
	//
	// (a) Check for "Transfer-Encoding: " header, which indicates 
	//     if the original HTTP Body was chunk-encoded
	//

	for ( i = 0; i < total_hdr_count; i++ )
	{
		encap_hdr	= hdr_v->at(i);

		hdr_ptr		= encap_hdr->hdr().data();
		hdr_len		= encap_hdr->hdr().length();

		//
		// Safe memcmp:
		// (a) Have we seen "Transfer-Encoding: " Header yet
		// (b) Is the length of the current Header string equal to
		//     "Transfer-Encoding: chunked"
		// (c) If so, then check if "Transfer-Encoding: "
		// (d) If so, then check if "chunked"
		//

		if ( (!transfer_encoding_found) && (hdr_len == (z_len + y_len)) )
		{
		    if ( strncasecmp((const char*)hdr_ptr, (const char*)z_ptr, z_len) == 0 )
		    {
			// Found "Transfer-Encoding: " Header
			transfer_encoding_found	= true;

			// Now Check if "chunked"
			if ( strncasecmp((const char*)(hdr_ptr + z_len), (const char*)y_ptr, y_len) == 0 )
			{
				// "Transfer-Encoding: " is "chunked"
				transfer_encoding_chunked = true;
		
				i = total_hdr_count;	// Exit for-loop
			}
		    }
		}

	} // end for-loop

	#ifdef ICAP_DEBUG
	cout << dbg_icap << " :: http_transfer_encoding_found :: " << transfer_encoding_found << "\n";
	cout << dbg_icap << " :: http_transfer_encoding_chunked :: " << transfer_encoding_chunked << "\n";
	#endif


	return transfer_encoding_chunked;

   // get_http_transfer_encoding_chunk_value_from_hdr()
%}


   # end refine flow ICAP_Flow
};


# end icap-analyzer-utils.pac
