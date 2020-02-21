#
# File: icap-analyzer-http.pac
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
	# HTTP-Processing Functions:
	#
	#	proc_http_reassemble_headers()
	#	proc_http_reassemble_body()
	#	proc_http_invoke_analyzer_submit_all_headers()
	#	proc_http_invoke_analyzer_submit_body()
	#	proc_http_invoke_analyzer()
# # # # #

function proc_http_reassemble_headers
(
	encap_hdrs	: ICAP_Encapsulated_Http_Headers,
	is_orig		: bool
								) : StringVal
%{
	#ifdef ICAP_DEBUG
	const char* dbg_icap = "DEBUG <icap_analyzer_http.pac> proc_http_reassemble_headers";
	cout << dbg_icap << "\n";
	cout << dbg_icap << " :: is_orig :: " << is_orig << "\n";
	#endif

	//
	// This routine is used only for the purpose of posting the HTTP Headers 
	// as a single, as a continuous buffer to the 'BifEvent::generate_icap_chunk_wierd'  
	// event.
	//
	// When the HTTP transfer-encoding is not chunked, then we should be able to compare
	// the 'total_body_len' we calculated against the 'http_content_length'
	// we extracted from the HTTP Header.  If the two values do not match,
	// then generate a weird...
	//
	// In support of that wierd event, let's print the full HTTP headers in the weird log.
	// Perhaps we could do trending to see who/why/what/when/where this
	// happens.
	//
	// Bro did a great job tearing the fields apart into individual strings, according
	// to the record types we defined, but now we shall put it back together, as follows:
	//
	//	<header_field_1><CRLF>
	//	<header_field_2><CRLF>
	//	...
	//	<header_field_n><CRLF>
	//	<CRLF><NULL>
	//
	// At first, I thought this routine would be necessary in support of submitting the
	// HTTP Headers to the HTTP Analyzer, but such was not the case, because I later
	// learned that 'HTTP_Analyzer::DeliverStream()' requires each Header to be submitted
	// individually, not as a continuous buffer.
	//
	// We add a NULL-terminator to faciliate string-processing routines.
	//

	ICAP_Encapsulated_Http_Header* encap_hdr = 0;
	vector<ICAP_Encapsulated_Http_Header *> * hdr_v = 0;

	StringVal* hdr_reassembled = 0;

	unsigned char* hdr_ptr = 0;		// Pointer to individual header field
	unsigned char* total_hdr_ptr = 0;	// Pointer to all header fields combined

	unsigned int hdr_len = 0;		// Length of individual header field
	unsigned int total_hdr_len = 0;		// Length of all header fields combined
	unsigned int total_hdr_count = 0;	// Number of header fields
	unsigned int i = 0;

	unsigned char crlf[2] = {0x0D, 0x0A};
	unsigned char null[1] = {0x00};

	unsigned int crlf_len = sizeof(crlf);
	unsigned int null_len = sizeof(null);

	const char* error_type_ptr = "ERROR: <icap_analyzer_http.pac> proc_http_reassemble_headers\n";
	StringVal* error_type	= 0;
	StringVal* error_descr	= 0;


	// Total count of all headers is same as
	// size of vector array

	total_hdr_count	= encap_hdrs->size();
	hdr_v		= encap_hdrs->val();

	#ifdef ICAP_DEBUG
	cout << dbg_icap << " :: total_hdr_count :: " << total_hdr_count << "\n";
	#endif

	//
	// Walk thru each HTTP Header field in order to calculate
	// the total size of all headers combined 'total_hdr_len'
	//

	for ( i = 0; i < total_hdr_count; i++ )
	{
		encap_hdr	= hdr_v->at(i);

		hdr_ptr		= encap_hdr->hdr().data();
		hdr_len		= encap_hdr->hdr().length();

		total_hdr_len	+= hdr_len; 
	
	} // end for-loop

	//
	// Increase 'total_hdr_len' to account for:
	//
	// (a) CRLF insert after each header field (indicating end of field)
	// (b) Final CRLF (indicating end of all headers)
	// (c) NULL-terminator (indicating end of string)
	//

	total_hdr_len	+= ((total_hdr_count * crlf_len) + crlf_len + null_len);


	//
	// Allocate local buffer for 'total_hdr_ptr'
	//

	total_hdr_ptr	= new unsigned char[total_hdr_len];
	memset(total_hdr_ptr, 0x00, total_hdr_len);


	//
	// Walk thru each HTTP Header field again, in order to:
	// Copy each header sequentially into a single buffer 'total_hdr_ptr'
	//

	unsigned char* start_ptr	= total_hdr_ptr;
	const unsigned char* end_ptr	= start_ptr + total_hdr_len;

	for ( i = 0; i < total_hdr_count; i++ )
	{
		encap_hdr	= hdr_v->at(i);

		hdr_ptr		= encap_hdr->hdr().data();
		hdr_len		= encap_hdr->hdr().length();

		//
		// Safe memcpy:
		// (a) Append header into single buffer
		// (b) Append CRLF after header field
		//

		if ( (start_ptr + hdr_len + crlf_len) <= end_ptr )
		{
			memcpy(start_ptr, hdr_ptr, hdr_len);
			start_ptr += hdr_len;

			memcpy(start_ptr, &crlf, crlf_len);
			start_ptr += crlf_len;
		}
		else {
			//
			// We should have calculated the buffer size correctly, so if we
			// do not have enough space to append the header and CRLF, then
			// something unexpected happened, so generate ICAP ERROR event.
			//
			error_type  = new StringVal(error_type_ptr);
			error_descr = 
				new StringVal("Not enough buffer space for header and CRLF.\n");
			BifEvent::generate_icap_error
			(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig,
				error_type,
				error_descr
			); 
		}

	} // end for


	//
	// Safe memcpy:
	// (c) append final CRLF to terminate header section
	// (d) append NULL-terminator for good measure
	//

	if ( (start_ptr + crlf_len + null_len) <= end_ptr )
	{
		memcpy(start_ptr, &crlf, crlf_len);
		start_ptr += crlf_len;

		memcpy(start_ptr, &null, null_len);
		start_ptr += null_len;
	}
	else {
		//
		// We should have calculated the buffer size correctly, so if we
		// do not have enough space to append the header and CRLF, then
		// something unexpected happened, so generate ICAP ERROR event.
		//
		error_type  = new StringVal(error_type_ptr);
		error_descr = 
			new StringVal("Not enough buffer space for final CRLF and NULL-terminator.\n");
		BifEvent::generate_icap_error
		(
			connection()->bro_analyzer(),
			connection()->bro_analyzer()->Conn(),
			is_orig,
			error_type,
			error_descr
		); 
	}


	// Create StringVal from total_hdr_ptr
	hdr_reassembled = new StringVal((int)total_hdr_len, (const char*)total_hdr_ptr);
	delete[] total_hdr_ptr;


	return hdr_reassembled;

   // proc_http_reassemble_headers()
%}


function proc_http_reassemble_body
(
	raw_chunks			: ICAP_Chunks,
	http_hdrs			: ICAP_Encapsulated_Http_Headers,
	http_transfer_encoding_chunked	: bool,
	http_content_length		: int,
	is_orig				: bool
								) : StringVal
%{
	#ifdef ICAP_DEBUG
	const char* dbg_icap = "DEBUG <icap_analyzer_http.pac> proc_http_reassemble_body";
	cout << dbg_icap << "\n";
	cout << dbg_icap << " :: is_orig :: " << is_orig << "\n";
	cout << dbg_icap << " :: http_chunked :: " << http_transfer_encoding_chunked << "\n";
	cout << dbg_icap << " :: http_content_length :: " << http_content_length << "\n";
	#endif

	//
	// Per RFC 3507, we can use the "Transfer-Encoding: chunked" HTTP header field 
	// to determine the chunk-encoding state of the original HTTP Body.
	//
	// If 'http_transfer_encoding_chunked' is FALSE, then we must reassemble the HTTP
	// Body Chunks prior to invoking the Bro HTTP analyzer.
	//
	// Bro did a great job tearing the fields apart into individual strings, according
	// to the record types we defined, but now we must put it back together, as follows:
	//
	//	<chunk_data_1><chunk_data_2>...<chunk_data_n>
	//
	// We do not add a NULL-terminator or any trailing CRLF to the UNCHUNKED buffer.
	// Instead, the total buffer size SHOULD equal the 'Content-Length' value contained
	// in the HTTP Header; but given the Headers are optional within the ICAP payload
	// (per RFC 3507), we must account for the case if/when that value is not avaiable
	// for comparison.
	//
	// This routine is used only for the purpose of creating an UNCHUNKED HTTP Body
	// as a single, continuous buffer.  This buffer is used prior to submitting the 
	// Body to the HTTP Protocol Analyzer.
	//
	// If 'http_transfer_encoding_chunked' is TRUE, then we do not use this routine.
	// Instead, 'HTTP_Analyzer::DeliverStream() requires each Chunk to be submitted
	// individually.
	//

	// Exit if 'http_transfer_encoding_chunked' is TRUE
	if (http_transfer_encoding_chunked) { return 0; }

	ICAP_Chunk* encap_chunk = 0;
	vector<ICAP_Chunk *> * chunk_v = 0;

	StringVal* body_reassembled = 0;

	unsigned char* chunk_ptr = 0;
	unsigned char* size_ptr = 0;
	unsigned char* total_body_ptr = 0;

	unsigned int chunk_len = 0;
	unsigned int total_body_len = 0;
	unsigned int total_chunk_count = 0;
	unsigned int i = 0;

	const char* error_type_ptr = "ERROR: <icap_analyzer_http.pac> proc_http_reassemble_body\n";
	StringVal* error_type	= 0;
	StringVal* error_descr	= 0;


	// Total count of all chunks is same as
	// size of vector array

	chunk_v			= raw_chunks->chunks();
	total_chunk_count	= chunk_v->size();

	#ifdef ICAP_DEBUG
	cout << dbg_icap << " :: total_chunk_count :: " << total_chunk_count << "\n";
	#endif

	//
	// Walk thru each CHUNK in order to calculate the
	// total size of all chunks combined 'total_body_len'
	//

	for ( i = 0; i < total_chunk_count; i++ )
	{
		encap_chunk = chunk_v->at(i);

		chunk_len	= encap_chunk->chunk_size();
		total_body_len += chunk_len; 

	} // end for-loop


	//
	// Compare 'total_body_len' to 'http_content_length'
	//

	if ( (total_body_len != (unsigned int)http_content_length) &&
	     (http_content_length != -1 ) )
	{	
		// If the HTTP Body is not chunked, then we should be able to compare
		// the 'total_body_len' we calculated against the 'http_content_length'
		// we extracted from the HTTP Header.  If the two values do not match,
		// then generate a weird...
		//
		// EXCEPT if the 'http_content_length' is equal to '-1' (unknown),
		// which is the case when the ICAP packet contains only the HTTP Body
		// and not the Header.  Therefore, if '-1' then do not generate error.
		//
		// Let's print the HTTP headers as part of the ICAP_CHUNK_WEIRD event. 
		// Perhaps we could do trending to see who/why/what/when/where this
		// happens.

		StringVal* hdrs_reassembled = proc_http_reassemble_headers(http_hdrs, is_orig);

		BifEvent::generate_icap_chunk_weird
		(
			connection()->bro_analyzer(),
			connection()->bro_analyzer()->Conn(),
			is_orig,
			http_content_length,
			total_body_len,
			hdrs_reassembled,
			hdrs_reassembled->Len()
		);
	}


	//
	// Allocate local buffer for Body
	//

	total_body_ptr	= new unsigned char[total_body_len];
	memset(total_body_ptr, 0x00, total_body_len);


	//
	// Walk thru each CHUNK field in order to copy
	// each chunk sequentially into a single buffer 'total_body_ptr'
	//

	unsigned char* start_ptr	= total_body_ptr;
	const unsigned char* end_ptr	= start_ptr + total_body_len;

	for ( i = 0; i < total_chunk_count; i++ )
	{
		encap_chunk = chunk_v->at(i);

		chunk_ptr = encap_chunk->chunk_data_field()->data_str().data();
		chunk_len = encap_chunk->chunk_size();

		//
		// Safe memcpy:
		// Append CHUNK field into single buffer
		//

		if ( (start_ptr + chunk_len) <= end_ptr )
		{
			memcpy(start_ptr, chunk_ptr, chunk_len);
			start_ptr += chunk_len;
		}
		else {
			//
			// We should have calculated the buffer size correctly, so if we
			// do not have enough space to append the CHUNK, then
			// something unexpected happened, so generate ICAP ERROR event.
			//
			error_type  = new StringVal(error_type_ptr);
			error_descr = 
				new StringVal("Not enough buffer space for chunks.\n");
			BifEvent::generate_icap_error
			(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig,
				error_type,
				error_descr
			);
		}

	} // end for-loop


	// Create StringVal from 'total_body_ptr'
	body_reassembled = new StringVal((int)total_body_len, (const char*)total_body_ptr);
	delete[] total_body_ptr;


	return body_reassembled;

   // proc_http_reassemble_body()
%}


function proc_http_invoke_analyzer_submit_all_headers
(
	http_hdrs		: ICAP_Encapsulated_Http_Headers,
	http_is_orig		: bool
								) : bool
%{
	#ifdef ICAP_DEBUG
	const char* dbg_icap = "DEBUG <icap_analyzer_http.pac> proc_http_invoke_analyzer_submit_all_headers";
	cout << dbg_icap << "\n";
	cout << dbg_icap << " :: http_is_orig :: " << http_is_orig << "\n";
	#endif

	ICAP_Encapsulated_Http_Header* encap_hdr = 0;
	vector<ICAP_Encapsulated_Http_Header *> * hdr_v = 0;

	unsigned char*	hdr_ptr		= 0;
	unsigned char	null[1]		= {0x00};

	unsigned int	hdr_len		= 0;
	unsigned int	total_hdr_count	= 0;
	unsigned int	i = 0;

	// Total count of all headers is same as
	// size of vector array

	total_hdr_count	= http_hdrs->size();
	hdr_v		= http_hdrs->val();

	#ifdef ICAP_DEBUG
	cout << dbg_icap << " :: total_hdr_count :: " << total_hdr_count << "\n";
	#endif

	//
	// Submit each HTTP Request Header field one-by-one
	//

	for ( i = 0; i < total_hdr_count; i++ )
	{
		encap_hdr	= hdr_v->at(i);

		hdr_ptr		= encap_hdr->hdr().data();
		hdr_len		= encap_hdr->hdr().length();

		//
		// Invoke HTTP Protocol Analyzer
		//

		h->DeliverStream(hdr_len, hdr_ptr, http_is_orig);

	} // end for-loop


	//
	// End of Headers
	//
	// Submit a zero-length field to indicate "end of headers" because
	// 'HTTP_Analyzer::DeliverStream()' calls 'HTTP_Entity::Deliver()'
	// which calls 'MIME_Entity::Deliver()' which looks for a zero-length 
	// header in order to (a) determine the header section has ended and
	// (b) expect the HTTP (or MIME) Body next.
	//

	hdr_ptr		= (unsigned char*)&null;
	hdr_len		= 0;

	h->DeliverStream(hdr_len, hdr_ptr, http_is_orig);


	return true;

   // proc_http_invoke_analyzer_submit_all_headers()
%}


function proc_http_invoke_analyzer_submit_body
(
	http_raw_chunks			: ICAP_Chunks,
	http_hdrs			: ICAP_Encapsulated_Http_Headers,
	http_transfer_encoding_chunked	: bool,
	http_content_length		: int,
	http_is_orig			: bool
								) : bool
%{
	#ifdef ICAP_DEBUG
	const char* dbg_icap = "DEBUG <icap_analyzer_http.pac> proc_http_invoke_analyzer_submit_body";
	cout << dbg_icap << "\n";
	cout << dbg_icap << " :: http_is_orig :: " << http_is_orig << "\n";
	#endif

	ICAP_Chunk* encap_chunk = 0;
	vector<ICAP_Chunk *> * chunk_v = 0;

	StringVal*	http_body	= 0;

	unsigned char*	chunk_ptr	= 0;
	unsigned char*	size_ptr	= 0;
	unsigned char	null[1]		= {0x00};

	unsigned int chunk_len		= 0;
	unsigned int size_len		= 0;
	unsigned int total_chunk_count	= 0;
	unsigned int i = 0;

	//
	// Submit the HTTP Request Body
	//

	if ( http_transfer_encoding_chunked )
	{
		// Total count of all chunks is same as
		// size of vector array

		chunk_v			= http_raw_chunks->chunks();
		total_chunk_count	= chunk_v->size();

		//
		// Submit each Chunk field one-by-one
		//

		for ( i = 0; i < total_chunk_count; i++ )
		{
			encap_chunk = chunk_v->at(i);

			size_ptr = encap_chunk->chunk_size_field()->size_str().data();
			size_len = encap_chunk->chunk_size_field()->size_str().length();

			chunk_ptr = encap_chunk->chunk_data_field()->data_str().data();
			chunk_len = encap_chunk->chunk_size();


			// Invoke HTTP Protocol Analyzer

			h->DeliverStream(size_len,  size_ptr,  http_is_orig);
			h->DeliverStream(chunk_len, chunk_ptr, http_is_orig);


			//
			// End of Chunk
			//
			// Submit a zero-length field to represent the CRLF trailing the 
			// <chunk_data> field because 'HTTP_Analyzer::DeliverStream()' calls 					// 'HTTP_Entity::Deliver()' which looks for a zero-length field to
			// know when to expect the next <chunk_size> field.
			//

			chunk_ptr = (unsigned char*)&null;
			chunk_len = 0;

			h->DeliverStream(chunk_len, chunk_ptr, http_is_orig);

		} // end for-loop
	}
	else
	{
		//
		// Unchunk HTTP Body
		//

		http_body = proc_http_reassemble_body
		(
			http_raw_chunks,
			http_hdrs,
			http_transfer_encoding_chunked,
			http_content_length,
			http_is_orig
		);
		if ( ! http_body ) { return false; }


		// Invoke HTTP Protocol Analyzer

		h->DeliverStream(http_body->Len(), http_body->Bytes(), http_is_orig);
		delete http_body;
	}


	return true;

   // proc_http_invoke_analyzer_submit_body()
%}


function proc_http_invoke_analyzer
(
	http_req_hdrs			: ICAP_Encapsulated_Http_Headers,
	http_req_body			: ICAP_Chunks,
	http_rsp_hdrs			: ICAP_Encapsulated_Http_Headers,
	http_rsp_body			: ICAP_Chunks,
	http_transfer_encoding_chunked	: bool,
	http_content_length		: int,
	icap_body_type			: int,
	is_orig				: bool
								) : bool
%{
	#ifdef ICAP_DEBUG
	const char* dbg_icap = "DEBUG <icap_analyzer_http.pac> proc_http_invoke_analyzer";
	cout << dbg_icap << "\n";
	cout << dbg_icap << " :: is_orig :: " << is_orig << "\n";
	#endif

	// Global var 'h' is declared within the ICAP_Flow class

	h = analyzer::ICAP::ICAP_Analyzer::HttpAnalyzer(connection()->bro_analyzer()->Conn());


	//
	// HTTP Request Headers (a)
	//

	if (	(icap_body_type == BODY_TYPE_ACD)	||
		(icap_body_type == BODY_TYPE_AC)	||
		(icap_body_type == BODY_TYPE_AB)	||
		(icap_body_type == BODY_TYPE_A)	   )
	{
		proc_http_invoke_analyzer_submit_all_headers
		(
			http_req_hdrs,
			true
		);
	}


	//
	// HTTP Request Body (b)
	//

	if (	(icap_body_type == BODY_TYPE_AB)	||
		(icap_body_type == BODY_TYPE_B)	   )
	{
		proc_http_invoke_analyzer_submit_body
		(
			http_req_body,
			http_req_hdrs,
			http_transfer_encoding_chunked,
			http_content_length,
			true
		);
	}


	//
	// HTTP Reply Headers (c)
	//

	if (	(icap_body_type == BODY_TYPE_ACD)	||
		(icap_body_type == BODY_TYPE_AC)	||
		(icap_body_type == BODY_TYPE_CD)	   )
	{
		proc_http_invoke_analyzer_submit_all_headers
		(
			http_rsp_hdrs,
			false
		);
	}


	//
	// HTTP Reply Body (d)
	//

	if (	(icap_body_type == BODY_TYPE_ACD)	||
		(icap_body_type == BODY_TYPE_CD)	||
		(icap_body_type == BODY_TYPE_D)		   )
	{
		proc_http_invoke_analyzer_submit_body
		(
			http_rsp_body,
			http_rsp_hdrs,
			http_transfer_encoding_chunked,
			http_content_length,
			false
		);
	}


	//
	// Done... Tell the Protocol Analyzer that the HTTP transaction
	// 	   is complete.
	//

	h->Done();


	return true;

   // proc_http_invoke_analyzer()
%}


   # end refine flow ICAP_Flow
};


# end icap-analyzer-http.pac
