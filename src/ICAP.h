//
// File: ICAP.h
// Date: 20161024
//
// Bro Internet Content Adaptation Protocol (ICAP) Analyzer.
//
// Copyright 2016 The MITRE Corporation.  All rights reserved.
// Approved for public release.  Distribution unlimited.  Case number 16-3871.
//

#ifndef ANALYZER_PROTOCOL_ICAP_ICAP_H
#define ANALYZER_PROTOCOL_ICAP_ICAP_H

#include "icap_pac.h"
#include "events.bif.h"
#include "analyzer/protocol/tcp/TCP.h"
#include "analyzer/protocol/http/HTTP.h"


namespace binpac { namespace ICAP { class ICAP_Conn; } }

namespace analyzer { namespace ICAP {

class ICAP_Analyzer

: public tcp::TCP_ApplicationAnalyzer {

public:
	ICAP_Analyzer(Connection* conn);
	virtual ~ICAP_Analyzer();

	// Overriden from Analyzer.
	virtual void Done();
	
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(uint64 seq, int len, bool orig);

	// Overriden from tcp::TCP_ApplicationAnalyzer.
	virtual void EndpointEOF(bool is_orig);
	

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new ICAP_Analyzer(conn); }

	// Include the HTTP analyzer in order to parse
	// HTTP messages encapsulated within the ICAP payload.
	static analyzer::Analyzer* HttpAnalyzer(Connection* conn)
		{ return new analyzer::http::HTTP_Analyzer(conn); }

protected:
	binpac::ICAP::ICAP_Conn* interp;
	
	bool had_gap;
	
};

} } // namespace analyzer::* 

#endif
