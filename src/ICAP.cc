//
// File: ICAP.cc
// Date: 20161024
//
// Bro Internet Content Adaptation Protocol (ICAP) Analyzer.
//
// Copyright 2016 The MITRE Corporation.  All rights reserved.
// Approved for public release.  Distribution unlimited.  Case number 16-3871.
//

#include "ICAP.h"
#include "analyzer/protocol/tcp/TCP_Reassembler.h"
#include "Reporter.h"

using namespace analyzer::ICAP;

ICAP_Analyzer::ICAP_Analyzer(Connection* c)

: tcp::TCP_ApplicationAnalyzer("ICAP", c)

	{
	interp = new binpac::ICAP::ICAP_Conn(this);
	had_gap = false;
	
	}

ICAP_Analyzer::~ICAP_Analyzer()
	{
	delete interp;
	}

void ICAP_Analyzer::Done()
	{
	
	tcp::TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	
	}

void ICAP_Analyzer::EndpointEOF(bool is_orig)
	{
	tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	interp->FlowEOF(is_orig);
	}

void ICAP_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	assert(TCP());
	if ( TCP()->IsPartial() )
		return;

	if ( had_gap )
		// If only one side had a content gap, we could still try to
		// deliver data to the other side if the script layer can handle this.
		return;

	try
		{
		interp->NewData(orig, data, data + len);
		}
	catch ( const binpac::Exception& e )
		{
		ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
		}
	}

void ICAP_Analyzer::Undelivered(uint64 seq, int len, bool orig)
	{
	tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	had_gap = true;
	interp->NewGap(orig, len);
	}
