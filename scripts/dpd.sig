#
# File: dpd.sig
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

signature dpd_icap_client
{
	ip-proto == tcp
	payload /^(RESPMOD|REQMOD|OPTIONS)/
	tcp-state originator
}

signature dpd_icap_server
{
	ip-proto == tcp
	payload /^ICAP\/[0-9]/
	tcp-state responder
	requires-reverse-signature dpd_icap_client
	enable "icap"
}
