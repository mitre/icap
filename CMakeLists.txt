# Generated by init-plugin
#
# File: CMakeLists.txt
# Date: 20161024
#
# Bro Internet Content Adaptation Protocol (ICAP) Analyzer
#

#
# Usage: Bro Plugin.
#
# Use this version of CMakeLists.txt when compiling
# the ICAP Analyzer as a Bro Plugin.
#

cmake_minimum_required(VERSION 2.8)

project(Plugin)
include(BroPlugin)

bro_plugin_begin(MITRE ICAP)
	bro_plugin_cc(src/ICAP.cc src/Plugin.cc)
	bro_plugin_bif(src/events.bif)
	bro_plugin_pac(
		src/icap.pac
		src/icap-protocol.pac
		src/icap-analyzer.pac
		src/icap-analyzer-http.pac
		src/icap-analyzer-utils.pac
	)
	bro_plugin_dist_files(README CHANGES COPYING VERSION)
bro_plugin_end()
