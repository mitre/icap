//
// File: Plugin.cc
// Date: 20161024
//
// Bro Internet Content Adaptation Protocol (ICAP) Analyzer.
//
// Copyright 2016 The MITRE Corporation.  All rights reserved.
// Approved for public release.  Distribution unlimited.  Case number 16-3871.
//

#include "plugin/Plugin.h"

#include "ICAP.h"

namespace plugin {
namespace MITRE_ICAP {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("ICAP",
		             ::analyzer::ICAP::ICAP_Analyzer::InstantiateAnalyzer));

		plugin::Configuration config;
		config.name = "MITRE::ICAP";
		config.description = "Internet Content Adaptation Protocol analyzer";
                config.version.major = 1;
                config.version.minor = 0;
		return config;
 		}
} plugin;

}
}
