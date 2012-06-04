#include "Config.h"

#include "ParseSection.h"
#include "utils.h"

#include <iostream>
#include <fstream>
#include <boost/lexical_cast.hpp>

// Fees are in XNS raw.
#define	DEFAULT_FEE_CREATE				1000
#define	DEFAULT_FEE_DEFAULT				100

#define CONFIG_FILE_NAME				SYSTEM_NAME "d.cfg"	// newcoind.cfg
#define SECTION_PEER_IP					"peer_ip"
#define SECTION_PEER_PORT				"peer_port"
#define SECTION_RPC_IP					"rpc_ip"
#define SECTION_RPC_PORT				"rpc_port"
#define SECTION_VALIDATION_PASSWORD		"validation_password"
#define SECTION_VALIDATION_KEY			"validation_key"
#define SECTION_PEER_SSL_CIPHER_LIST	"peer_ssl_cipher_list"
#define SECTION_PEER_SCAN_INTERVAL_MIN	"peer_scan_interval_min"
#define SECTION_PEER_START_MAX			"peer_start_max"
#define	SECTION_PEER_CONNECT_LOW_WATER	"peer_connect_low_water"
#define SECTION_NETWORK_QUORUM			"network_quorum"
#define SECTION_VALIDATION_QUORUM		"validation_quorum"
#define SECTION_FEE_CREATE				"fee_create"
#define SECTION_FEE_DEFAULT				"fee_default"
#define SECTION_ACCOUNT_PROBE_MAX		"account_probe_max"

Config theConfig;

Config::Config()
{
	VERSION					= 1;

	NETWORK_START_TIME		= 1319844908;

	PEER_PORT				= SYSTEM_PEER_PORT;
	RPC_PORT				= 5001;
	NUMBER_CONNECTIONS		= 30;

	// a new ledger every minute
	LEDGER_SECONDS			= 60;

	RPC_USER				= "admin";
	RPC_PASSWORD			= "pass";

	DATA_DIR				= "db/";

	PEER_SSL_CIPHER_LIST	= DEFAULT_PEER_SSL_CIPHER_LIST;
	PEER_SCAN_INTERVAL_MIN	= DEFAULT_PEER_SCAN_INTERVAL_MIN;

	PEER_START_MAX			= DEFAULT_PEER_START_MAX;
	PEER_CONNECT_LOW_WATER	= DEFAULT_PEER_CONNECT_LOW_WATER;

	TRANSACTION_FEE_BASE	= 1000;

	NETWORK_QUORUM			= 0;	// Don't need to see other nodes
	VALIDATION_QUORUM		= 1;	// Only need one node to vouch

	FEE_CREATE				= DEFAULT_FEE_CREATE;
	FEE_DEFAULT				= DEFAULT_FEE_DEFAULT;

	ACCOUNT_PROBE_MAX		= 10;
}

void Config::load()
{
	std::ifstream	ifsConfig(CONFIG_FILE_NAME, std::ios::in);

	if (!ifsConfig)
	{
		std::cerr << "Failed to open '" CONFIG_FILE_NAME "'." << std::endl;
	}
	else
	{
		std::string	strConfigFile;

		strConfigFile.assign((std::istreambuf_iterator<char>(ifsConfig)),
			std::istreambuf_iterator<char>());

		if (ifsConfig.bad())
		{
			std::cerr << "Failed to read '" CONFIG_FILE_NAME "'." << std::endl;
		}
		else
		{
			section		secConfig	= ParseSection(strConfigFile, true);
			std::string	strTemp;

			(void) sectionSingleB(secConfig, SECTION_PEER_IP, PEER_IP);

			if (sectionSingleB(secConfig, SECTION_PEER_PORT, strTemp))
				PEER_PORT = boost::lexical_cast<int>(strTemp);

			(void) sectionSingleB(secConfig, SECTION_RPC_IP, RPC_IP);

			if (sectionSingleB(secConfig, SECTION_RPC_PORT, strTemp))
				RPC_PORT = boost::lexical_cast<int>(strTemp);

			(void) sectionSingleB(secConfig, SECTION_VALIDATION_PASSWORD, VALIDATION_PASSWORD);
			(void) sectionSingleB(secConfig, SECTION_VALIDATION_KEY, VALIDATION_KEY);

			(void) sectionSingleB(secConfig, SECTION_PEER_SSL_CIPHER_LIST, PEER_SSL_CIPHER_LIST);
			if (sectionSingleB(secConfig, SECTION_PEER_SCAN_INTERVAL_MIN, strTemp))
				PEER_SCAN_INTERVAL_MIN = MAX(60, boost::lexical_cast<int>(strTemp));

			if (sectionSingleB(secConfig, SECTION_PEER_START_MAX, strTemp))
				PEER_START_MAX = MAX(1, boost::lexical_cast<int>(strTemp));

			if (sectionSingleB(secConfig, SECTION_PEER_CONNECT_LOW_WATER, strTemp))
				PEER_CONNECT_LOW_WATER = MAX(1, boost::lexical_cast<int>(strTemp));

			if (sectionSingleB(secConfig, SECTION_NETWORK_QUORUM, strTemp))
				NETWORK_QUORUM = MAX(0, boost::lexical_cast<int>(strTemp));

			if (sectionSingleB(secConfig, SECTION_VALIDATION_QUORUM, strTemp))
				VALIDATION_QUORUM = MAX(0, boost::lexical_cast<int>(strTemp));

			if (sectionSingleB(secConfig, SECTION_FEE_CREATE, strTemp))
				FEE_CREATE = boost::lexical_cast<int>(strTemp);

			if (sectionSingleB(secConfig, SECTION_FEE_DEFAULT, strTemp))
				FEE_DEFAULT = boost::lexical_cast<int>(strTemp);

			if (sectionSingleB(secConfig, SECTION_ACCOUNT_PROBE_MAX, strTemp))
				ACCOUNT_PROBE_MAX = boost::lexical_cast<int>(strTemp);
		}
	}
}

// vim:ts=4
