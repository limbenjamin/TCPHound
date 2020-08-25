#include "stdafx.h"     // Precompiled headers

#include <boost/property_tree/json_parser.hpp>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#include "libcurl/x64/curl.h"
#pragma comment(lib, "libcurl/x64/libcurl_a.lib")
#pragma comment(lib, "libcurl/x86/libcurl_a.lib")

size_t CurlWrite_CallbackFunc_StdString(void *contents, size_t size, size_t nmemb, std::string *s)
{
	size_t newLength = size*nmemb;
	size_t oldLength = s->size();
	try
	{
		s->resize(oldLength + newLength);
	}
	catch (std::bad_alloc &e)
	{
		//handle memory problem
		return 0;
	}

	std::copy((char*)contents, (char*)contents + newLength, s->begin() + oldLength);
	return size*nmemb;
}

int GetASInfo(char *ip, char *asStrChar)
{
	char fullURL[80];
	strcpy(fullURL, "https://limbenjamin.com/whois.php?ip=");
	strcat(fullURL, ip);

	std::string response;
	std::string asString;
	CURL *curl = curl_easy_init();

	if (curl) {
		CURLcode res;
		curl_easy_setopt(curl, CURLOPT_URL, fullURL);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWrite_CallbackFunc_StdString);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
		res = curl_easy_perform(curl);
		curl_easy_cleanup(curl);
	}

	//std::string response = "{\"as\":\"AS36351 SoftLayer Technologies Inc.\",\"city\":\"Dallas\",\"country\":\"United States\",\"countryCode\":\"US\"}";
	std::istringstream is(response);

	try {
		boost::property_tree::ptree pt2;
		boost::property_tree::read_json(is, pt2);
		asString = pt2.get<std::string>("as");
	}
	catch (boost::exception const&  ex) { //No as field in JSON or response not JSON
		asString = "Unable to retrieve AS info";
	}

	std::string asStringStr(asString.begin(), asString.end());
	std::strcpy(asStrChar, asStringStr.c_str());


	return 0;
}

