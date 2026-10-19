#pragma once

#include <map>
#include <string>
#include <sstream>
#include <optional>
#include <algorithm>
#include <unordered_set>
#include <vector>
#include <Windows.h>

#include <lstate.h>
#include <lualib.h>

#define CPPHTTPLIB_MBEDTLS_SUPPORT
#include <cpp-httplib/httplib.h>

#include <nlohmann/json.hpp>

#include <bcrypt.h>
#include <Utilitys/Log.hpp>
#include <Utilitys/Globals.hpp>
#include <RBX/update.hpp>
#include <RBX/environment/yielding/yielding.hpp>
#include <RBX/environment/env.hpp>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "mbedtls.lib")
#pragma comment(lib, "mbedcrypto.lib")
#pragma comment(lib, "mbedx509.lib")

namespace module::core::environment
{
    enum request_method_t
    {
        H_GET,
        H_HEAD,
        H_POST,
        H_PUT,
        H_DELETE,
        H_OPTIONS,
        H_PATCH
    };

    inline std::map<std::string, request_method_t> request_method_map = {
        { "get",     H_GET     },
        { "head",    H_HEAD    },
        { "post",    H_POST    },
        { "put",     H_PUT     },
        { "delete",  H_DELETE  },
        { "options", H_OPTIONS },
        { "patch",   H_PATCH   }
    };

    inline std::unordered_set<std::string> blocked_domains = {
        "accountinformation.roblox.com", "accountsettings.roblox.com",
        "twostepverification.roblox.com", "trades.roblox.com",
        "billing.roblox.com", "economy.roblox.com", "auth.roblox.com",
        "accountinformation.roproxy.com", "accountsettings.roproxy.com",
        "twostepverification.roproxy.com", "trades.roproxy.com",
        "billing.roproxy.com", "economy.roproxy.com", "auth.roproxy.com",
        "api.ipify.org", "api4.ipify.org", "api6.ipify.org", "api64.ipify.org",
        "api.ipapi.is", "api.ipapi.co", "api.ipapi.com",
        "api.ipinfo.io", "api.ipgeolocation.io", "api.freegeoip.app",
        "api.myip.com", "api.ip.sb", "api.ipwhois.io",
        "api.ipdata.co", "api.ipstack.com", "api.db-ip.com",
        "api.seeip.org", "api.ipregistry.co", "api.abstractapi.com",
        "api.ipbase.com", "api.iplocation.net", "api.ip.nf",
        "api.bigdatacloud.net", "api.techniknews.net", "api.country.is",
        "api.2ip.me", "api.reallyfreegeoip.org",
    };

    struct http_result_t
    {
        bool success = false;
        int status_code = 0;
        std::string body;
        std::string error;
        httplib::Headers headers;
    };

    struct parsed_url_t
    {
        std::string scheme;
        std::string host;
        int port = 0;
        std::string path;
    };

    struct c_http
    {
        static int funcnameinc;

        static bool is_url_blocked(const std::string& url);
        static std::string get_hwid();
        static parsed_url_t parse_url(const std::string& url);
        static http_result_t do_request(request_method_t method, const std::string& url,
            const httplib::Headers& headers, const std::string& body, const std::string& content_type = "");
        static std::string get_status_phrase(int code);

        static int http_get(lua_State* L);
        static int http_post(lua_State* L);
        static int request(lua_State* L);

        static void register_lib(lua_State* L);
    };

    inline c_http http{};
}