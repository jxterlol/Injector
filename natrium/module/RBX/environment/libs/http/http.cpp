#include "http.hpp"
#include <winhttp.h>
#include <Utilitys/Log.hpp>

// static data member declared in http.hpp has to live in exactly one TU,
// otherwise every reference from register_lib dangles at link time
int module::core::environment::c_http::funcnameinc = 0;

bool module::core::environment::c_http::is_url_blocked(const std::string& url)
{
    std::string lower = url;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    for (const auto& domain : blocked_domains)
        if (lower.find(domain) != std::string::npos)
            return true;
    return false;
}

std::string module::core::environment::c_http::get_hwid()
{
    HW_PROFILE_INFO hw_info{};
    std::string clean;

    if (GetCurrentHwProfile(&hw_info))
    {
        std::wstring w_guid(hw_info.szHwProfileGuid);
        std::string guid(w_guid.begin(), w_guid.end());
        for (char c : guid)
        {
            if (c != '{' && c != '}' && c != '-')
                clean += c;
        }
    }

    if (clean.empty())
        clean = ("fallback");

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
        return clean;

    DWORD hash_length = 0;
    DWORD obj_length = 0;
    DWORD bytes_done = 0;

    BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH,
        reinterpret_cast<PUCHAR>(&hash_length), sizeof(hash_length), &bytes_done, 0);
    BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&obj_length), sizeof(obj_length), &bytes_done, 0);

    std::vector<uint8_t> hash_obj(obj_length);
    std::vector<uint8_t> digest(hash_length);

    if (!BCRYPT_SUCCESS(BCryptCreateHash(algorithm, &hash,
        hash_obj.data(), obj_length, nullptr, 0, 0)))
    {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return clean;
    }

    BCryptHashData(hash,
        reinterpret_cast<PUCHAR>(clean.data()),
        static_cast<ULONG>(clean.size()), 0);

    char computer_name[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD name_len = sizeof(computer_name);
    if (GetComputerNameA(computer_name, &name_len))
        BCryptHashData(hash,
            reinterpret_cast<PUCHAR>(computer_name),
            name_len, 0);

    DWORD volume_serial = 0;
    if (GetVolumeInformationA(("C:\\"), nullptr, 0,
        &volume_serial, nullptr, nullptr, nullptr, 0))
        BCryptHashData(hash,
            reinterpret_cast<PUCHAR>(&volume_serial),
            sizeof(volume_serial), 0);

    BCryptFinishHash(hash, digest.data(), hash_length, 0);
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);

    std::string result(hash_length * 2, '\0');
    for (size_t i = 0; i < hash_length; i++)
        std::snprintf(&result[i * 2], 3, ("%02x"), digest[i]);

    return result;
}

module::core::environment::parsed_url_t module::core::environment::c_http::parse_url(const std::string& url)
{
    parsed_url_t p{};

    size_t scheme_end = url.find(("://"));
    if (scheme_end == std::string::npos)
        return p;

    p.scheme = url.substr(0, scheme_end);
    std::transform(p.scheme.begin(), p.scheme.end(), p.scheme.begin(), ::tolower);

    size_t host_start = scheme_end + 3;
    size_t path_start = url.find('/', host_start);
    std::string host_port;

    if (path_start == std::string::npos)
    {
        host_port = url.substr(host_start);
        p.path = ("/");
    }
    else
    {
        host_port = url.substr(host_start, path_start - host_start);
        p.path = url.substr(path_start);
    }

    size_t colon = host_port.find(':');
    if (colon != std::string::npos)
    {
        p.host = host_port.substr(0, colon);

        // hand-rolled instead of std::stoi: a malformed port ("host:abc")
        // used to throw straight out of do_request and kill the game
        const std::string port_text = host_port.substr(colon + 1);
        int parsed_port = 0;
        for (char digit : port_text)
        {
            if (digit < '0' || digit > '9')
            {
                parsed_port = 0;
                break;
            }
            parsed_port = parsed_port * 10 + (digit - '0');
            if (parsed_port > 65535)
            {
                parsed_port = 0;
                break;
            }
        }
        p.port = (parsed_port > 0) ? parsed_port : ((p.scheme == ("https")) ? 443 : 80);
    }
    else
    {
        p.host = host_port;
        p.port = (p.scheme == ("https")) ? 443 : 80;
    }

    return p;
}

// ---- executor request helpers (luarmor support + NUL-safe bodies) ----
namespace
{
    inline bool header_present(const httplib::Headers& headers, const char* key)
    {
        for (const auto& header : headers)
            if (_stricmp(header.first.c_str(), key) == 0)
                return true;
        return false;
    }

    inline void replace_header(httplib::Headers& headers, const char* key, const std::string& value)
    {
        for (auto it = headers.begin(); it != headers.end(); )
        {
            if (_stricmp(it->first.c_str(), key) == 0)
                it = headers.erase(it);
            else
                ++it;
        }
        headers.insert({ key, value });
    }

    inline bool url_is_luarmor(const std::string& url)
    {
        std::string lower = url;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        return lower.find(("luarmor")) != std::string::npos;
    }

    inline std::string clip_for_log(const std::string& text, size_t max_length)
    {
        std::string out;
        out.reserve(max_length + 4);
        const size_t size = (std::min)(text.size(), max_length);
        for (size_t i = 0; i < size; i++)
        {
            const char c = text[i];
            out += (c == '\r' || c == '\n') ? ' ' : c;
        }
        if (text.size() > max_length)
            out += ("...");
        return out;
    }

    inline void log_luarmor_exchange(module::core::environment::request_method_t method, const std::string& url,
        const httplib::Headers& headers, const std::string& body,
        const module::core::environment::http_result_t& result)
    {
        static const char* method_names[] = { "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH" };
        const int method_index = static_cast<int>(method);
        std::string out;
        out += ("[LUARMOR] -> ");
        out += (method_index >= 0 && method_index <= 6) ? method_names[method_index] : "?";
        out += ' ';
        out += url;
        out += '\n';
        for (const auto& header : headers)
        {
            out += ("[LUARMOR]    ");
            out += header.first;
            out += (": ");
            out += clip_for_log(header.second, 400);
            out += '\n';
        }
        if (!body.empty())
        {
            out += ("[LUARMOR]    body: ");
            out += clip_for_log(body, 900);
            out += '\n';
        }
        out += ("[LUARMOR] <- ");
        out += std::to_string(result.status_code);
        if (!result.success && !result.error.empty())
        {
            out += (" ");
            out += result.error;
        }
        out += (" body: ");
        out += clip_for_log(result.body, 900);
        out += '\n';
        LogFile::Write(out.c_str(), static_cast<int>(out.size()));
    }

    // lua_tostring truncates at the first NUL - binary POST bodies need the length
    inline std::string lua_sized_string(lua_State* L, int idx)
    {
        size_t len = 0;
        const char* data = lua_tolstring(L, idx, &len);
        if (!data)
            return std::string();
        return std::string(data, len);
    }

    // luarmor endpoints want the stock Roblox headers; everything else gets ours
    inline void apply_executor_headers(const std::string& url, const std::string& hwid, httplib::Headers& headers)
    {
        if (url_is_luarmor(url))
        {
            replace_header(headers, ("Sodium-Fingerprint"), hwid);
            replace_header(headers, ("clienthwid"), hwid);
            replace_header(headers, ("hwid"), hwid);
            replace_header(headers, ("User-Agent"), ("Roblox/WinInet"));
            return;
        }
        if (!header_present(headers, ("Sodium-Fingerprint")))
            headers.insert({ ("Sodium-Fingerprint"), hwid });
        if (!header_present(headers, ("User-Agent")))
            headers.insert({ ("User-Agent"), ("Sodium/1.6.0") });
    }
}
namespace
{
    // WinHTTP transport helpers. The old cpp-httplib + mbedTLS request path
    // faulted on every request inside Roblox (our /EHa handler turned the AV
    // into "request failed: unknown exception", so loadstring only ever got an
    // error string). WinHTTP is the OS network stack - same one Roblox itself
    // uses - and reports exact GetLastError() codes on failure.
    inline std::string winhttp_error(const char* stage)
    {
        DWORD code = GetLastError();
        return std::string(("winhttp: ")) + stage + (" failed (") + std::to_string(code) + (")");
    }

    inline std::wstring wide_from_utf8(const std::string& s)
    {
        if (s.empty())
            return std::wstring();
        int needed = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
        if (needed <= 0)
            return std::wstring();
        std::wstring w((size_t)needed, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), needed);
        return w;
    }

    inline std::string utf8_from_wide(const std::wstring& w)
    {
        if (w.empty())
            return std::string();
        int needed = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
        if (needed <= 0)
            return std::string();
        std::string s((size_t)needed, '\0');
        WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), s.data(), needed, nullptr, nullptr);
        return s;
    }
}

module::core::environment::http_result_t module::core::environment::c_http::do_request(
    request_method_t method, const std::string& url,
    const httplib::Headers& headers, const std::string& body, const std::string& content_type)
{
    http_result_t result{};

    parsed_url_t p = parse_url(url);
    if (p.host.empty())
    {
        result.error = ("invalid url");
        return result;
    }

    const wchar_t* verb = L"GET";
    switch (method)
    {
    case H_GET:     verb = L"GET"; break;
    case H_HEAD:    verb = L"HEAD"; break;
    case H_POST:    verb = L"POST"; break;
    case H_PUT:     verb = L"PUT"; break;
    case H_DELETE:  verb = L"DELETE"; break;
    case H_OPTIONS: verb = L"OPTIONS"; break;
    case H_PATCH:   verb = L"PATCH"; break;
    default:
        result.error = ("invalid request method");
        return result;
    }

    const std::string ct = content_type.empty() ? ("application/octet-stream") : content_type;
    const bool https = p.scheme == ("https");
    const bool method_sends_body = method == H_POST || method == H_PUT || method == H_DELETE || method == H_PATCH;

    // one user agent per session, taken from our header set (Sodium/1.6.0, or
    // Roblox/WinInet on luarmor endpoints) so it can never be sent twice
    std::wstring wua = L"Sodium/1.6.0";
    std::wstring wheaders;
    bool saw_content_type = false;

    for (const auto& h : headers)
    {
        const std::string& key = h.first;

        if (_stricmp(key.c_str(), ("User-Agent")) == 0)
        {
            wua = wide_from_utf8(h.second);
            continue;
        }

        // WinHTTP owns these; forwarding our own copy desyncs the request
        if (_stricmp(key.c_str(), ("Host")) == 0 ||
            _stricmp(key.c_str(), ("Content-Length")) == 0 ||
            _stricmp(key.c_str(), ("Connection")) == 0 ||
            _stricmp(key.c_str(), ("Transfer-Encoding")) == 0)
            continue;

        if (_stricmp(key.c_str(), ("Content-Type")) == 0)
            saw_content_type = true;

        wheaders += wide_from_utf8(key) + L": " + wide_from_utf8(h.second) + L"\r\n";
    }

    if ((method_sends_body || !body.empty()) && !saw_content_type)
        wheaders += L"Content-Type: " + wide_from_utf8(ct) + L"\r\n";

    auto run = [&]()
        {
            struct ScopedHandle
            {
                HINTERNET handle = nullptr;
                ~ScopedHandle() { if (handle) WinHttpCloseHandle(handle); }
            } session, connection, request;

            session.handle = WinHttpOpen(wua.c_str(), WINHTTP_ACCESS_TYPE_NO_PROXY,
                WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
            if (!session.handle)
            {
                result.error = winhttp_error(("open"));
                return;
            }

            WinHttpSetTimeouts(session.handle, 30000, 30000, 30000, 30000);

            connection.handle = WinHttpConnect(session.handle, wide_from_utf8(p.host).c_str(),
                (INTERNET_PORT)p.port, 0);
            if (!connection.handle)
            {
                result.error = winhttp_error(("connect"));
                return;
            }

            request.handle = WinHttpOpenRequest(connection.handle, verb,
                wide_from_utf8(p.path).c_str(), nullptr, WINHTTP_NO_REFERER,
                WINHTTP_DEFAULT_ACCEPT_TYPES, https ? WINHTTP_FLAG_SECURE : 0);
            if (!request.handle)
            {
                result.error = winhttp_error(("open request"));
                return;
            }

            if (https)
            {
                // parity with the old client: certificate verification off
                DWORD security = 0x00000100 /* ignore unknown CA */
                    | 0x00002000 /* ignore cert date invalid */
                    | 0x00001000 /* ignore cert CN invalid */
                    | 0x00000200 /* ignore cert wrong usage */;
                WinHttpSetOption(request.handle, WINHTTP_OPTION_SECURITY_FLAGS, &security, sizeof(security));
            }

            DWORD redirect_policy = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
            WinHttpSetOption(request.handle, WINHTTP_OPTION_REDIRECT_POLICY, &redirect_policy, sizeof(redirect_policy));

            // Some hosts (Cloudflare fronting api.eclipsehub.xyz, etc.) send an
            // optional TLS CertificateRequest (mTLS / bot checks). Browsers and
            // curl/schannel just continue with an empty Certificate message,
            // but WinHTTP fails WinHttpSendRequest/ReceiveResponse with 12044
            // (ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED) unless we explicitly tell
            // it we have no client cert and retry.
            auto send_once = [&]() -> BOOL
                {
                    SetLastError(0);
                    return WinHttpSendRequest(request.handle,
                        wheaders.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : wheaders.c_str(),
                        (DWORD)wheaders.size(),
                        body.empty() ? WINHTTP_NO_REQUEST_DATA : (LPVOID)body.data(),
                        (DWORD)body.size(), (DWORD)body.size(), 0);
                };

            if (!send_once())
            {
                if (GetLastError() == 12044 /* ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED */)
                {
                    WinHttpSetOption(request.handle, WINHTTP_OPTION_CLIENT_CERT_CONTEXT,
                        WINHTTP_NO_CLIENT_CERT_CONTEXT, 0);
                    if (!send_once())
                    {
                        result.error = winhttp_error(("send"));
                        return;
                    }
                }
                else
                {
                    result.error = winhttp_error(("send"));
                    return;
                }
            }

            if (!WinHttpReceiveResponse(request.handle, nullptr))
            {
                if (GetLastError() == 12044 /* server asked for client cert on receive */)
                {
                    WinHttpSetOption(request.handle, WINHTTP_OPTION_CLIENT_CERT_CONTEXT,
                        WINHTTP_NO_CLIENT_CERT_CONTEXT, 0);
                    // Receive path requires a full resend before receiving again.
                    if (!send_once() || !WinHttpReceiveResponse(request.handle, nullptr))
                    {
                        result.error = winhttp_error(("receive"));
                        return;
                    }
                }
                else
                {
                    result.error = winhttp_error(("receive"));
                    return;
                }
            }

            DWORD status = 0;
            DWORD status_size = sizeof(status);
            if (WinHttpQueryHeaders(request.handle,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size, WINHTTP_NO_HEADER_INDEX))
                result.status_code = (int)status;

            // raw response headers -> result.headers (request() exposes these
            // as Headers / Cookies, incl. Set-Cookie parsing)
            DWORD raw_size = 0;
            WinHttpQueryHeaders(request.handle, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &raw_size, WINHTTP_NO_HEADER_INDEX);
            if (raw_size >= sizeof(wchar_t))
            {
                std::wstring raw(raw_size / sizeof(wchar_t), L'\0');
                if (WinHttpQueryHeaders(request.handle, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                    WINHTTP_HEADER_NAME_BY_INDEX, raw.data(), &raw_size, WINHTTP_NO_HEADER_INDEX))
                {
                    size_t terminator = raw.find(L'\0');
                    if (terminator != std::wstring::npos)
                        raw.resize(terminator);

                    size_t start = 0;
                    while (start < raw.size())
                    {
                        size_t end = raw.find(L"\r\n", start);
                        if (end == std::wstring::npos)
                            end = raw.size();
                        std::wstring line = raw.substr(start, end - start);
                        start = end + 2;

                        size_t colon = line.find(L':');
                        if (colon == std::wstring::npos || colon == 0)
                            continue;

                        size_t value_start = colon + 1;
                        while (value_start < line.size() && (line[value_start] == L' ' || line[value_start] == L'\t'))
                            ++value_start;

                        result.headers.insert({ utf8_from_wide(line.substr(0, colon)),
                                                utf8_from_wide(line.substr(value_start)) });
                    }
                }
            }

            for (;;)
            {
                DWORD available = 0;
                if (!WinHttpQueryDataAvailable(request.handle, &available))
                {
                    result.error = winhttp_error(("query data"));
                    return;
                }
                if (available == 0)
                    break;

                std::vector<char> chunk(available);
                DWORD read = 0;
                if (!WinHttpReadData(request.handle, chunk.data(), available, &read))
                {
                    result.error = winhttp_error(("read data"));
                    return;
                }
                if (read == 0)
                    break;

                result.body.append(chunk.data(), read);
            }

            result.success = true;
        };

    try
    {
        run();
    }
    catch (const std::exception& ex)
    {
        result.success = false;
        result.error = std::string(("request failed: ")) + ex.what();
    }
    catch (...)
    {
        result.success = false;
        result.error = ("request failed: unknown exception");
    }

    if (url_is_luarmor(url))
        log_luarmor_exchange(method, url, headers, body, result);

    return result;
}

std::string module::core::environment::c_http::get_status_phrase(int code)
{
    switch (code)
    {
    case 100: return ("Continue");
    case 101: return ("Switching Protocols");
    case 102: return ("Processing");
    case 103: return ("Early Hints");
    case 200: return ("OK");
    case 201: return ("Created");
    case 202: return ("Accepted");
    case 203: return ("Non-Authoritative Information");
    case 204: return ("No Content");
    case 205: return ("Reset Content");
    case 206: return ("Partial Content");
    case 207: return ("Multi-Status");
    case 208: return ("Already Reported");
    case 226: return ("IM Used");
    case 300: return ("Multiple Choices");
    case 301: return ("Moved Permanently");
    case 302: return ("Found");
    case 303: return ("See Other");
    case 304: return ("Not Modified");
    case 305: return ("Use Proxy");
    case 307: return ("Temporary Redirect");
    case 308: return ("Permanent Redirect");
    case 400: return ("Bad Request");
    case 401: return ("Unauthorized");
    case 402: return ("Payment Required");
    case 403: return ("Forbidden");
    case 404: return ("Not Found");
    case 405: return ("Method Not Allowed");
    case 406: return ("Not Acceptable");
    case 407: return ("Proxy Authentication Required");
    case 408: return ("Request Timeout");
    case 409: return ("Conflict");
    case 410: return ("Gone");
    case 411: return ("Length Required");
    case 412: return ("Precondition Failed");
    case 413: return ("Payload Too Large");
    case 414: return ("URI Too Long");
    case 415: return ("Unsupported Media Type");
    case 416: return ("Range Not Satisfiable");
    case 417: return ("Expectation Failed");
    case 418: return ("I'm a teapot");
    case 422: return ("Unprocessable Entity");
    case 423: return ("Locked");
    case 424: return ("Failed Dependency");
    case 426: return ("Upgrade Required");
    case 428: return ("Precondition Required");
    case 429: return ("Too Many Requests");
    case 431: return ("Request Header Fields Too Large");
    case 451: return ("Unavailable For Legal Reasons");
    case 500: return ("Internal Server Error");
    case 501: return ("Not Implemented");
    case 502: return ("Bad Gateway");
    case 503: return ("Service Unavailable");
    case 504: return ("Gateway Time-out");
    case 505: return ("HTTP Version Not Supported");
    case 506: return ("Variant Also Negotiates");
    case 507: return ("Insufficient Storage");
    case 508: return ("Loop Detected");
    case 510: return ("Not Extended");
    case 511: return ("Network Authentication Required");
    default:  return std::string();
    }
}

inline int module::core::environment::c_http::http_get(lua_State* L)
{
    std::string url;

    if (!lua_isstring(L, 1))
    {
        luaL_checkstring(L, 2);
        url = lua_tostring(L, 2);
    }
    else
    {
        url = lua_tostring(L, 1);
    }

    if (url.find(("http://")) != 0 && url.find(("https://")) != 0)
    {
        luaL_argerror(L, 2, ("invalid protocol (expected 'http' or 'https')"));
        return 0;
    }

    if (is_url_blocked(url))
    {
        luaL_error(L, ("url is blocked"));
        return 0;
    }

    std::string game_id;
    lua_getglobal(L, ("game"));
    if (lua_istable(L, -1))
    {
        lua_getfield(L, -1, ("GameId"));
        if (lua_isstring(L, -1))
            game_id = lua_tostring(L, -1);
        lua_pop(L, 1);
    }
    lua_pop(L, 1);

    std::string place_id;
    lua_getglobal(L, ("game"));
    if (lua_istable(L, -1))
    {
        lua_getfield(L, -1, ("PlaceId"));
        if (lua_isstring(L, -1))
            place_id = lua_tostring(L, -1);
        lua_pop(L, 1);
    }
    lua_pop(L, 1);

    std::string hwid = get_hwid();

    using Json = nlohmann::json;
    httplib::Headers headers;
    Json session_id_json;

    session_id_json[("GameId")] = game_id;
    session_id_json[("PlaceId")] = place_id;

    headers.insert({ ("User-Agent"), ("Sodium/1.6.0") });
    headers.insert({ ("Roblox-Session-Id"), session_id_json.dump() });
    headers.insert({ ("Roblox-Place-Id"), place_id });
    headers.insert({ ("Roblox-Game-Id"), game_id });
    headers.insert({ ("Exploit-Identifier"), ("Sodium") });
    headers.insert({ ("Exploit-Guid"), hwid });
    headers.insert({ ("Sodium-Fingerprint"), hwid });
    headers.insert({ ("Accept"), ("*/*") });
    apply_executor_headers(url, hwid, headers);

    return Yielding::YieldExecution(L, [url, headers]() -> std::function<int(lua_State*)>
        {
            http_result_t result = do_request(H_GET, url, headers, "");

            return [result](lua_State* L) -> int
                {
                    if (!result.success)
                    {
                        // surface the real reason in Roblox output - a bare
                        // error string fed to loadstring() only ever shows up
                        // as "attempt to call a nil value" with no context
                        Roblox::Print(3, ("[HttpGet] %s"),
                            (("http_get failed: ") + result.error).c_str());
                        lua_pushstring(L, (("http_get failed: ") + result.error).c_str());
                        return 1;
                    }

                    if (result.status_code != 200)
                    {
                        std::stringstream err;
                        err << ("http_get returned status: ") << result.status_code;
                        Roblox::Print(3, ("[HttpGet] %s"), err.str().c_str());
                        lua_pushstring(L, err.str().c_str());
                        return 1;
                    }

                    lua_pushlstring(L, result.body.data(), result.body.size());
                    return 1;
                };
        });
}

inline int module::core::environment::c_http::request(lua_State* L)
{
    luaL_checktype(L, 1, LUA_TTABLE);

    // Keep the always-returns-a-table contract even when the thread can't
    // yield (YieldExecution would otherwise return a bare error string,
    // which again turns request({...}).Body into nil).
    if (!L || !L->userdata || !L->userdata->shared)
    {
        lua_newtable(L);
        lua_pushboolean(L, 0);
        lua_setfield(L, -2, ("Success"));
        lua_pushinteger(L, 0);
        lua_setfield(L, -2, ("StatusCode"));
        lua_pushstring(L, "");
        lua_setfield(L, -2, ("StatusMessage"));
        lua_newtable(L);
        lua_setfield(L, -2, ("Headers"));
        lua_newtable(L);
        lua_setfield(L, -2, ("Cookies"));
        lua_pushstring(L, "");
        lua_setfield(L, -2, ("Body"));
        lua_pushstring(L, "yield unavailable: thread extra space missing");
        lua_setfield(L, -2, ("Error"));
        return 1;
    }

    lua_getfield(L, 1, ("Url"));
    if (!lua_isstring(L, -1))
        luaL_error(L, ("missing or invalid 'Url'"));

    std::string url = lua_tostring(L, -1);
    lua_pop(L, 1);

    if (url.find(("http://")) != 0 && url.find(("https://")) != 0)
    {
        luaL_error(L, ("invalid protocol (expected 'http' or 'https')"));
        return 0;
    }

    if (is_url_blocked(url))
    {
        luaL_error(L, ("url is blocked"));
        return 0;
    }

    auto method = H_GET;
    lua_getfield(L, 1, ("Method"));
    if (lua_isstring(L, -1))
    {
        std::string method_str = lua_tostring(L, -1);
        std::transform(method_str.begin(), method_str.end(), method_str.begin(), ::tolower);
        if (!request_method_map.count(method_str))
            luaL_error(L, ("invalid request method: '%s'"), method_str.c_str());

        method = request_method_map[method_str];
    }
    lua_pop(L, 1);

    httplib::Headers headers;
    lua_getfield(L, 1, ("Headers"));
    if (lua_istable(L, -1))
    {
        lua_pushnil(L);
        while (lua_next(L, -2))
        {
            if (!lua_isstring(L, -2) || !lua_isstring(L, -1))
                luaL_error(L, ("'Headers' must have string keys/values"));

            std::string key = lua_tostring(L, -2);
            if (_stricmp(key.c_str(), ("Content-Length")) == 0)
                luaL_error(L, ("'Content-Length' cannot be overwritten"));

            headers.insert({ key, lua_tostring(L, -1) });
            lua_pop(L, 1);
        }
    }
    lua_pop(L, 1);

    std::string cookie_header;
    lua_getfield(L, 1, ("Cookies"));
    if (lua_istable(L, -1))
    {
        lua_pushnil(L);
        while (lua_next(L, -2))
        {
            if (!lua_isstring(L, -2) || !lua_isstring(L, -1))
                luaL_error(L, ("'Cookies' must have string keys/values"));

            if (!cookie_header.empty()) cookie_header += ("; ");
            cookie_header += lua_tostring(L, -2);
            cookie_header += ("=");
            cookie_header += lua_tostring(L, -1);
            lua_pop(L, 1);
        }
    }
    lua_pop(L, 1);

    if (!cookie_header.empty())
        headers.insert({ ("Cookie"), cookie_header });

    std::string body;
    lua_getfield(L, 1, ("Body"));
    if (lua_isstring(L, -1))
    {
        if (method == H_GET || method == H_HEAD)
            luaL_error(L, ("'Body' is not allowed for GET/HEAD requests"));

        body = lua_sized_string(L, -1);
    }
    lua_pop(L, 1);

    std::string game_id;
    lua_getglobal(L, ("game"));
    if (lua_istable(L, -1))
    {
        lua_getfield(L, -1, ("GameId"));
        if (lua_isstring(L, -1))
            game_id = lua_tostring(L, -1);
        lua_pop(L, 1);
    }
    lua_pop(L, 1);

    std::string place_id;
    lua_getglobal(L, ("game"));
    if (lua_istable(L, -1))
    {
        lua_getfield(L, -1, ("PlaceId"));
        if (lua_isstring(L, -1))
            place_id = lua_tostring(L, -1);
        lua_pop(L, 1);
    }
    lua_pop(L, 1);

    std::string hwid = get_hwid();

    nlohmann::json session_id_json;
    session_id_json[("GameId")] = game_id;
    session_id_json[("PlaceId")] = place_id;

    auto has_header = [&](const std::string& key) -> bool
        {
            for (auto& h : headers)
                if (_stricmp(h.first.c_str(), key.c_str()) == 0)
                    return true;
            return false;
        };

    if (!has_header(("User-Agent")))
        headers.insert({ ("User-Agent"), ("Sodium/1.6.0") });
    if (!has_header(("Roblox-Session-Id")))
        headers.insert({ ("Roblox-Session-Id"), session_id_json.dump() });
    if (!has_header(("Roblox-Place-Id")))
        headers.insert({ ("Roblox-Place-Id"), place_id });
    if (!has_header(("Roblox-Game-Id")))
        headers.insert({ ("Roblox-Game-Id"), game_id });
    if (!has_header(("Exploit-Identifier")))
        headers.insert({ ("Exploit-Identifier"), ("Sodium") });
    if (!has_header(("Exploit-Guid")))
        headers.insert({ ("Exploit-Guid"), hwid });
    if (!has_header(("Sodium-Fingerprint")))
        headers.insert({ ("Sodium-Fingerprint"), hwid });
    if (!has_header(("Sodium-User-Identifier")))
        headers.insert({ ("Sodium-User-Identifier"), hwid });
    if (!has_header(("Sodium-Fingerprint")))
        headers.insert({ ("Sodium-Fingerprint"), hwid });
    if (!has_header(("Accept")))
        headers.insert({ ("Accept"), ("*/*") });
    apply_executor_headers(url, hwid, headers);

    return Yielding::YieldExecution(L, [=]() -> std::function<int(lua_State*)>
        {
            http_result_t response = do_request(method, url, headers, body);

            return [response](lua_State* L) -> int
                {
                    if (!response.success)
                    {
                        // Standard executor contract: request() ALWAYS returns a
                        // table, even on transport failure. The old code returned
                        // a bare string here, so key-system loaders doing
                        // request({...}).Body got nil, and loadstring(nil)
                        // surfaced as "invalid argument #1 (string expected,
                        // got nil)" with no hint of the real network error.
                        Roblox::Print(3, ("[request] %s"),
                            (("request failed: ") + response.error).c_str());
                        lua_newtable(L);
                        lua_pushboolean(L, 0);
                        lua_setfield(L, -2, ("Success"));
                        lua_pushinteger(L, response.status_code);
                        lua_setfield(L, -2, ("StatusCode"));
                        std::string phrase = get_status_phrase(response.status_code);
                        lua_pushstring(L, phrase.c_str());
                        lua_setfield(L, -2, ("StatusMessage"));
                        lua_newtable(L);
                        lua_setfield(L, -2, ("Headers"));
                        lua_newtable(L);
                        lua_setfield(L, -2, ("Cookies"));
                        lua_pushstring(L, "");
                        lua_setfield(L, -2, ("Body"));
                        lua_pushstring(L, response.error.c_str());
                        lua_setfield(L, -2, ("Error"));
                        return 1;
                    }

                    lua_newtable(L);
                    lua_pushboolean(L, response.status_code >= 200 && response.status_code < 300);
                    lua_setfield(L, -2, ("Success"));

                    lua_pushinteger(L, response.status_code);
                    lua_setfield(L, -2, ("StatusCode"));

                    std::string phrase = get_status_phrase(response.status_code);
                    lua_pushstring(L, phrase.c_str());
                    lua_setfield(L, -2, ("StatusMessage"));

                    lua_newtable(L);
                    for (auto& header : response.headers)
                    {
                        lua_pushstring(L, header.first.c_str());
                        lua_pushstring(L, header.second.c_str());
                        lua_settable(L, -3);
                    }
                    lua_setfield(L, -2, ("Headers"));

                    lua_newtable(L);
                    auto set_cookie_range = response.headers.equal_range(("Set-Cookie"));
                    for (auto it = set_cookie_range.first; it != set_cookie_range.second; ++it)
                    {
                        const std::string& cookie = it->second;
                        size_t eq = cookie.find('=');
                        size_t sc = cookie.find(';');
                        if (eq == std::string::npos) continue;
                        std::string key = cookie.substr(0, eq);
                        std::string val = cookie.substr(eq + 1, (sc == std::string::npos ? cookie.size() : sc) - eq - 1);
                        lua_pushstring(L, key.c_str());
                        lua_pushstring(L, val.c_str());
                        lua_settable(L, -3);
                    }
                    lua_setfield(L, -2, ("Cookies"));

                    lua_pushlstring(L, response.body.data(), response.body.size());
                    lua_setfield(L, -2, ("Body"));

                    return 1;
                };
        });
}

inline int module::core::environment::c_http::http_post(lua_State* L)
{
    std::string url;
    std::string body;
    std::string content_type = ("application/json");

    int arg_offset = 0;
    if (!lua_isstring(L, 1))
    {
        arg_offset = 1;
        luaL_checkstring(L, 2);
    }

    url = lua_tostring(L, 1 + arg_offset);

    if (lua_isstring(L, 2 + arg_offset))
        body = lua_sized_string(L, 2 + arg_offset);

    if (lua_isstring(L, 3 + arg_offset))
        content_type = lua_tostring(L, 3 + arg_offset);
    else if (lua_isnumber(L, 3 + arg_offset))
    {
        int ct = static_cast<int>(lua_tointeger(L, 3 + arg_offset));
        switch (ct)
        {
        case 0: content_type = ("application/json"); break;
        case 1: content_type = ("application/xml"); break;
        case 2: content_type = ("application/x-www-form-urlencoded"); break;
        case 3: content_type = ("text/plain"); break;
        case 4: content_type = ("text/xml"); break;
        default: content_type = ("application/json"); break;
        }
    }

    if (url.find(("http://")) != 0 && url.find(("https://")) != 0)
    {
        luaL_argerror(L, 1 + arg_offset, ("invalid protocol (expected 'http' or 'https')"));
        return 0;
    }

    if (is_url_blocked(url))
    {
        luaL_error(L, ("url is blocked"));
        return 0;
    }

    std::string game_id;
    lua_getglobal(L, ("game"));
    if (lua_istable(L, -1))
    {
        lua_getfield(L, -1, ("GameId"));
        if (lua_isstring(L, -1))
            game_id = lua_tostring(L, -1);
        lua_pop(L, 1);
    }
    lua_pop(L, 1);

    std::string place_id;
    lua_getglobal(L, ("game"));
    if (lua_istable(L, -1))
    {
        lua_getfield(L, -1, ("PlaceId"));
        if (lua_isstring(L, -1))
            place_id = lua_tostring(L, -1);
        lua_pop(L, 1);
    }
    lua_pop(L, 1);

    std::string hwid = get_hwid();

    using Json = nlohmann::json;
    httplib::Headers headers;
    Json session_id_json;

    session_id_json[("GameId")] = game_id;
    session_id_json[("PlaceId")] = place_id;

    headers.insert({ ("User-Agent"), ("Sodium/1.6.0") });
    headers.insert({ ("Roblox-Session-Id"), session_id_json.dump() });
    headers.insert({ ("Roblox-Place-Id"), place_id });
    headers.insert({ ("Roblox-Game-Id"), game_id });
    headers.insert({ ("Exploit-Identifier"), ("Sodium") });
    headers.insert({ ("Exploit-Guid"), hwid });
    headers.insert({ ("Sodium-Fingerprint"), hwid });
    headers.insert({ ("Accept"), ("*/*") });
    apply_executor_headers(url, hwid, headers);

    return Yielding::YieldExecution(L, [url, body, headers, content_type]() -> std::function<int(lua_State*)>
        {
            http_result_t result = do_request(H_POST, url, headers, body, content_type);

            return [result](lua_State* L) -> int
                {
                    if (!result.success)
                    {
                        lua_pushstring(L, (("http_post failed: ") + result.error).c_str());
                        return 1;
                    }

                    if (result.status_code < 200 || result.status_code >= 300)
                    {
                        std::stringstream err;
                        err << ("http_post returned status: ") << result.status_code;
                        lua_pushstring(L, err.str().c_str());
                        return 1;
                    }

                    lua_pushlstring(L, result.body.data(), result.body.size());
                    return 1;
                };
        });
}

void module::core::environment::c_http::register_lib(lua_State* L)
{
    funcnameinc = 0;

    Environment->make_global(L, ("HttpGet"), c_http::http_get, funcnameinc++);
    Environment->make_global(L, ("HttpPost"), c_http::http_post, funcnameinc++);
    Environment->make_global(L, ("request"), c_http::request, funcnameinc++);

    Environment->make_aliases(L, c_http::http_get, funcnameinc++, { ("httpget"), ("HttpGetAsync"), ("httpgetasync"), ("syn_httpget"), ("gethttp"), ("httpGet") });
    Environment->make_aliases(L, c_http::http_post, funcnameinc++, { ("httppost"), ("HttpPostAsync"), ("httppostasync"), ("syn_httppost"), ("posthttp"), ("httpPost") });
    Environment->make_aliases(L, c_http::request, funcnameinc++, { ("http_request"), ("httprequest"), ("syn_request"), ("krnl_request"), ("webrequest") });

    lua_newtable(L);
    Environment->make_table_function(L, ("request"), c_http::request, funcnameinc++);
    Environment->make_table_function(L, ("Request"), c_http::request, funcnameinc++);
    Environment->make_table_function(L, ("http_request"), c_http::request, funcnameinc++);
    lua_setglobal(L, ("http"));
}