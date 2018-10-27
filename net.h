#ifndef NET_H
#define NET_H

#include <windows.h>
#include <winhttp.h>

#include <stdexcept>
#include <string>
#include <regex>

#define LOG(msg) std::wcout << (msg) << std::endl;

namespace net
{

class error : public std::runtime_error
{
  public:
    error(const std::wstring &msg) : runtime_error("Use wwhat"),
                                     msg(msg),
                                     error_code(0),
                                     error_msg(L"") {}

    error(const std::wstring &msg, DWORD error_code) : runtime_error("Use wwhat"),
                                                       msg(msg),
                                                       error_code(error_code),
                                                       error_msg(format_message(error_code)) {}
    virtual ~error() noexcept {}

    std::wstring wwhat() const
    {
        if (error_msg.empty())
            return msg;

        return msg + L" " + error_msg;
    }

    static std::wstring format_message(DWORD error_code)
    {
        //Get the error message, if any.
        if (error_code == 0)
            return std::wstring(); //No error message has been recorded

        LPTSTR message_buffer = nullptr;
        size_t size = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                    NULL, error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&message_buffer, 0, NULL);

        std::wstring message(message_buffer, size);

        //Free the buffer.
        LocalFree(message_buffer);

        return message;
    }

  protected:
    std::wstring msg;
    DWORD error_code;
    std::wstring error_msg;
};

class url
{
  public:
    url(const std::wstring &url_text) : text(url_text)
    {
        // The regex using RFC 3986 suggestion is
        // (^(([^:\/?#]+):)?(//([^\/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?)
        // We manage also the split of authority into host and port
        std::wregex url_regex(LR"(^(([^:\/?#]+):)?(//([^\/?#:]*)(:([^\/?#]*))?)?([^?#]*)(\?([^#]*))?(#(.*))?)",
                              std::wregex::extended);
        std::wsmatch url_match_result;

        if (std::regex_match(url_text, url_match_result, url_regex))
        {
            unsigned counter = 0;
            for (const auto &res : url_match_result)
            {
                switch (counter)
                {
                case 2:
                    scheme = res;
                    break;
                case 4:
                    host = res;
                    break;
                case 6:
                    port = res;
                    break;
                case 7:
                    path = res;
                    break;
                case 9:
                    query = res;
                    break;
                case 11:
                    fragment = res;
                    break;
                }
                counter++;
            }
        }
        else
        {
            throw error(L"Malformed url");
        }
    }
    ~url()
    {
    }

    std::wstring get_text() const { return text; }
    std::wstring get_scheme() const { return scheme; }
    std::wstring get_host() const { return host; }
    std::wstring get_port() const { return port; }
    std::wstring get_path() const { return path; }
    std::wstring get_query() const { return query; }
    std::wstring get_fragment() const { return fragment; }

  protected:
    std::wstring text;
    std::wstring scheme;
    std::wstring host;
    std::wstring port;
    std::wstring path;
    std::wstring query;
    std::wstring fragment;
};

template <typename Tag>
class internet_handle
{
  public:
    internet_handle(HINTERNET raw_handle) : handle(raw_handle) {}
    ~internet_handle()
    {
        if (handle)
        {
            WinHttpCloseHandle(handle);
        }
    }

    internet_handle(internet_handle &&other) noexcept // move constructor
        : handle(std::exchange(other.handle, NULL))
    {
    }

    internet_handle &operator=(internet_handle &&other) noexcept // move assignment
    {
        std::swap(handle, other.handle);
        return *this;
    }

    operator HINTERNET() { return handle; }

  protected:
    HINTERNET handle;

    internet_handle(const internet_handle &other) {}            // copy constructor
    internet_handle &operator=(const internet_handle &other) {} // copy assignment
};

using session = internet_handle<struct SessionTag>;
using connection = internet_handle<struct ConnectionTag>;
using request = internet_handle<struct RequestTag>;
using buffer_t = std::vector<char>;

session make_session(const std::wstring &user_agent)
{
    HINTERNET raw_handle = WinHttpOpen(user_agent.c_str(), WINHTTP_ACCESS_TYPE_NO_PROXY, 0, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!raw_handle)
    {
        throw error(L"Error (WinHttpOpen)", GetLastError());
    }

    return session(raw_handle);
}

struct named_proxy_policy
{
    static bool check_policy(const WINHTTP_CURRENT_USER_IE_PROXY_CONFIG &config)
    {
        return config.lpszProxy;
    }

    static WINHTTP_PROXY_INFO make_proxy_info(session &http_session, const url &dest_url, const WINHTTP_CURRENT_USER_IE_PROXY_CONFIG &config)
    {
        WINHTTP_PROXY_INFO proxy_info = {};
        proxy_info.lpszProxy = config.lpszProxy;
        proxy_info.dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
        proxy_info.lpszProxyBypass = NULL;

        return proxy_info;
    }
};

struct auto_config_url_policy
{
    static bool check_policy(const WINHTTP_CURRENT_USER_IE_PROXY_CONFIG &config)
    {
        return config.lpszAutoConfigUrl;
    }

    static WINHTTP_PROXY_INFO make_proxy_info(session &http_session, const url &dest_url, const WINHTTP_CURRENT_USER_IE_PROXY_CONFIG &config)
    {
        WINHTTP_PROXY_INFO proxy_info = {};
        WINHTTP_PROXY_INFO proxy_info_tmp = {};
        WINHTTP_AUTOPROXY_OPTIONS opt_pac = {};

        // Script proxy pac
        opt_pac.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL;
        opt_pac.lpszAutoConfigUrl = config.lpszAutoConfigUrl;
        opt_pac.dwAutoDetectFlags = 0;
        opt_pac.fAutoLogonIfChallenged = TRUE;
        opt_pac.lpvReserved = 0;
        opt_pac.dwReserved = 0;

        if (WinHttpGetProxyForUrl(http_session, dest_url.get_text().c_str(), &opt_pac, &proxy_info_tmp))
        {
            proxy_info = proxy_info_tmp;
        }

        return proxy_info;
    }
};

struct auto_detect_policy
{
    static bool check_policy(const WINHTTP_CURRENT_USER_IE_PROXY_CONFIG &config)
    {
        return config.fAutoDetect;
    }

    static WINHTTP_PROXY_INFO make_proxy_info(session &http_session, const url &dest_url, const WINHTTP_CURRENT_USER_IE_PROXY_CONFIG &config)
    {
        WINHTTP_PROXY_INFO proxy_info = {};
        WINHTTP_PROXY_INFO proxy_info_tmp = {};
        WINHTTP_AUTOPROXY_OPTIONS opt_pac = {};

        // Autodetect proxy
        opt_pac.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT;
        opt_pac.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
        opt_pac.fAutoLogonIfChallenged = TRUE;
        opt_pac.lpszAutoConfigUrl = NULL;
        opt_pac.lpvReserved = 0;
        opt_pac.dwReserved = 0;

        if (WinHttpGetProxyForUrl(http_session, dest_url.get_text().c_str(), &opt_pac, &proxy_info_tmp))
        {
            proxy_info = proxy_info_tmp;
        }

        return proxy_info;
    }
};

void detect_proxy(session &http_session, const url &dest_url)
{
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG config = {};
    WINHTTP_PROXY_INFO proxy_info;
    DWORD options = SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

    if (WinHttpGetIEProxyConfigForCurrentUser(&config))
    {
        if (named_proxy_policy::check_policy(config))
        {
            proxy_info = named_proxy_policy::make_proxy_info(http_session, dest_url, config);
        }
        if (auto_config_url_policy::check_policy(config))
        {
            proxy_info = auto_config_url_policy::make_proxy_info(http_session, dest_url, config);
        }
        if (auto_detect_policy::check_policy(config))
        {
            proxy_info = auto_detect_policy::make_proxy_info(http_session, dest_url, config);
        }
        if (proxy_info.lpszProxy)
        {
            WinHttpSetOption(http_session, WINHTTP_OPTION_PROXY, &proxy_info, sizeof(proxy_info));
        }
    }
    WinHttpSetOption(http_session, WINHTTP_OPTION_SECURITY_FLAGS, &options, sizeof(DWORD));
}

INTERNET_PORT get_port_from_url(const url &dest_url)
{
    if (!dest_url.get_port().empty())
    {
        // Retrieve port specified in the URL
        return (INTERNET_PORT)std::stoi(dest_url.get_port());
    }

    // Use default port for URL scheme
    if (dest_url.get_scheme() == L"http")
    {
        return INTERNET_DEFAULT_HTTP_PORT;
    }
    else if (dest_url.get_scheme() == L"https")
    {
        return INTERNET_DEFAULT_HTTPS_PORT;
    }

    throw error(L"Unknown scheme " + dest_url.get_text());
}

connection make_connection(session &http_session, const url &dest_url)
{
    HINTERNET raw_handle = NULL;
    if (!(raw_handle = WinHttpConnect(http_session, dest_url.get_host().c_str(), get_port_from_url(dest_url), 0)))
    {
        throw error(L"Error (WinHttpConnect)", GetLastError());
    }

    return connection(raw_handle);
}

request make_request(connection &http_connection, const std::wstring &verb, const url &dest_url)
{
    HINTERNET raw_handle = NULL;
    DWORD flags = 0;

    if (dest_url.get_scheme() == L"https")
    {
        flags = WINHTTP_FLAG_SECURE;
    }
    if (!(raw_handle = WinHttpOpenRequest(http_connection, verb.c_str(), dest_url.get_path().c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags)))
    {
        throw error(L"Error (WinHttpOpenRequest)", GetLastError());
    }

    return request(raw_handle);
}

void send_request(request &http_request)
{
    if (!WinHttpSendRequest(http_request,
                            WINHTTP_NO_ADDITIONAL_HEADERS,
                            0, WINHTTP_NO_REQUEST_DATA, 0,
                            0, 0))
    {
        throw error(L"Error (WinHttpSendRequest)", GetLastError());
    }
}

void receive_response(request &http_request)
{
    if (!WinHttpReceiveResponse(http_request, NULL))
    {
        throw error(L"Error (WinHttpReceiveResponse)", GetLastError());
    }
}

size_t query_data_avaliable(request &http_request)
{
    DWORD size = 0;
    if (!WinHttpQueryDataAvailable(http_request, &size))
    {
        throw error(L"Error (WinHttpQueryDataAvailable)", GetLastError());
    }
    return size;
}

buffer_t read_data(request &http_request, size_t size = 0)
{
    DWORD downloaded = 0;

    if (size == 0)
    {
        size = query_data_avaliable(http_request);
    }
    std::vector<char> buffer;
    buffer.resize(size);
    if (!WinHttpReadData(http_request,
                         (LPVOID)&buffer[0],
                         size, 
                         &downloaded))
    {
        throw error(L"Error (WinHttpReadData)", GetLastError());
    }

    return buffer;
}

// Can not use wstring because the encoding is defined by the the remote server
buffer_t fetch_request(const url &dest_url, const std::wstring &user_agent = L"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko)")
{
    LOG(L"make_request " + dest_url.get_text());
    auto http_session = make_session(user_agent);
    detect_proxy(http_session, dest_url);
    auto http_connection = make_connection(http_session, dest_url);

    auto http_request = make_request(http_connection, L"GET", dest_url);
    send_request(http_request);
    receive_response(http_request);

    buffer_t buffer;
    while(size_t size = query_data_avaliable(http_request) != 0)
    {
        auto chunk = read_data(http_request, size);
        buffer.insert(std::end(buffer), std::begin(chunk), std::end(chunk));
    }
    return buffer;
}

} // namespace net

#endif