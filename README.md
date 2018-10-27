# WinHTTP-Wrapper

A simple WinHTTP wrapper

```c++
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
```
