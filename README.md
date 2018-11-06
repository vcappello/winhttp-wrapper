# WinHTTP-Wrapper

A simple WinHTTP wrapper

Usage

```c++
    try
    {
        auto data = net::fetch_request(net::url(L"https://jsonplaceholder.typicode.com/todos"));

        // Convert the buffer to a standard string and write it
        std::string sdata(data.begin(), data.end());   
        std::cout << sdata << std::endl;
    }
    catch (net::error &e)
    {
        std::wcerr << e.wwhat() << std::endl;
    }
```
