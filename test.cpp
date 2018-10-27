#include <windows.h>
#include <stdio.h>

#include <iostream>

#include "net.h"

#include <stdexcept>

int main()
{
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

    system("pause");
    return 0;
}