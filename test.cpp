#include <windows.h>
#include <stdio.h>

#include <iostream>

#include "net.h"

#include <stdexcept>

int main()
{
    try
    {
        net::url url(L"https://jsonplaceholder.typicode.com/todos");
        auto data = net::send_get_request(url);
        ////////////
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