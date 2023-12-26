#include "dns_server.h"
#include "unistd.h"

int main()
{
    if (!start_dns_server())
    {
        return -1;
    }

    while (true)
    {
        while (upstream()) {};
        while (downstream()) {};

        cleanup_requests();
        usleep(10000);
    }
    return 0;
}