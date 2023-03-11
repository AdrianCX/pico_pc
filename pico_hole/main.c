#include "dns_server.h"
#include "unistd.h"

int main()
{
    start_dns_server();

    while (true)
    {
        while (upstream()) {};
        while (downstream()) {};

        cleanup_requests();
        usleep(10000);
    }
    return 0;
}