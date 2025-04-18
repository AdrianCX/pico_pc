#include "dns.h"
#include "mappings.h"
#include "dns_server.h"

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <time.h>

#include <cstdio>
#include <map>

extern "C" void trace(const char* format, ...)
{
    va_list args;
    va_start (args, format);
    vprintf (format, args);
    va_end (args);
    fflush(stdout);
}


uint8_t downstream_buffer[DECODE_BUFFER_SIZE];
uint8_t upstream_buffer[DECODE_BUFFER_SIZE];

uint8_t buffer[DECODE_BUFFER_SIZE];

int downstream_sock;
int upstream_sock;

uint32_t last_update = 0;

uint32_t get_timestamp_ms()
{
    struct timespec spec;
    clock_gettime(CLOCK_MONOTONIC, &spec);
    
    return (spec.tv_sec*1000 + (spec.tv_nsec/1000000));
}

struct RequestSource
{
    RequestSource(struct sockaddr_in ipaddr) : m_ipaddr(ipaddr), m_timestamp(get_timestamp_ms()) {}   

    struct sockaddr_in m_ipaddr;
    uint32_t m_timestamp;
};

std::map<int, RequestSource> m_active_requests;

extern "C" bool downstream();
extern "C" bool upstream();
extern "C" void cleanup_requests();

#define DNS_SERVER "192.168.100.1"

extern "C" bool start_dns_server()
{
    struct sockaddr_in anyaddr;
    anyaddr.sin_family = AF_INET;
    anyaddr.sin_addr.s_addr = INADDR_ANY;
    
    if (inet_aton("192.168.100.64", &anyaddr.sin_addr) == 0) {
        trace("Invalid address\n");
        return false;
    }

    downstream_sock = socket(AF_INET, SOCK_DGRAM, 0);
    upstream_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (downstream_sock < 0 || upstream_sock < 0 )
    {
        trace("Failed to create sockets\r\n");
        return false;
    }

    anyaddr.sin_port = htons(5301);
    if ( bind(downstream_sock, (const struct sockaddr *)&anyaddr, sizeof(anyaddr)) < 0 )
    {
        trace("Failed to bind on port 53\r\n");
        return false;
    }

    anyaddr.sin_port = htons(5303);
    if ( bind(upstream_sock, (const struct sockaddr *)&anyaddr, sizeof(anyaddr)) < 0 )
    {
        trace("Failed to bind on port 5353\r\n");
        return false;
    }

    struct sockaddr_in remote_addr;
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(53);

    if (inet_pton(AF_INET, DNS_SERVER, &remote_addr.sin_addr) == 0)
    {
        trace("Failed decoding remote dns server address, address: %s\r\n", DNS_SERVER);
        return false;
    }

    if (connect(upstream_sock, (struct sockaddr *)&remote_addr, sizeof(remote_addr)) < 0)
    {
        trace("Failed to call connect on upstream socket with address: %s\r\n", DNS_SERVER);
        return false;
    }
    trace("Startup complete\r\n");
    return true;
}


bool downstream()
{
    struct sockaddr_in remote_addr;
    int addr_len = sizeof(remote_addr);

    int len = recvfrom(downstream_sock, (char *)buffer, DECODE_BUFFER_SIZE, MSG_DONTWAIT, (struct sockaddr *) &remote_addr, (socklen_t*)&addr_len);

    if (len <= 0) {
        return false;
    }
    
    size_t downstream_buffer_size = DECODE_BUFFER_SIZE;
    int rc = dns_decode((dns_decoded_t *)downstream_buffer, &downstream_buffer_size,(const dns_packet_t *)buffer, len);

    if (rc != 0)
    {
        trace("Failed to decode input packet, error code: %d\r\n", rc);
        return true;
    }

    bool allowed = true;
    dns_query_t* query = (dns_query_t*)downstream_buffer;
    
    // Check all questions if allowed
    for (size_t i = 0 ; allowed && i<query->qdcount; i++)
    {
        if (query->questions[i].name != NULL)
        {
            allowed = allowed && check_dns_name(query->id, query->questions[i].name);
        }
    }
    
    // If not allowed, then just drop it, no reply
    if (!allowed)
    {
        return true;
    }
    
    rc = sendto(upstream_sock, buffer, len, 0, (struct sockaddr*)NULL, sizeof(struct sockaddr_in));
    if (rc <= 0)
    {
        trace("Failed to forward packet: %d\r\n", rc);
        return true;
    }

    m_active_requests.insert(std::make_pair(query->id, RequestSource(remote_addr)));

    return true;
}

bool upstream()
{
    //trace("upstream: arg=%p, pcb=%p, pbuf=%p, data=%p, len=%d, queue_len: %d\n", arg, pcb, p, (p != NULL ? p->payload : NULL), (p != NULL ? p->len : 0), m_active_requests.size());
    struct sockaddr_in remote_addr;
    int addr_len = sizeof(remote_addr);
    int len = recvfrom(upstream_sock, (char *)buffer, DECODE_BUFFER_SIZE, MSG_DONTWAIT, (struct sockaddr *) &remote_addr, (socklen_t*)&addr_len);

    if (len <= 0)
    {
        return false;
    }
    
    size_t upstream_buffer_size = DECODE_BUFFER_SIZE;
    int rc = dns_decode((dns_decoded_t *)upstream_buffer, &upstream_buffer_size,(const dns_packet_t *)buffer, len);
        
    if (rc != 0)
    {
        trace("Failed to decode upstream input packet, error code: %d\r\n", rc);
        return true;
    }
    
    dns_query_t* query = (dns_query_t*)downstream_buffer;

    auto it = m_active_requests.find(query->id);
    if (it == m_active_requests.end())
    {
        trace("Unknown id for packet reply: %d\r\n", query->id);
        return true;
    }

    rc = sendto(downstream_sock, buffer, len, 0, (struct sockaddr*)&it->second.m_ipaddr, sizeof(struct sockaddr_in));
    if (rc <= 0)
    {
        trace("Failed to forward packet: %d\r\n", rc);
        return true;
    }

    return true;
}

void cleanup_requests()
{
    uint32_t current_time = get_timestamp_ms();

    if (current_time - last_update >= TIMEOUT_DNS_REQUEST/2)
    {
        last_update = current_time;
        for (auto it=m_active_requests.begin();it!=m_active_requests.end();)
        {
            if (current_time - it->second.m_timestamp >= TIMEOUT_DNS_REQUEST)
            {
                it = m_active_requests.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }
}