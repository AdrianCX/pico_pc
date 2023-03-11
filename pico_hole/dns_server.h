#ifndef _DNS_SERVER_H
#define _DNS_SERVER_H

#define TIMEOUT_DNS_REQUEST 30000
#define DECODE_BUFFER_SIZE DNS_DECODEBUF_8K

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
       
bool start_dns_server();
bool downstream();
bool upstream();
void cleanup_requests();
bool check_dns_name(int id, const char *name);

#ifdef __cplusplus
}
#endif


#endif