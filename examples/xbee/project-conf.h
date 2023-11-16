#ifndef PROJECT_CONF_H
#define PROJECT_CONF_H

#if 1
#define LOG_CONF_LEVEL_IPV6 LOG_LEVEL_ERR
#define LOG_CONF_LEVEL_TCPIP LOG_LEVEL_DBG
#endif

#define SERVER_MAC_ADDR 0x02,0x13,0xA2,0x00,0x42,0x1C,0x4A,0xF5
#define CLIENT_MAC_ADDR 0x00,0x13,0xA2,0x00,0x42,0x1C,0x4A,0xE0

#ifdef APP_SERVER
#define PLATFORM_CONF_MAC_ADDR {SERVER_MAC_ADDR}
#else
#define PLATFORM_CONF_MAC_ADDR {CLIENT_MAC_ADDR}
#endif

#define DTLS_PSK 1


#define UIP_CONF_UDP 1
#define UIP_CONF_ROUTER 1
#define UIP_CONF_BUFFER_SIZE	4096

#define NETSTACK_CONF_NETWORK slipnet_driver
#define NETSTACK_CONF_FRAMER no_framer

typedef struct {
  char V[16];
  char I[16];
  char id[4];
  int timestamp;
} meter_information_t;

#endif /* PROJECT_CONF_H */
