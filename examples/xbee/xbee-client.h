#ifndef XBEE_CLIENT_H
#define XBEE_CLIENT_H

#include "contiki.h"
#include "contiki-net.h"
#include "sys/subprocess.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "os/dev/slip.h"
#include "sys/log.h"


#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_DBG

#define UDP_CLIENT_PORT	8765
#define UDP_SERVER_PORT	5678
#define SERVER_NAME "localhost"

#endif /* XBEE_CLIENT_H */
