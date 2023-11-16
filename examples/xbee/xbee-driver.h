#ifndef XBEE_DRIVER_H
#define XBEE_DRIVER_H

#define SLIP_END	0300
#define SLIP_ESC	0333
#define SLIP_ESC_END	0334
#define SLIP_ESC_ESC	0335
#define XBEE_DATA_MAX	4096

static int xbee_fd;
static unsigned char xbee_data[XBEE_DATA_MAX];
static int xbee_data_len = 0;

void xbee_init(const char *dev_name);
unsigned int xbee_read(void);
void xbee_send(void);
#endif /* XBEE_DRIVER_H */