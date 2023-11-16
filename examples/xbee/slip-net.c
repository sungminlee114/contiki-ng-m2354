#include "xbee-client.h"
#include "project-conf.h"

#if TARGET_NATIVE
#include "xbee-driver.h"
#endif /* TARGET_NATIVE */

#include <stdio.h>

#define SLIP_END     0300
#define SLIP_ESC     0333
#define SLIP_ESC_END 0334
#define SLIP_ESC_ESC 0335

#ifdef TARGET_NATIVE
extern int contiki_argc;
extern char **contiki_argv;
#endif /* TARGET_NATIVE */

static void
slipnet_init(void)
{
#ifdef TARGET_NATIVE
	if (contiki_argc != 2){
		printf("(usage) %s {xbee device}\n", contiki_argv[0]);
	  exit(1);
	}
  xbee_init(contiki_argv[1]);
  
#endif /* TARGET_NATIVE */
}

static void
slipnet_input(void)
{
#ifdef TARGET_NATIVE
  // printf("slipnet_input start: uip_len: %d\n", uip_len);
  xbee_read();
#endif /* TARGET_NATIVE */
}

static uint8_t
slipnet_output(const linkaddr_t *localdest)
{
#ifdef TARGET_NATIVE
  // printf("slipnet_output start: uip_len: %d\n", uip_len);
  xbee_send();

#else
  const uint8_t *ptr = uip_buf;
  uint16_t i;
  uint8_t c;

  // printf("slipnet_output start: uip_len: %d\n", uip_len);

  slip_arch_writeb(SLIP_END);

  for(i = 0; i < uip_len; ++i) {
    c = *ptr++;
    if(c == SLIP_END) {
      slip_arch_writeb(SLIP_ESC);
      c = SLIP_ESC_END;
    } else if(c == SLIP_ESC) {
      slip_arch_writeb(SLIP_ESC);
      c = SLIP_ESC_ESC;
    }
    // printf("so: %02x, %c\n", c, c);
    slip_arch_writeb(c);
  }

  slip_arch_writeb(SLIP_END);
  // printf("slipnet_output end\n");

#endif /* TARGET_NATIVE */
  return 1;
}

const struct network_driver slipnet_driver = {
  "slipnet",
  slipnet_init,
  slipnet_input,
  slipnet_output
};
