#include "xbee-client.h"
#include "project-conf.h"

#define RX_BUF_SIZE 1024
#define TX_BUF_SIZE	1024
#define payload 128

static struct simple_udp_connection udp_sock;

// #define TARGET_M2354 1
#define TARGET_NATIVE 1
#define USE_FDTLS 1

#ifdef TARGET_M2354
#include <string.h>
#include "lib/ringbuf.h"
#include "meterif_data.h"
#define METER_RXBUF_SIZE	128
static struct ringbuf meter_rxbuf;
static uint8_t meter_rxbuf_data[METER_RXBUF_SIZE];
process_event_t meter_if_serial_event_message;
#endif /* TARGET_M2354 */

#ifdef USE_FDTLS
#include "os/net/security/tinydtls/tinydtls.h"
#include "os/net/security/tinydtls/dtls.h"
static dtls_context_t *dtls_context;
int handshake_complete = 0;
static struct etimer handshake_timer;
#endif /* USE_FDTLS */

PROCESS(udp_client_process, "UDP client");
AUTOSTART_PROCESSES(&udp_client_process);

#ifdef USE_FDTLS
// int
// dtls_encrypt_data(dtls_context_t * ctx,dtls_peer_t *dst, uint8_t *buf,size_t len, uint8_t *sendbuf, size_t s_len){
// 	dtls_peer_t * peer = dtls_get_peer(ctx,dst);

// 	if(!peer){
// 		int res;
// 		res = dtls_connect(ctx, peer);
// 		printf("no peer! and dtls_connect executed!\n");
// 		return (res >= 0) ? 0 : res;
// 	} else {
// 		if(peer->state != DTLS_STATE_CONNECTED) {
// 			return 0;
// 		} else {
// 			// have to change func name
// 			return dtls_encrypt(ctx,peer,dtls_security_params(peer) ,&peer->session,DTLS_CT_APPLICATION_DATA,&buf,&len,1,sendbuf,s_len);
// 		}
// 	}
// }

// int
// calculate_key_block_self(dtls_context_t *ctx,
// 		    session_t *sess){

//   dtls_peer_t * peer = dtls_get_peer(ctx,sess);
//   dtls_handshake_parameters_t *handshake = peer->handshake_params;
//   dtls_security_parameters_t *security = dtls_security_params_next(peer);

//   unsigned char *pre_master_secret;
//   int pre_master_len = 0;
//   uint8_t master_secret[DTLS_MASTER_SECRET_LENGTH];

//   if (!security) {
//     return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
//   }

//   pre_master_secret = security->key_block;

//   if(handshake->cipher == TLS_PSK_WITH_AES_128_CCM_8){
//     unsigned char psk[DTLS_PSK_MAX_KEY_LEN];
//     int len;

//     len = CALL(ctx, get_psk_info, sess, DTLS_PSK_KEY,
// 	       handshake->keyx.psk.identity,
// 	       handshake->keyx.psk.id_length,
// 	       psk, DTLS_PSK_MAX_KEY_LEN);

//     if (len < 0) {
//       dtls_crit("no psk key for session available\n");
//       return len;
//     }
//   /* Temporarily use the key_block storage space for the pre master secret. */
//     pre_master_len = dtls_psk_pre_master_secret(psk, len,
// 						pre_master_secret,
// 						MAX_KEYBLOCK_LENGTH);

//     dtls_debug_hexdump("psk", psk, len);

//     memset(psk, 0, DTLS_PSK_MAX_KEY_LEN);
//     if (pre_master_len < 0) {
//       dtls_crit("the psk was too long, for the pre master secret\n");
//       return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
//     }

//   } else {
//     dtls_crit("calculate_key_block: unknown cipher\n");
//     return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
//   }

//   dtls_debug_dump("client_random", handshake->tmp.random.client, DTLS_RANDOM_LENGTH);
//   dtls_debug_dump("server_random", handshake->tmp.random.server, DTLS_RANDOM_LENGTH);
//   dtls_debug_dump("pre_master_secret", pre_master_secret, pre_master_len);

//   #ifdef CUSTOM_PRF
//     dtls_prf_custom(pre_master_secret, pre_master_len,
//              PRF_LABEL(master), PRF_LABEL_SIZE(master),
//              handshake->tmp.random.client, DTLS_RANDOM_LENGTH,
//              handshake->tmp.random.server, DTLS_RANDOM_LENGTH,
//              master_secret,
//              DTLS_MASTER_SECRET_LENGTH);
//   #else
//     dtls_prf(pre_master_secret, pre_master_len,
//              PRF_LABEL(master), PRF_LABEL_SIZE(master),
//              handshake->tmp.random.client, DTLS_RANDOM_LENGTH,
//              handshake->tmp.random.server, DTLS_RANDOM_LENGTH,
//              master_secret,
//              DTLS_MASTER_SECRET_LENGTH);
//   #endif

//   dtls_debug_dump("master_secret", master_secret, DTLS_MASTER_SECRET_LENGTH);

//   /* create key_block from master_secret
//    * key_block = PRF(master_secret,
//                     "key expansion" + tmp.random.server + tmp.random.client) */
//   #ifdef CUSTOM_PRF
//     dtls_prf_custom(master_secret,
//             DTLS_MASTER_SECRET_LENGTH,
//             PRF_LABEL(key), PRF_LABEL_SIZE(key),
//             handshake->tmp.random.server, DTLS_RANDOM_LENGTH,
//             handshake->tmp.random.client, DTLS_RANDOM_LENGTH,
//             security->key_block,
//             dtls_kb_size(security, peer->role));
//   #else
//     dtls_prf(master_secret,
//             DTLS_MASTER_SECRET_LENGTH,
//             PRF_LABEL(key), PRF_LABEL_SIZE(key),
//             handshake->tmp.random.server, DTLS_RANDOM_LENGTH,
//             handshake->tmp.random.client, DTLS_RANDOM_LENGTH,
//             security->key_block,
//             dtls_kb_size(security, peer->role));
//   #endif /*CUSTOM_PRF*/

//   memcpy(handshake->tmp.master_secret, master_secret, DTLS_MASTER_SECRET_LENGTH);
//   dtls_debug_keyblock(security);
//   security->cipher = handshake->cipher;
//   security->compression = handshake->compression;
//   security->rseq = 1;
//   security->epoch = 1;
//   dtls_security_params_switch(peer);
//   dtls_debug_dump("test iv", dtls_kb_local_iv(security, peer->role), 4);
//   dtls_debug_dump("test key:", dtls_kb_local_write_key(security, peer->role),
//       dtls_kb_key_size(security, peer->role));
//   return 0;
// }
static int
read_from_peer(struct dtls_context_t *ctx, 
	       session_t *session, uint8_t *data, size_t len) {
  size_t i;
  printf("read_from_peer: %d(%lu)\n", data, len);
  for (i = 0; i < len; i++)
    printf("%c", data[i]);
  printf("\n");
  return 0;
}

static int
send_to_peer(struct dtls_context_t *ctx, 
	     session_t *session, uint8_t *data, size_t len) {
  
  printf("send_to_peer: %d(%lu)\n", data, len);
  return simple_udp_send(&udp_sock, data, len);
}

static int
dtls_handle_read(struct dtls_context_t *ctx) {
  session_t session;
  memset(&session, 0, sizeof(session_t));
  
  static uint8_t buf[RX_BUF_SIZE];
  int len;

  printf("dtls_handle_read\n");
  if(uip_newdata()) {
    printf("uip_newdata\n");
    uip_ipaddr_copy(&session.addr, &UIP_IP_BUF->srcipaddr);
    session.port = UIP_UDP_BUF->srcport;

    len = uip_datalen();

    if (len > sizeof(buf)) {
      // dtls_warn("packet is too large");
      return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
    }

    memcpy(buf, uip_appdata, len);
    printf("buf: %s\n", buf);
  }
  return dtls_handle_message(ctx, &session, buf, len);
}

#ifdef DTLS_PSK
/* This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identity within this particular
 * session. */
static int
get_psk_info(struct dtls_context_t *ctx, const session_t *session,
             dtls_credentials_type_t type,
             const unsigned char *id, size_t id_len,
             unsigned char *result, size_t result_length) {

  struct keymap_t {
    unsigned char *id;
    size_t id_length;
    unsigned char *key;
    size_t key_length;
  } psk[3] = {
    { (unsigned char *)"Client_identity", 15,
      (unsigned char *)"secretPSK", 9 },
    { (unsigned char *)"default identity", 16,
      (unsigned char *)"\x11\x22\x33", 3 },
    { (unsigned char *)"\0", 2,
      (unsigned char *)"", 1 }
  };

  if (type != DTLS_PSK_KEY) {
    return 0;
  }

  if (id) {
    int i;
    for (i = 0; i < sizeof(psk)/sizeof(struct keymap_t); i++) {
      if (id_len == psk[i].id_length && memcmp(id, psk[i].id, id_len) == 0) {
        if (result_length < psk[i].key_length) {
          return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
        }

        memcpy(result, psk[i].key, psk[i].key_length);
        return psk[i].key_length;
      }
    }
  }
  return dtls_alert_fatal_create(DTLS_ALERT_DECRYPT_ERROR);
}
#endif /* DTLS_PSK */

static int
dtls_complete(struct dtls_context_t *ctx, session_t *session, dtls_alert_level_t level, unsigned short code){

  if(code == DTLS_EVENT_CONNECTED) {
    handshake_complete = 1;
    printf("handshake_complete!\n");
    //struct etimer et;
    etimer_set(&handshake_timer,CLOCK_SECOND*5);

    //buflen = sizeof(buf);
    //dtls_write(ctx, session, (uint8 *)buf, buflen);
    //rtimer_count = rtimer_arch_now();
    //printf("send packet\n");
  }
  return 0;
}

// int
// create_virtual_peer(dtls_context_t *ctx, session_t *sess,unsigned char *psk_id, size_t len){
// 	//create peer
// 	dtls_peer_t *peer;
//   memset(sess,0,sizeof(session_t));
//   uip_ipaddr_t ipaddr;
//   uip_ipaddr(&ipaddr, 127,0,0,1);
//   sess -> addr = ipaddr;
// 	peer = dtls_new_peer(sess);

// 	if(!peer){
// 		dtls_crit("cannot create new peer\n");
//     return -1;
// 	}

// 	peer-> role = DTLS_SERVER;
// 	peer-> handshake_params = dtls_handshake_new();
// 	peer-> state = DTLS_STATE_CONNECTED;

// 	dtls_cipher_t newchiper = TLS_PSK_WITH_AES_128_CCM_8;
// 	dtls_handshake_parameters_t *handshake = peer->handshake_params;
// 	handshake->cipher = newchiper;
//   //handshake->compression = TLS_COMPRESSION_NULL;

// 	dtls_security_parameters_t *security = dtls_security_params(peer);
// 	security->cipher = newchiper;
// 	security->epoch = 1;
// 	security->rseq = 1;
// 	security->compression = TLS_COMPRESSION_NULL;

// 	handshake -> keyx.psk.id_length = len;
//   memcpy(handshake->keyx.psk.identity, psk_id, len);
//   dtls_add_peer(ctx, peer);
//   //calculate_key_block_self(ctx,sess);
//   //dtls_security_params_switch(peer);

//   return 0;
// }

#endif /* USE_FDTLS */


#ifdef TARGET_M2354
/*---------------------------------------------------------------------------*/
// called from meter_dev_process.native
int
meter_if_serial_input_byte(unsigned char c)
{
  int ret = 1;
  
    /* Add character */
  if(ringbuf_put(&meter_rxbuf, c) == 0) {
      ret = 0;
    /* Buffer overflow: ignore the rest of the line */
  }
  /* Wake up consumer process */
  //process_poll(&meter_if_serial_process);
  process_post(&udp_client_process, meter_if_serial_event_message, NULL);
  return ret;
}
#endif /* TARGET_M2354 */
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_client_process, ev, data)
{
	// static unsigned char buf[1024];

  uip_ipaddr_t dest_ipaddr =  {{ 0xFE,0x80,0x00,0x00,0x00,0x00,0x00,0x00, SERVER_MAC_ADDR}};
	
#ifdef USE_FDTLS
  session_t vir_sess;
#endif

  // static struct etimer send_timer;
	

	PROCESS_BEGIN();
#ifdef TARGET_M2354
  ringbuf_init(&meter_rxbuf, meter_rxbuf_data, sizeof(meter_rxbuf_data));
  meter_if_serial_event_message = process_alloc_event();
#endif /* TARGET_M2354 */

	// convert 16 uint8_t to string
	char dest_ipaddr_str[40];
	if(dest_ipaddr_str == NULL) {
		LOG_ERR("malloc error\n");
		goto exit;
	} else {
		sprintf(dest_ipaddr_str, "%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X",
			dest_ipaddr.u8[0], dest_ipaddr.u8[1], dest_ipaddr.u8[2], dest_ipaddr.u8[3], dest_ipaddr.u8[4], dest_ipaddr.u8[5], dest_ipaddr.u8[6], dest_ipaddr.u8[7],
			dest_ipaddr.u8[8], dest_ipaddr.u8[9], dest_ipaddr.u8[10], dest_ipaddr.u8[11], dest_ipaddr.u8[12], dest_ipaddr.u8[13], dest_ipaddr.u8[14], dest_ipaddr.u8[15]);
		// printf("dest_ipaddr_str: %s\n", dest_ipaddr_str);
	}

  //   // 수신을 위한 메모리 할당
	// rx_buf = malloc(rx_buf_size);
	// if (rx_buf == NULL) {
	// 	LOG_ERR("malloc error\n");
	// 	goto exit;
	// }

  printf( "  . Connecting to udp/%s/%d...", dest_ipaddr_str, UDP_SERVER_PORT);
  fflush( stdout );
  
	if (!simple_udp_register(&udp_sock, UDP_CLIENT_PORT, &dest_ipaddr, UDP_SERVER_PORT, NULL))
	{
		LOG_ERR("simple_udp_register error\n");
		goto exit;
	}

  printf( " ok\n" );
  fflush( stdout );


#ifdef USE_FDTLS
	printf("Init DTLS..\n");

	dtls_init();

  static session_t dst_session;
  dst_session.addr = dest_ipaddr;
  dst_session.port = UDP_SERVER_PORT;

  static dtls_handler_t cb = {
    .write = send_to_peer,
    .read  = read_from_peer,
    .event = dtls_complete,
#ifdef DTLS_PSK
    .get_psk_info = get_psk_info,
#endif /* DTLS_PSK */
// #ifdef DTLS_ECC
//     .get_ecdsa_key = get_ecdsa_key,
//     .verify_ecdsa_key = verify_ecdsa_key
// #endif /* DTLS_ECC */
  };

  dtls_context = dtls_new_context(&udp_sock);
  if (dtls_context)
    dtls_set_handler(dtls_context, &cb);

	if(!dtls_context){
		printf("cannot create context\n");
		goto exit;
	}

  dtls_connect(dtls_context, &dst_session);
  printf("DEBUG 0\n");

	// unsigned char *psk_id = "Client_identity";
	// if(create_virtual_peer(dtls_context,&vir_sess,psk_id,15) != 0){
	// 	printf("create virtual peer error\n");
	// }
	// calculate_key_block_self(dtls_context,&vir_sess);
	// cfs_prepare_data(dtls_context,vir_sess);

#endif /* USE_FDTLS */


  


  // etimer_set(&send_timer, 10 * CLOCK_SECOND); // every 1sec

  while(1) {
    // PROCESS_YIELD();

    printf("DEBUG 1\n");
    if (ev == tcpip_event){
      printf("DEBUG 2-1-1\n");
      dtls_handle_read(dtls_context);
      printf("DEBUG 2-1-2\n");
      if(handshake_complete == 1){
        printf("DEBUG 2-1-3-1\n");
        // PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&handshake_timer));
        // dtls_write(dtls_context, &dst, (uint8 *)buf, sizeof(buf));
        // printf("send packet\n");
        break;
      }
    } else {
      printf("DEBUG 2-2-1\n");
    }

    printf("DEBUG 3\n");
    meter_information_t meter_information;
    strcpy(meter_information.id, "1");
    
#ifdef TARGET_M2354
    int c = ringbuf_get(&meter_rxbuf);

    if(c != -1) {
      static meterif_data_context_t ctx;
      if (meterif_data_beginning(c)) {
          meterif_data_init(&ctx);
      }
      meterif_data_accumulate(&ctx, c);
      if (meterif_data_complete(&ctx)) {

          meterif_data_process(&ctx, &meter_information);

          meter_information.timestamp = clock_seconds();
          printf("%d| V: %s, I: %s\n",  meter_information.timestamp, meter_information.V, meter_information.I);
      }
    }
#endif /* TARGET_M2354 */
#ifdef TARGET_NATIVE
    meter_information.timestamp = clock_seconds();
    strcpy(meter_information.V, "5");
    strcpy(meter_information.I, "10");

#endif /* TARGET_NATIVE */

    char msg[payload];
    sprintf(msg, "%05d| V: %s, I: %s",  meter_information.timestamp, meter_information.V, meter_information.I);
    char sendbuf[TX_BUF_SIZE];
    
#ifdef USE_FDTLS
    
    // int res = dtls_encrypt_data(dtls_context,&vir_sess,msg,sizeof(msg),sendbuf,sizeof(sendbuf));

    // if(res < 0){
    //   printf("dtls_encrypt_data error\n");
    // }


#endif /* USE_FDTLS */
    
    PROCESS_YIELD();
    // PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&send_timer));
    // etimer_reset(&send_timer);
  }

exit:
    ;
#ifdef USE_FDTLS
	dtls_free_context(dtls_context);
#endif /* USE_FDTLS */
    PROCESS_END();
}
