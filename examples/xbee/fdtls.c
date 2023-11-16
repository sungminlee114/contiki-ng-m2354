#include <os/net/security/tinydtls/tinydtls.h>

int
dtls_encrypt_data(dtls_context_t * ctx,dtls_peer_t *dst, uint8 *buf,size_t len,uint8 *sendbuf, size_t s_len){
	dtls_peer_t * peer = dtls_get_peer(ctx,dst);

	if(!peer){
		int res;
		res = dtls_connect(ctx, peer);
		printf("no peer! and dtls_connect executed!\n");
		return (res >= 0) ? 0 : res;
	} else {
		if(peer->state != DTLS_STATE_CONNECTED) {
			return 0;
		} else {
			// have to change func name
			return dtls_encrypt(ctx,peer,dtls_security_params(peer) ,&peer->session,DTLS_CT_APPLICATION_DATA,&buf,&len,1,sendbuf,s_len);
		}
	}
}