#ifndef _COMPONENT_IFTTT_MAKER_H_
#define _COMPONENT_IFTTT_MAKER_H_

// uncomment to enable output debugging
// #define IFTTT_MAKER_DEBUG_ON

#define IFTTT_MAKER_OK		 			0
#define IFTTT_MAKER_ERR_DRBG_SEED		1
#define IFTTT_MAKER_ERR_CONNECTION		2
#define IFTTT_MAKER_ERR_SSL_DEFAULTS	3
#define IFTTT_MAKER_ERR_SEND			4
#define IFTTT_MAKER_ERR_KEY				5
#define IFTTT_MAKER_ERR_UNKNOWN			10

#define IFTTT_MAKER_SERVER_NAME "maker.ifttt.com"
#define IFTTT_MAKER_SERVER_PORT "443"

void ifttt_maker_mbedtls_debug(void *ctx, int level, const char *file, int line, const char *st);
void ifttt_maker_init(char* key);
int ifttt_maker_trigger(char* event);
int ifttt_maker_trigger_values(char* event, char* vals[], int valc);


#endif //_COMPONENT_IFTTT_MAKER_H_