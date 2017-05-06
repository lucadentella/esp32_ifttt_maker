// component header
#include "esp32_ifttt_maker.h"

// mbed TLS headers
#include "mbedtls/platform.h"
#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"

// standard libraries
#include <string.h>
#include <stdlib.h>

// Maker private key
char* _key;

// mbed TLS variables
mbedtls_ssl_config conf;
mbedtls_net_context server_fd;
mbedtls_ssl_context ssl;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;


// mbed TLS debug function
void ifttt_maker_mbedtls_debug(void *ctx, int level, const char *file, int line, const char *st) {
		
	printf("mbedtls: %s\n", st);
}

// initialize the component with the private key of your Maker account
void ifttt_maker_init(char* key) {
	
	// store the private key
	_key = key;
}


// trigger an event with no values
int ifttt_maker_trigger(char* event) {
	
	return ifttt_maker_trigger_values(event, NULL, 0);
}


// trigger an event with valc values
int ifttt_maker_trigger_values(char* event, char* vals[], int valc) {
	
	// return code for the different functions
	int _ret;
	
	// initialize mbed TLS
	mbedtls_net_init(&server_fd);
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);	
	#ifdef IFTTT_MAKER_DEBUG_ON 
		printf("mbedtls initialized\n");
	#endif
	
	// seed the random number generator
	if((_ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0)) != 0)
		return IFTTT_MAKER_ERR_DRBG_SEED;	
	#ifdef IFTTT_MAKER_DEBUG_ON 
		printf("mbedtls_ctr_drbg_seed\n");
	#endif
	
	// connect to the server
	if((_ret = mbedtls_net_connect( &server_fd, IFTTT_MAKER_SERVER_NAME, IFTTT_MAKER_SERVER_PORT, MBEDTLS_NET_PROTO_TCP)) != 0)
		return IFTTT_MAKER_ERR_CONNECTION;
	#ifdef IFTTT_MAKER_DEBUG_ON 
		printf("mbedtls_net_connect\n");
	#endif
	
	// configure the SSL/TLS layer (client mode with TLS)
	if((_ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
		return IFTTT_MAKER_ERR_SSL_DEFAULTS;	
	#ifdef IFTTT_MAKER_DEBUG_ON 
		printf("mbedtls_ssl_config_defaults\n");
	#endif
	
	// do not verify the CA certificate
	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
	#ifdef IFTTT_MAKER_DEBUG_ON 
		printf("mbedtls_ssl_conf_authmode\n");
	#endif
	
	// configure the random engine and the debug function
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ssl_conf_dbg(&conf, ifttt_maker_mbedtls_debug, NULL);
	#ifdef IFTTT_MAKER_DEBUG_ON 
		printf("mbedtls_ssl_conf_dbg\n");
	#endif
	
	mbedtls_ssl_setup(&ssl, &conf);
	mbedtls_ssl_handshake(&ssl);
	
	// configure the input and output functions
	mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
	#ifdef IFTTT_MAKER_DEBUG_ON 
		printf("mbedtls_ssl_set_bio\n");
	#endif
	
	// request and body buffer
	char* request = NULL;
	int request_length;
	char* body = NULL;
	int body_length;
	
	// if no values were provided, prepare the GET request
	if(vals == NULL) {
		
		request_length = 80 + strlen(_key) + strlen(event) + strlen(IFTTT_MAKER_SERVER_NAME) * 2;
		request = malloc(request_length);
		snprintf(request, request_length, "GET https://%s/trigger/%s/with/key/%s HTTP/1.1\n"
			"Host: %s\n"
			"User-Agent: esp32_ifttt_maker\n\n",
			IFTTT_MAKER_SERVER_NAME, event, _key, IFTTT_MAKER_SERVER_NAME);
	} 
	
	// if values were provided, prepare the POST request
	else {
		
		int args_length = 0;
		int i;
		
		for(i = 0; i < valc; i++) args_length += strlen(vals[i]);
		body_length = 2 + valc * 12 + args_length;

		body = malloc(body_length);
		sprintf(body, "{");
		for(i = 1; i < valc; i++) sprintf(body + strlen(body), "\"value%d\" : \"%s\",", i, vals[i-1]);
		sprintf(body + strlen(body), "\"value%d\":\"%s\"}", i, vals[i-1]);
		
		request_length = 110 + strlen(_key) + strlen(event) + strlen(IFTTT_MAKER_SERVER_NAME) * 2 + strlen(body);
		fflush(stdout);
		request = malloc(request_length);
		snprintf(request, request_length, "POST https://%s/trigger/%s/with/key/%s HTTP/1.1\n"
			"Host: %s\n"
			"Content-Type: application/json\n"
			"Content-length: %d\n\n"
			"%s",
			IFTTT_MAKER_SERVER_NAME, event, _key, IFTTT_MAKER_SERVER_NAME, strlen(body), body);		
	}
	
	// sending the request
	#ifdef IFTTT_MAKER_DEBUG_ON
		printf("sending %s\n", request);
	#endif
	while((_ret = mbedtls_ssl_write(&ssl, (const unsigned char *)request, strlen(request))) <= 0) 
		{
            if(_ret != MBEDTLS_ERR_SSL_WANT_READ && _ret != MBEDTLS_ERR_SSL_WANT_WRITE)
            {
				#ifdef IFTTT_MAKER_DEBUG_ON
					printf("mbedtls_ssl_write returned -0x%x\n", -_ret);
				#endif
                return IFTTT_MAKER_ERR_SEND;
            }
        }
	#ifdef IFTTT_MAKER_DEBUG_ON
		printf("mbedtls_ssl_write\n");
	#endif

	// parsing the response
	char buf[500];
	int len;
	int return_code = IFTTT_MAKER_ERR_UNKNOWN;
	
	do
        {
            len = sizeof(buf) - 1;
            bzero(buf, sizeof(buf));
            _ret = mbedtls_ssl_read(&ssl, (unsigned char *)buf, len);

			if(_ret <= 0) break;
			
			#ifdef IFTTT_MAKER_DEBUG_ON
				printf("response %s\n", buf);
			#endif
			
			if(strstr(buf, "Congratulations!") != NULL) {
				return_code = IFTTT_MAKER_OK;
				break;
			}
			else if(strstr(buf, "You sent an invalid key.") != NULL) {
				return_code = IFTTT_MAKER_ERR_KEY;	
				break;
			}
        } while(1);	

	// close connection
	mbedtls_ssl_close_notify(&ssl);
	mbedtls_ssl_session_reset(&ssl);
    mbedtls_net_free(&server_fd);
	
	// free memory
	if(body) free(body);
	free(request);
	
	return return_code;
}
