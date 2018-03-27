/*
 * libFCGI responder for basic PAM-authentication
 */

#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <netdb.h>
#include <pthread.h>
#ifdef _GNU_SOURCE
#	include <sched.h>
#endif /* _GNU_SOURCE */
#include <errno.h>
#include <sysexits.h>

#include <sys/types.h>
#include <security/pam_appl.h>

#include "fcgi_config.h"
#include "fcgiapp.h"

#include "base64.h"


static const char * _pam_service_name = NULL;
static const char * _realm = NULL;
static unsigned long _nproc = 0;
static const char *_domain = NULL;


/* send a 500 response, and log the fprintf-style parameters */
static
void
_req_error500(FCGX_Request *req, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	FCGX_VFPrintF(req->err, fmt, ap);
	va_end(ap);

	FCGX_PutS("Status: 500 Internal Server Error\r\n"
	          "Content-type: text/plain\r\n"
	          "\r\n", req->out);
}


/* write a realm to a stream, sneaking in escapes before double quotes */
static
int
_stream_realm_escaped(FCGX_Stream *stream, const char *realm)
{
	const char *end = realm;

	while (*realm) {
		while (*end && *end != '"') {
			end++;
		}

		if (FCGX_PutStr(realm, end - realm, stream) < 0) {
			return -1;
		}

		realm = end;
		if (*end) {
			if (FCGX_PutStr("\\", 1, stream) < 0 ) {
				return -1;
			}

			end++;
		}
	}

	return 0;
}


/* request authentication */
static
void
_req_auth401(FCGX_Request *req)
{
	const char *realm = NULL;

	realm = FCGX_GetParam("REALM", req->envp);
	if (realm == NULL) {
		realm = _realm;
	}

	FCGX_PutS("Status: 401 Unauthorized\r\n"
	          "WWW-Authenticate: Basic realm=\"", req->out);
	_stream_realm_escaped(req->out, realm);
	FCGX_PutS("\"\r\n"
	          "Content-type: text/plain\r\n"
	          "\r\n", req->out);
}


static
void
_req_auth426(FCGX_Request *req, const char *tok)
{
	FCGX_FPrintF(req->out,
	             "Status: 426 Upgrade Required\r\n"
	             "Upgrade: %s\r\n"
	             "\r\n",
	             tok);
}


static
void
_req_ok200(FCGX_Request *req)
{
	FCGX_PutS("Content-type: text/plain\r\n"
	          "\r\n", req->out);
}


struct conv_data {
	char *username;
	char *password;
};


static
int _conv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
{
	struct conv_data *conv_data = (struct conv_data *)appdata_ptr;
	struct pam_response *response = NULL;
	int i;

	if (resp == NULL
	||  msg == NULL
	||  conv_data == NULL)
		return PAM_CONV_ERR;

	response = calloc(num_msg, sizeof *response);
	if (response == NULL)
		return PAM_CONV_ERR;

	for (i = 0; i < num_msg; i++) {
		switch (msg[i]->msg_style) {
		case PAM_PROMPT_ECHO_ON:
			response[i].resp = strdup(conv_data->username);
			break;

		case PAM_PROMPT_ECHO_OFF:
			response[i].resp = strdup(conv_data->password);
			break;

		case PAM_TEXT_INFO:
		case PAM_ERROR_MSG:
			/* ignore these */
			break;

		default: /* is to forget */
			/* something unknowable happened, roll back time and give up */
			while (i--) {
				if (response[i].resp) {
					memset(response[i].resp, 0, strlen(response[i].resp));
					free(response[i].resp);
					response[i].resp = NULL;
				}
			}
			free(response);
			return PAM_CONV_ERR;
		}
	}

	*resp = response;
	return PAM_SUCCESS;
}


/* for every single request... */
static
void
_handle_request(FCGX_Request *req)
{
	pam_handle_t *pamh = NULL;
	struct pam_conv pam_conv;
	const char *https;
	const char *remote_addr;
	const char *authorization;
	size_t authorization_len;
	char *auth_buf;
	size_t auth_buf_len;
	char *domain;
	int r;
	int auth_result;

	struct conv_data conv_data;

	https = FCGX_GetParam("HTTPS", req->envp);
	if (https == NULL
	||  strcmp("on", https)) {
		FCGX_PutS("refusing unsecured request\r\n", req->err);
		_req_auth426(req, "TLS/1.2");
		return;
	}

	authorization = FCGX_GetParam("HTTP_AUTHORIZATION", req->envp);
	if (authorization == NULL
	||  strncmp(authorization, "Basic ", 6)) {
		_req_auth401(req);
		return;
	}

	authorization += 6;
	authorization_len = strlen(authorization);

	/* I believe this will always be ample room for the base64-decoded auth */
	auth_buf_len = (((authorization_len + 3) / 4) * 3) + 1;
	auth_buf = malloc(auth_buf_len);
	if (auth_buf == NULL) {
		_req_error500(req, "%s:%s\r\n", "malloc", strerror(errno));
		return;
	}

/*
	A #define, out here?  Forfend!
	ZERO_FREE handles nulling-out the auth_buf before releasing it.
	It is undefined below, after auth_buf is no longer used.
*/
#define ZERO_FREE(buf,len) do { memset((buf), 0, (len)); (len) = 0; free((buf)); } while (0)

	if (base64decode(authorization, authorization_len, (unsigned char *)auth_buf, &auth_buf_len)) {
		_req_auth401(req);
		ZERO_FREE(auth_buf, auth_buf_len);
		return;
	}

	auth_buf[auth_buf_len] = '\0';

	conv_data.username = auth_buf;
	conv_data.password = strchr(conv_data.username, ':');
	if (conv_data.password == NULL) {
		_req_auth401(req);
		ZERO_FREE(auth_buf, auth_buf_len);
		return;
	}
	*(conv_data.password) = '\0';
	conv_data.password += 1;

	if (_domain
	&&  (domain = strchr(conv_data.username, '@')) != NULL) {
		*domain = '\0';
		domain += 1;
		if (*_domain != '*'
		&&  strncmp(domain, _domain, auth_buf_len - (domain - conv_data.username)) != 0) {
			_req_auth401(req);
			ZERO_FREE(auth_buf, auth_buf_len);
			return;
		}
	}

	pam_conv.conv = &_conv;
	pam_conv.appdata_ptr = &conv_data;

	r = pam_start(_pam_service_name, conv_data.username, &pam_conv, &pamh);
	if (r != PAM_SUCCESS) {
		_req_error500(req, "%s:%s\r\n", "pam_start", pam_strerror(pamh, r));
		ZERO_FREE(auth_buf, auth_buf_len);
		return;
	}

	remote_addr = FCGX_GetParam("REMOTE_ADDR", req->envp);
	if (remote_addr && *remote_addr) {
		r = pam_set_item(pamh, PAM_RHOST, remote_addr);
		if (r != PAM_SUCCESS) {
			_req_error500(req, "%s:%s\r\n", "pam_set_item", pam_strerror(pamh, r));
			ZERO_FREE(auth_buf, auth_buf_len);
			return;
		}
	}

	auth_result = pam_authenticate(pamh, PAM_SILENT|PAM_DISALLOW_NULL_AUTHTOK);

	if (auth_result == PAM_SUCCESS) {
		auth_result = pam_acct_mgmt(pamh, PAM_SILENT|PAM_DISALLOW_NULL_AUTHTOK);
		if (auth_result != PAM_SUCCESS) {
			FCGX_FPrintF(req->err, "PAM: user '%s' denied: %s\r\n", conv_data.username, pam_strerror(pamh, auth_result));
		}
	} else {
		FCGX_FPrintF(req->err, "PAM: user '%s' not authenticated: %s\r\n", conv_data.username, pam_strerror(pamh, auth_result));
	}

	ZERO_FREE(auth_buf, auth_buf_len);

#undef ZERO_FREE

	r = pam_end(pamh, r);
	if (r != PAM_SUCCESS) {
		_req_error500(req, "%s:%s\r\n", "pam_end", strerror(errno));
		return;
	}

	if (auth_result == PAM_ABORT) {
		_req_error500(req, "PAM_ABORT\r\n");
		FCGX_ShutdownPending();
		return;
	}

	if (auth_result != PAM_SUCCESS) {
		_req_auth401(req);
		return;
	}

	_req_ok200(req);
}


#ifdef _GNU_SOURCE
#define NPROC _nprocessors_sched
static
unsigned long
_nprocessors_sched(void)
{
	cpu_set_t cs;
	int r;

	CPU_ZERO(&cs);
	r = sched_getaffinity(0, sizeof(cs), &cs);
	if (r != 0) {
		fprintf(stderr, "%s:%s\n", "sched_getaffinity", strerror(errno));
		return 0;
	}
	return CPU_COUNT(&cs);
}
#endif /* _GNU_SOURCE */


#ifdef _SC_NPROCESSORS_ONLN
#define NPROC _nprocessors_sysconf
static
unsigned long
_nprocessors_sysconf(void)
{
	long n;

	n = sysconf(_SC_NPROCESSORS_ONLN);
	if (n < 0 && errno == EINVAL) {
		fprintf(stderr, "%s(%s):%s\n", "sysconf", "_SC_NPROCESSORS_ONLN", strerror(errno));
		return 0;
	}

	return (unsigned)n;
}
#endif /* _SC_NPROCESSORS_ONLN */


#ifndef NPROC
#define NPROC _nprocessors_default
static
unsigned long
_nprocessors_default(void)
{
	return 1;
}
#endif /* ! NPROC */


static
void *
_worker(void *data)
{
#ifdef NEED_ACCEPT_LOCK
	static pthread_mutex_t accept_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif /* NEED_ACCEPT_LOCK */
	FCGX_Request request;

	(void)data;

	FCGX_InitRequest(&request, 0, 0);

	for (;;) {
#ifdef NEED_ACCEPT_LOCK
		int r;
#endif /* NEED_ACCEPT_LOCK */
		int rc = -1;

#ifdef NEED_ACCEPT_LOCK
		if ((r = pthread_mutex_lock(&accept_mutex))) {
			FCGX_FPrintF(request.err, "%s:%s\n", "pthread_mutex_lock", strerror(r));
		} else {
#endif /* NEED_ACCEPT_LOCK */
			rc = FCGX_Accept_r(&request);
#ifdef NEED_ACCEPT_LOCK
		}
		if ((r = pthread_mutex_unlock(&accept_mutex))) {
			FCGX_FPrintF(request.err, "%s:%s\n", "pthread_mutex_unlock", strerror(r));
		}
#endif /* NEED_ACCEPT_LOCK */
		if (rc < 0)
			break;

		_handle_request(&request);

		FCGX_Finish_r(&request);
	}

	return NULL;
}


#define USAGE_FLAG_FULL (1<<0)
static
void
_usage(const char *prog, unsigned flags)
{
	FILE *f = (flags & USAGE_FLAG_FULL) ? stdout : stderr;

	fprintf(f, "Usage: %s [-s service_name] [-r realm] [-n num_threads] [-d domain]\n", prog);

	if (flags & USAGE_FLAG_FULL) {
		fprintf(f, "\nOptions:\n"
		           "\t-s service_name -- set the PAM service name to use, default: '%s'\n"
		           "\t-r realm        -- set the default authentication realm, default: '%s'\n"
		           "\t-n num_threads  -- number of processing threads, default: %lu (detected number of cpus)\n"
			   "\t-d domain       -- username@domain will check PAM for username if domain matches\n"
		           "\n",
		           _pam_service_name,
		           _realm,
		           _nproc
		);
		fprintf(f, "\tPer-request, the realm may be supplied as the fastcgi REALM parameter."
		           "  If one is not present, the globally-specified realm (or default) is used.\n");
	}
}


static
const char *
_fqdn(void)
{
	static char hostname[_POSIX_HOST_NAME_MAX];
	struct addrinfo hints, *info, *p;
	int gai_result;

	hostname[sizeof hostname - 1] = '\0';
	gethostname(hostname, sizeof hostname - 1);

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_CANONNAME;

	gai_result = getaddrinfo(hostname, "http", &hints, &info);
	if (gai_result != 0) {
		fprintf(stderr, "%s:%s\n", "getaddrinfo", gai_strerror(gai_result));
		return hostname;
	}

	for (p = info; p != NULL; p = p->ai_next) {
		if (p->ai_canonname && *(p->ai_canonname)) {
			hostname[sizeof hostname - 1] = '\0';
			strncpy(hostname, p->ai_canonname, sizeof hostname - 1);
			break;
		}
	}

	freeaddrinfo(info);

	return hostname;
}


int
main(int argc, char *argv[])
{
	unsigned long thd_n;
	char *prog;
	char *x;
	pthread_t *thd;
	char *realm = NULL;
	char *service = NULL;
	char *domain = NULL;
	long n = 0;
	int c;

	/* initialize our defaults */
	_nproc = NPROC();
	if (_nproc < 1)
		_nproc = 1;

	_realm = _fqdn();

	prog = strrchr(argv[0], '/');
	prog = (prog && *(prog + 1)) ? (prog + 1) : argv[0];
	_pam_service_name = prog;

	while ((c = getopt(argc, argv, "hs:r:n:d:")) != -1) {
		switch (c) {
			case 'h':
				_usage(prog, USAGE_FLAG_FULL);
				exit(EX_OK);
			break;

			case 's':
				if (*optarg == '\0') {
					fprintf(stderr, "invalid value '%s'\n", optarg);
					exit(EX_DATAERR);
				}
				service = optarg;
			break;

			case 'r':
				if (*optarg == '\0') {
					fprintf(stderr, "invalid value '%s'\n", optarg);
					exit(EX_DATAERR);
				}
				realm = optarg;
			break;

			case 'n':
				n = strtol(optarg, &x, 0);
				if (*optarg == '\0' || *x != '\0') {
					fprintf(stderr, "invalid value '%s'\n", optarg);
					exit(EX_DATAERR);
				}
				if (n <= 0
				||  ((n == LONG_MIN || n == LONG_MAX) && errno == ERANGE)) {
					fprintf(stderr, "value '%s' out of range\n", optarg);
					exit(EX_DATAERR);
				}
			break;

			case 'd':
				domain = optarg;
			break;

			default: /* '?' */
				_usage(prog, 0);
				exit(EX_USAGE);
			break;
		}
	}

	if (argc - optind != 0) {
		_usage(prog, 0);
		exit(EX_USAGE);
	}

	if (service != NULL) {
		_pam_service_name = service;
	}

	if (realm != NULL) {
		_realm = realm;
	}

	if (n) {
		_nproc = n;
	}
	thd_n = _nproc - 1;

	if (domain != NULL) {
		_domain = domain;
	}

	fprintf(stderr, "starting %s realm: '%s' service: '%s' threads: '%lu'\r\n",
	        prog,
		_realm,
		_pam_service_name,
		_nproc);
	fflush(stderr);

	FCGX_Init();

	if (thd_n > 0) {
		thd = calloc(thd_n, sizeof *thd);
		if (thd == NULL) {
			fprintf(stderr, "%s:%s\n", "calloc", strerror(errno));
			exit(EX_OSERR);
		}
	} else {
		thd = NULL;
	}

	for (n = thd_n; n > 0; n--) {
		int r;

		r = pthread_create(&thd[n - 1], NULL, _worker, (void *)n);
		if (r) {
			fprintf(stderr, "%s:%s\n", "pthread_create", strerror(r));
			exit(EX_OSERR);
		}
	}

	_worker((void *)n);

	for (n = thd_n; n > 0; n--) {
		int r;

		r = pthread_join(thd[n - 1], NULL);
		if (r) {
			fprintf(stderr, "%s:%s\n", "pthread_join", strerror(r));
			exit(EX_OSERR);
		}
	}

	exit(EX_OK);
}
