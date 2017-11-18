/*
 * SSLsplit - transparent and scalable SSL/TLS interception
 * Copyright (c) 2009-2014, Daniel Roethlisberger <daniel@roe.ch>
 * All rights reserved.
 * http://www.roe.ch/SSLsplit
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "pxyconn.h"

#include "pxysslshut.h"
#include "cachemgr.h"
#include "ssl.h"
#include "opts.h"
#include "sys.h"
#include "util.h"
#include "base64.h"
#include "url.h"
#include "log.h"
#include "attrib.h"
#include "proc.h"
#include "format.h"

#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/timeb.h>

#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include "./libevent/include/event2/bufferevent_ssl.h"

#include <event2/buffer.h>
#include <event2/thread.h>
#include <event2/dns.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/md5.h>


/*
 * Maximum size of data to buffer per connection direction before
 * temporarily stopping to read data from the other end.
 */
#define OUTBUF_LIMIT	(128*1024*1024)

/*
 * Print helper for logging code.
 */
#define STRORDASH(x)	(((x)&&*(x))?(x):"-")

/*
 * Context used for all server sessions.
 */
#ifdef USE_SSL_SESSION_ID_CONTEXT
static unsigned long ssl_session_context = 0x31415926;
#endif /* USE_SSL_SESSION_ID_CONTEXT */


/*
 * Proxy connection context state, describes a proxy connection
 * with source and destination socket bufferevents, SSL context and
 * other session state.  One of these exists per handled proxy
 * connection.
 */

/* single dst or src socket bufferevent descriptor */
typedef struct pxy_conn_desc {
	struct bufferevent *bev;
	SSL *ssl;
	unsigned int closed : 1;
} pxy_conn_desc_t;

#ifdef HAVE_LOCAL_PROCINFO
/* local process data - filled in iff pid != -1 */
typedef struct pxy_conn_lproc_desc {
	struct sockaddr_storage srcaddr;
	socklen_t srcaddrlen;

	pid_t pid;
	uid_t uid;
	gid_t gid;

	/* derived log strings */
	char *exec_path;
	char *user;
	char *group;
} pxy_conn_lproc_desc_t;
#endif /* HAVE_LOCAL_PROCINFO */

/* actual proxy connection state consisting of two connection descriptors,
 * connection-wide state and the specs and options */
typedef struct pxy_conn_ctx {
	/* per-connection state */
	struct pxy_conn_desc src;
	struct pxy_conn_desc dst;

	/* status flags */
	unsigned int immutable_cert : 1;  /* 1 if the cert cannot be changed */
	unsigned int connected : 1;       /* 0 until both ends are connected */
	unsigned int seen_req_header : 1; /* 0 until request header complete */
	unsigned int seen_resp_header : 1;  /* 0 until response hdr complete */
	unsigned int sent_http_conn_close : 1;   /* 0 until Conn: close sent */
	unsigned int passthrough : 1;      /* 1 if SSL passthrough is active */
	unsigned int ocsp_denied : 1;                /* 1 if OCSP was denied */
	unsigned int enomem : 1;                       /* 1 if out of memory */
	unsigned int req_ssl : 1; 				/* 1 if first request is ssl */
	unsigned int sni_peek_retries : 6;       /* max 64 SNI parse retries */
	unsigned int session;

	/* server name indicated by client in SNI TLS extension */
	char *sni;

	/* server name and port indicated by CONNECT METHOD */
	char *conn_host;
	int conn_port; /* 443 */

	/* log strings from socket */
	char *src_str;
	char *dst_str;

	/* log strings from HTTP request */
	char *http_method;
	char *http_uri;
	char *http_host;
	char *http_content_type;

	/* log strings from HTTP response */
	char *http_status_code;
	char *http_status_text;
	char *http_content_length;

	/* log strings from SSL context */
	char *ssl_names;

	char* gdriveRsp1;
	char* gdriveRsp2;
	size_t rsp_end;
	char* gdriveRsp3;
	char* gdriveRsp4;
	char* Uploader_ID;
	unsigned long long total;
	unsigned long long total_recv;
	unsigned long long current_recv;
	unsigned long long start;
	unsigned long long end;

	char* str_start;
	char* str_end;

	unsigned char *fragment;
	unsigned int gdrive:1;

#ifdef HAVE_LOCAL_PROCINFO
	/* local process information */
	pxy_conn_lproc_desc_t lproc;
#endif /* HAVE_LOCAL_PROCINFO */

	/* content log context */
	log_content_ctx_t *logctx;

	/* store fd and fd event while connected is 0 */
	evutil_socket_t fd;
	struct event *ev;

	/* original destination address, family and certificate */
	struct sockaddr_storage addr;
	socklen_t addrlen;
	int af;
	X509 *origcrt;

	/* references to event base and configuration */
	struct event_base *evbase;
	struct evdns_base *dnsbase;
	int thridx;
	pxy_thrmgr_ctx_t *thrmgr;
	proxyspec_t *spec;
	opts_t *opts;
} pxy_conn_ctx_t;

#define WANT_CONNECT_LOG(ctx)	((ctx)->opts->connectlog||!(ctx)->opts->detach)
#define WANT_CONTENT_LOG(ctx)	((ctx)->opts->contentlog&&!(ctx)->passthrough)

/*
 * Get current time
 * */
double time_milli()
{
	struct timeb tmb;
	ftime(&tmb);
	return (double)tmb.time + (double)tmb.millitm / 1000;
}

void print_timer(char *string, double time)
{
	fprintf(stderr,"%s %.04f\n", string, time);
}


static pxy_conn_ctx_t *
pxy_conn_ctx_new(proxyspec_t *spec, opts_t *opts,
                 pxy_thrmgr_ctx_t *thrmgr, evutil_socket_t fd)
                 MALLOC NONNULL(1,2,3);
static pxy_conn_ctx_t *
pxy_conn_ctx_new(proxyspec_t *spec, opts_t *opts,
                 pxy_thrmgr_ctx_t *thrmgr, evutil_socket_t fd)
{
	pxy_conn_ctx_t *ctx = malloc(sizeof(pxy_conn_ctx_t));
	if (!ctx)
		return NULL;
	memset(ctx, 0, sizeof(pxy_conn_ctx_t));
	ctx->spec = spec;
	ctx->opts = opts;
	ctx->fd = fd;
	ctx->thridx = pxy_thrmgr_attach(thrmgr, &ctx->evbase, &ctx->dnsbase);
	ctx->thrmgr = thrmgr;
#ifdef HAVE_LOCAL_PROCINFO
	ctx->lproc.pid = -1;
#endif /* HAVE_LOCAL_PROCINFO */
#ifdef DEBUG_PROXY
	if (OPTS_DEBUG(opts)) {
		log_dbg_printf("%p             pxy_conn_ctx_new\n",
		               (void*)ctx);
	}
#endif /* DEBUG_PROXY */
	return ctx;
}

static void
pxy_conn_ctx_free(pxy_conn_ctx_t *ctx) NONNULL(1);
static void
pxy_conn_ctx_free(pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	if (OPTS_DEBUG(ctx->opts)) {
		log_dbg_printf("%p             pxy_conn_ctx_free\n",
		                (void*)ctx);
	}
#endif /* DEBUG_PROXY */
	pxy_thrmgr_detach(ctx->thrmgr, ctx->thridx);
	if (ctx->src_str) {
		free(ctx->src_str);
	}
	if (ctx->dst_str) {
		free(ctx->dst_str);
	}
	if (ctx->http_method) {
		free(ctx->http_method);
	}
	if (ctx->http_uri) {
		free(ctx->http_uri);
	}
	if (ctx->http_host) {
		free(ctx->http_host);
	}
	if (ctx->http_content_type) {
		free(ctx->http_content_type);
	}
	if (ctx->http_status_code) {
		free(ctx->http_status_code);
	}
	if (ctx->http_status_text) {
		free(ctx->http_status_text);
	}
	if (ctx->http_content_length) {
		free(ctx->http_content_length);
	}
	if (ctx->ssl_names) {
		free(ctx->ssl_names);
	}
#ifdef HAVE_LOCAL_PROCINFO
	if (ctx->lproc.exec_path) {
		free(ctx->lproc.exec_path);
	}
	if (ctx->lproc.user) {
		free(ctx->lproc.user);
	}
	if (ctx->lproc.group) {
		free(ctx->lproc.group);
	}
#endif /* HAVE_LOCAL_PROCINFO */
	if (ctx->origcrt) {
		X509_free(ctx->origcrt);
	}
	if (ctx->ev) {
		event_free(ctx->ev);
	}
	if (ctx->sni) {
		free(ctx->sni);
	}
	if(ctx->conn_host) {
		free(ctx->conn_host);
	}
	if (WANT_CONTENT_LOG(ctx) && ctx->logctx) {
		if (log_content_close(&ctx->logctx) == -1) {
			log_err_printf("Warning: Content log close failed\n");
		}
	}
	free(ctx);
}


/* forward declaration of libevent callbacks */
static void pxy_bev_readcb(struct bufferevent *, void *);
static void pxy_bev_writecb(struct bufferevent *, void *);
static void pxy_bev_eventcb(struct bufferevent *, short, void *);
static void pxy_fd_readcb(evutil_socket_t, short, void *);

/* forward declaration of OpenSSL callbacks */
#ifndef OPENSSL_NO_TLSEXT
static int pxy_ossl_servername_cb(SSL *ssl, int *al, void *arg);
#endif /* !OPENSSL_NO_TLSEXT */
static int pxy_ossl_sessnew_cb(SSL *, SSL_SESSION *);
static void pxy_ossl_sessremove_cb(SSL_CTX *, SSL_SESSION *);
static SSL_SESSION * pxy_ossl_sessget_cb(SSL *, unsigned char *, int, int *);

/*
 * Dump information on a certificate to the debug log.
 */
static void
pxy_debug_crt(X509 *crt)
{
	char *sj = ssl_x509_subject(crt);
	if (sj) {
		log_dbg_printf("Subject DN: %s\n", sj);
		free(sj);
	}

	char *names = ssl_x509_names_to_str(crt);
	if (names) {
		log_dbg_printf("Common Names: %s\n", names);
		free(names);
	}

	unsigned char fpr[SSL_X509_FPRSZ];
	if (ssl_x509_fingerprint_sha1(crt, fpr) == -1) {
		log_err_printf("Warning: Error generating X509 fingerprint\n");
	} else {
		log_dbg_printf("Fingerprint: "     "%02x:%02x:%02x:%02x:"
		               "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:"
		               "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
		               fpr[0],  fpr[1],  fpr[2],  fpr[3],  fpr[4],
		               fpr[5],  fpr[6],  fpr[7],  fpr[8],  fpr[9],
		               fpr[10], fpr[11], fpr[12], fpr[13], fpr[14],
		               fpr[15], fpr[16], fpr[17], fpr[18], fpr[19]);
	}

#ifdef DEBUG_CERTIFICATE
	/* dump certificate */
	log_dbg_print_free(ssl_x509_to_str(crt));
	log_dbg_print_free(ssl_x509_to_pem(crt));
#endif /* DEBUG_CERTIFICATE */
}

static void
pxy_log_connect_nonhttp(pxy_conn_ctx_t *ctx)
{
	char *msg;
#ifdef HAVE_LOCAL_PROCINFO
	char *lpi = NULL;
#endif /* HAVE_LOCAL_PROCINFO */
	int rv;

#ifdef HAVE_LOCAL_PROCINFO
	if (ctx->opts->lprocinfo) {
		rv = asprintf(&lpi, "lproc:%i:%s:%s:%s",
		              ctx->lproc.pid,
		              STRORDASH(ctx->lproc.user),
		              STRORDASH(ctx->lproc.group),
		              STRORDASH(ctx->lproc.exec_path));
		if ((rv < 0) || !lpi) {
			ctx->enomem = 1;
			goto out;
		}
	} else {
		lpi = "";
	}
#endif /* HAVE_LOCAL_PROCINFO */

	if (!ctx->req_ssl || ctx->passthrough) {
		rv = asprintf(&msg, "%s %s %s"
#ifdef HAVE_LOCAL_PROCINFO
		              " %s"
#endif /* HAVE_LOCAL_PROCINFO */
		              "\n",
		              ctx->passthrough ? "passthrough" : "tcp",
		              STRORDASH(ctx->src_str),
		              STRORDASH(ctx->dst_str)
#ifdef HAVE_LOCAL_PROCINFO
		              , lpi
#endif /* HAVE_LOCAL_PROCINFO */
		             );
	} else {
		rv = asprintf(&msg, "ssl %s %s "
		              "sni:%s names:%s "
		              "sproto:%s:%s dproto:%s:%s"
#ifdef HAVE_LOCAL_PROCINFO
		              " %s"
#endif /* HAVE_LOCAL_PROCINFO */
		              "\n",
		              STRORDASH(ctx->src_str),
		              STRORDASH(ctx->dst_str),
		              STRORDASH(ctx->sni),
		              STRORDASH(ctx->ssl_names),
		              SSL_get_version(ctx->src.ssl),
		              SSL_get_cipher(ctx->src.ssl),
		              SSL_get_version(ctx->dst.ssl),
		              SSL_get_cipher(ctx->dst.ssl)
#ifdef HAVE_LOCAL_PROCINFO
		              , lpi
#endif /* HAVE_LOCAL_PROCINFO */
		             );
	}
	if ((rv < 0) || !msg) {
		ctx->enomem = 1;
		goto out;
	}
	if (!ctx->opts->detach) {
		log_err_printf("%s", msg);
	}
	if (ctx->opts->connectlog) {
		if (log_connect_print_free(msg) == -1) {
			free(msg);
			log_err_printf("Warning: Connection logging failed\n");
		}
	} else {
		free(msg);
	}
out:
#ifdef HAVE_LOCAL_PROCINFO
	if (lpi && ctx->opts->lprocinfo) {
		free(lpi);
	}
#endif /* HAVE_LOCAL_PROCINFO */
	return;
}

static void
pxy_log_connect_http(pxy_conn_ctx_t *ctx)
{
	char *msg;
#ifdef HAVE_LOCAL_PROCINFO
	char *lpi = NULL;
#endif /* HAVE_LOCAL_PROCINFO */
	int rv;

#ifdef DEBUG_PROXY
	if (ctx->passthrough) {
		log_err_printf("Warning: pxy_log_connect_http called while in "
		               "passthrough mode\n");
		return;
	}
#endif

#ifdef HAVE_LOCAL_PROCINFO
	if (ctx->opts->lprocinfo) {
		rv = asprintf(&lpi, "lproc:%i:%s:%s:%s",
		              ctx->lproc.pid,
		              STRORDASH(ctx->lproc.user),
		              STRORDASH(ctx->lproc.group),
		              STRORDASH(ctx->lproc.exec_path));
		if ((rv < 0) || !lpi) {
			ctx->enomem = 1;
			goto out;
		}
	}
#endif /* HAVE_LOCAL_PROCINFO */

	if (!ctx->req_ssl) {
		rv = asprintf(&msg, "http %s %s %s %s %s %s %s"
#ifdef HAVE_LOCAL_PROCINFO
		              " %s"
#endif /* HAVE_LOCAL_PROCINFO */
		              "%s\n",
		              STRORDASH(ctx->src_str),
		              STRORDASH(ctx->dst_str),
		              STRORDASH(ctx->http_host),
		              STRORDASH(ctx->http_method),
		              STRORDASH(ctx->http_uri),
		              STRORDASH(ctx->http_status_code),
		              STRORDASH(ctx->http_content_length),
#ifdef HAVE_LOCAL_PROCINFO
		              lpi,
#endif /* HAVE_LOCAL_PROCINFO */
		              ctx->ocsp_denied ? " ocsp:denied" : "");
	} else {
		rv = asprintf(&msg, "https %s %s %s %s %s %s %s "
		              "sni:%s names:%s "
		              "sproto:%s:%s dproto:%s:%s"
#ifdef HAVE_LOCAL_PROCINFO
		              " %s"
#endif /* HAVE_LOCAL_PROCINFO */
		              "%s\n",
		              STRORDASH(ctx->src_str),
		              STRORDASH(ctx->dst_str),
		              STRORDASH(ctx->http_host),
		              STRORDASH(ctx->http_method),
		              STRORDASH(ctx->http_uri),
		              STRORDASH(ctx->http_status_code),
		              STRORDASH(ctx->http_content_length),
		              STRORDASH(ctx->sni),
		              STRORDASH(ctx->ssl_names),
		              SSL_get_version(ctx->src.ssl),
		              SSL_get_cipher(ctx->src.ssl),
		              SSL_get_version(ctx->dst.ssl),
		              SSL_get_cipher(ctx->dst.ssl),
#ifdef HAVE_LOCAL_PROCINFO
		              lpi,
#endif /* HAVE_LOCAL_PROCINFO */
		              ctx->ocsp_denied ? " ocsp:denied" : "");
	}
	if ((rv < 0 ) || !msg) {
		ctx->enomem = 1;
		goto out;
	}
	if (!ctx->opts->detach) {
		log_err_printf("%s", msg);
	}
	if (ctx->opts->connectlog) {
		if (log_connect_print_free(msg) == -1) {
			free(msg);
			log_err_printf("Warning: Connection logging failed\n");
		}
	} else {
		free(msg);
	}
out:
#ifdef HAVE_LOCAL_PROCINFO
	if (lpi) {
		free(lpi);
	}
#endif /* HAVE_LOCAL_PROCINFO */
	return;
}

/*
 * Called by OpenSSL when a new src SSL session is created.
 * OpenSSL increments the refcount before calling the callback and will
 * decrement it again if we return 0.  Returning 1 will make OpenSSL skip
 * the refcount decrementing.  In other words, return 0 if we did not
 * keep a pointer to the object (which we never do here).
 */
#ifdef WITH_SSLV2
#define MAYBE_UNUSED
#else /* !WITH_SSLV2 */
#define MAYBE_UNUSED UNUSED
#endif /* !WITH_SSLV2 */
static int
pxy_ossl_sessnew_cb(MAYBE_UNUSED SSL *ssl, SSL_SESSION *sess)
#undef MAYBE_UNUSED
{
#ifdef DEBUG_SESSION_CACHE
	log_dbg_printf("===> OpenSSL new session callback:\n");
	if (sess) {
		log_dbg_print_free(ssl_session_to_str(sess));
	} else {
		log_dbg_print("(null)\n");
	}
#endif /* DEBUG_SESSION_CACHE */
#ifdef WITH_SSLV2
	/* Session resumption seems to fail for SSLv2 with protocol
	 * parsing errors, so we disable caching for SSLv2. */
	if (SSL_version(ssl) == SSL2_VERSION) {
		log_err_printf("Warning: Session resumption denied to SSLv2"
		               "client.\n");
		return 0;
	}
#endif /* WITH_SSLV2 */
	if (sess) {
		cachemgr_ssess_set(sess);
	}
	return 0;
}

/*
 * Called by OpenSSL when a src SSL session should be removed.
 * OpenSSL calls SSL_SESSION_free() after calling the callback;
 * we do not need to free the reference here.
 */
static void
pxy_ossl_sessremove_cb(UNUSED SSL_CTX *sslctx, SSL_SESSION *sess)
{
#ifdef DEBUG_SESSION_CACHE
	log_dbg_printf("===> OpenSSL remove session callback:\n");
	if (sess) {
		log_dbg_print_free(ssl_session_to_str(sess));
	} else {
		log_dbg_print("(null)\n");
	}
#endif /* DEBUG_SESSION_CACHE */
	if (sess) {
		cachemgr_ssess_del(sess);
	}
}

/*
 * Called by OpenSSL when a src SSL session is requested by the client.
 */
static SSL_SESSION *
pxy_ossl_sessget_cb(UNUSED SSL *ssl, unsigned char *id, int idlen, int *copy)
{
	SSL_SESSION *sess;

#ifdef DEBUG_SESSION_CACHE
	log_dbg_printf("===> OpenSSL get session callback:\n");
#endif /* DEBUG_SESSION_CACHE */

	*copy = 0; /* SSL should not increment reference count of session */
	sess = cachemgr_ssess_get(id, idlen);

#ifdef DEBUG_SESSION_CACHE
	if (sess) {
		log_dbg_print_free(ssl_session_to_str(sess));
	}
#endif /* DEBUG_SESSION_CACHE */

	log_dbg_printf("SSL session cache: %s\n", sess ? "HIT" : "MISS");
	return sess;
}

/*
 * Create and set up a new SSL_CTX instance for terminating SSL.
 * Set up all the necessary callbacks, the certificate, the cert chain and key.
 */
static SSL_CTX *
pxy_srcsslctx_create(pxy_conn_ctx_t *ctx, X509 *crt, STACK_OF(X509) *chain,
                     EVP_PKEY *key)
{
	SSL_CTX *sslctx = SSL_CTX_new(ctx->opts->sslmethod());
	if (!sslctx)
		return NULL;
	SSL_CTX_set_options(sslctx, SSL_OP_ALL);
#ifdef SSL_OP_TLS_ROLLBACK_BUG
	SSL_CTX_set_options(sslctx, SSL_OP_TLS_ROLLBACK_BUG);
#endif /* SSL_OP_TLS_ROLLBACK_BUG */
#ifdef SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
	SSL_CTX_set_options(sslctx, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
#endif /* SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION */
#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
	SSL_CTX_set_options(sslctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
#endif /* SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS */
#ifdef SSL_OP_NO_TICKET
	SSL_CTX_set_options(sslctx, SSL_OP_NO_TICKET);
#endif /* SSL_OP_NO_TICKET */
#ifdef SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
	SSL_CTX_set_options(sslctx,
	                    SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
#endif /* SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION */
#ifdef SSL_OP_NO_COMPRESSION
	if (!ctx->opts->sslcomp) {
		SSL_CTX_set_options(sslctx, SSL_OP_NO_COMPRESSION);
	}
#endif /* SSL_OP_NO_COMPRESSION */

#ifdef SSL_OP_NO_SSLv2
#ifdef WITH_SSLV2
	if (ctx->opts->no_ssl2) {
#endif /* WITH_SSLV2 */
		SSL_CTX_set_options(sslctx, SSL_OP_NO_SSLv2);
#ifdef WITH_SSLV2
	}
#endif /* WITH_SSLV2 */
#endif /* !SSL_OP_NO_SSLv2 */
#ifdef SSL_OP_NO_SSLv3
	if (ctx->opts->no_ssl3) {
		SSL_CTX_set_options(sslctx, SSL_OP_NO_SSLv3);
	}
#endif /* SSL_OP_NO_SSLv3 */
#ifdef SSL_OP_NO_TLSv1
	if (ctx->opts->no_tls10) {
		SSL_CTX_set_options(sslctx, SSL_OP_NO_TLSv1);
	}
#endif /* SSL_OP_NO_TLSv1 */
#ifdef SSL_OP_NO_TLSv1_1
	if (ctx->opts->no_tls11) {
		SSL_CTX_set_options(sslctx, SSL_OP_NO_TLSv1_1);
	}
#endif /* SSL_OP_NO_TLSv1_1 */
#ifdef SSL_OP_NO_TLSv1_2
	if (ctx->opts->no_tls12) {
		SSL_CTX_set_options(sslctx, SSL_OP_NO_TLSv1_2);
	}
#endif /* SSL_OP_NO_TLSv1_2 */

	SSL_CTX_set_cipher_list(sslctx, ctx->opts->ciphers);
	SSL_CTX_sess_set_new_cb(sslctx, pxy_ossl_sessnew_cb);
	SSL_CTX_sess_set_remove_cb(sslctx, pxy_ossl_sessremove_cb);
	SSL_CTX_sess_set_get_cb(sslctx, pxy_ossl_sessget_cb);
	SSL_CTX_set_session_cache_mode(sslctx, SSL_SESS_CACHE_SERVER |
	                                       SSL_SESS_CACHE_NO_INTERNAL);
#ifdef USE_SSL_SESSION_ID_CONTEXT
	SSL_CTX_set_session_id_context(sslctx, (void *)(&ssl_session_context),
	                                       sizeof(ssl_session_context));
#endif /* USE_SSL_SESSION_ID_CONTEXT */
#ifndef OPENSSL_NO_TLSEXT
	SSL_CTX_set_tlsext_servername_callback(sslctx, pxy_ossl_servername_cb);
	SSL_CTX_set_tlsext_servername_arg(sslctx, ctx);
#endif /* !OPENSSL_NO_TLSEXT */
#ifndef OPENSSL_NO_DH
	if (ctx->opts->dh) {
		SSL_CTX_set_tmp_dh(sslctx, ctx->opts->dh);
	} else if (EVP_PKEY_type(key->type) != EVP_PKEY_RSA) {
		SSL_CTX_set_tmp_dh_callback(sslctx, ssl_tmp_dh_callback);
	}
#endif /* !OPENSSL_NO_DH */
#ifndef OPENSSL_NO_ECDH
	if (ctx->opts->ecdhcurve) {
		EC_KEY *ecdh = ssl_ec_by_name(ctx->opts->ecdhcurve);
		SSL_CTX_set_tmp_ecdh(sslctx, ecdh);
		EC_KEY_free(ecdh);
	} else if (EVP_PKEY_type(key->type) != EVP_PKEY_RSA) {
		EC_KEY *ecdh = ssl_ec_by_name(NULL);
		SSL_CTX_set_tmp_ecdh(sslctx, ecdh);
		EC_KEY_free(ecdh);
	}
#endif /* !OPENSSL_NO_ECDH */
	SSL_CTX_use_certificate(sslctx, crt);
	SSL_CTX_use_PrivateKey(sslctx, key);
	for (int i = 0; i < sk_X509_num(chain); i++) {
		X509 *c = sk_X509_value(chain, i);
		ssl_x509_refcount_inc(c); /* next call consumes a reference */
		SSL_CTX_add_extra_chain_cert(sslctx, c);
	}

#ifdef DEBUG_SESSION_CACHE
	if (OPTS_DEBUG(ctx->opts)) {
		int mode = SSL_CTX_get_session_cache_mode(sslctx);
		log_dbg_printf("SSL session cache mode: %08x\n", mode);
		if (mode == SSL_SESS_CACHE_OFF)
			log_dbg_printf("SSL_SESS_CACHE_OFF\n");
		if (mode & SSL_SESS_CACHE_CLIENT)
			log_dbg_printf("SSL_SESS_CACHE_CLIENT\n");
		if (mode & SSL_SESS_CACHE_SERVER)
			log_dbg_printf("SSL_SESS_CACHE_SERVER\n");
		if (mode & SSL_SESS_CACHE_NO_AUTO_CLEAR)
			log_dbg_printf("SSL_SESS_CACHE_NO_AUTO_CLEAR\n");
		if (mode & SSL_SESS_CACHE_NO_INTERNAL_LOOKUP)
			log_dbg_printf("SSL_SESS_CACHE_NO_INTERNAL_LOOKUP\n");
		if (mode & SSL_SESS_CACHE_NO_INTERNAL_STORE)
			log_dbg_printf("SSL_SESS_CACHE_NO_INTERNAL_STORE\n");
	}
#endif /* DEBUG_SESSION_CACHE */

	return sslctx;
}

static cert_t *
pxy_srccert_create(pxy_conn_ctx_t *ctx)
{
	cert_t *cert = NULL;

	if (ctx->opts->tgcrtdir) {
		if (ctx->sni) {
			cert = cachemgr_tgcrt_get(ctx->sni);
			if (!cert) {
				char *wildcarded;
				wildcarded = ssl_wildcardify(ctx->sni);
				if (!wildcarded) {
					ctx->enomem = 1;
					return NULL;
				}
				cert = cachemgr_tgcrt_get(wildcarded);
				free(wildcarded);
			}
			if (cert && OPTS_DEBUG(ctx->opts)) {
				log_dbg_printf("Target cert by SNI\n");
			}
		} else if (ctx->origcrt) {
			char **names = ssl_x509_names(ctx->origcrt);
			for (char **p = names; *p; p++) {
				if (!cert) {
					cert = cachemgr_tgcrt_get(*p);
				}
				if (!cert) {
					char *wildcarded;
					wildcarded = ssl_wildcardify(*p);
					if (!wildcarded) {
						ctx->enomem = 1;
					} else {
						cert = cachemgr_tgcrt_get(
						       wildcarded);
						free(wildcarded);
					}
				}
				free(*p);
			}
			free(names);
			if (ctx->enomem) {
				return NULL;
			}
			if (cert && OPTS_DEBUG(ctx->opts)) {
				log_dbg_printf("Target cert by origcrt\n");
			}
		}

		if (cert) {
			ctx->immutable_cert = 1;
		}
	}

	if (!cert && ctx->origcrt && ctx->opts->key) {
		cert = cert_new();

		cert->crt = cachemgr_fkcrt_get(ctx->origcrt);
		if (cert->crt) {
			if (OPTS_DEBUG(ctx->opts))
				log_dbg_printf("Certificate cache: HIT\n");
		} else {
			if (OPTS_DEBUG(ctx->opts))
				log_dbg_printf("Certificate cache: MISS\n");
			cert->crt = ssl_x509_forge(ctx->opts->cacrt,
			                           ctx->opts->cakey,
			                           ctx->origcrt, NULL,
			                           ctx->opts->key);
			cachemgr_fkcrt_set(ctx->origcrt, cert->crt);
		}
		cert_set_key(cert, ctx->opts->key);
		cert_set_chain(cert, ctx->opts->chain);
	}

	return cert;
}

/*
 * Create new SSL context for the incoming connection, based on the original
 * destination SSL certificate.
 * Returns NULL if no suitable certificate could be found.
 */
static SSL *
pxy_srcssl_create(pxy_conn_ctx_t *ctx, SSL *origssl)
{
	cert_t *cert;

	cachemgr_dsess_set((struct sockaddr*)&ctx->addr,
	                   ctx->addrlen, ctx->sni,
	                   SSL_get0_session(origssl));

	ctx->origcrt = SSL_get_peer_certificate(origssl);

	if (OPTS_DEBUG(ctx->opts)) {
		if (ctx->origcrt) {
			log_dbg_printf("===> Original server certificate:\n");
			pxy_debug_crt(ctx->origcrt);
		} else {
			log_dbg_printf("===> Original server has no cert!\n");
		}
	}

	cert = pxy_srccert_create(ctx);
	if (!cert)
		return NULL;

	if (OPTS_DEBUG(ctx->opts)) {
		log_dbg_printf("===> Forged server certificate:\n");
		pxy_debug_crt(cert->crt);
	}

	if (WANT_CONNECT_LOG(ctx)) {
		ctx->ssl_names = ssl_x509_names_to_str(ctx->origcrt ?
		                                       ctx->origcrt :
		                                       cert->crt);
		if (!ctx->ssl_names)
			ctx->enomem = 1;
	}

	SSL_CTX *sslctx = pxy_srcsslctx_create(ctx, cert->crt, cert->chain,
	                                       cert->key);
	cert_free(cert);
	if (!sslctx) {
		ctx->enomem = 1;
		return NULL;
	}
	SSL *ssl = SSL_new(sslctx);
	SSL_CTX_free(sslctx); /* SSL_new() increments refcount */
	if (!ssl) {
		ctx->enomem = 1;
		return NULL;
	}
#ifdef SSL_MODE_RELEASE_BUFFERS
	/* lower memory footprint for idle connections */
	SSL_set_mode(ssl, SSL_get_mode(ssl) | SSL_MODE_RELEASE_BUFFERS);
#endif /* SSL_MODE_RELEASE_BUFFERS */
	return ssl;
}

#ifndef OPENSSL_NO_TLSEXT
/*
 * OpenSSL servername callback, called when OpenSSL receives a servername
 * TLS extension in the clientHello.  Must switch to a new SSL_CTX with
 * a different certificate if we want to replace the server cert here.
 * We generate a new certificate if the current one does not match the
 * supplied servername.  This should only happen if the original destination
 * server supplies a certificate which does not match the server name we
 * indicate to it.
 */
static int
pxy_ossl_servername_cb(SSL *ssl, UNUSED int *al, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	const char *sn;
	X509 *sslcrt;

	if (!(sn = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name)))
		return SSL_TLSEXT_ERR_NOACK;

	if (OPTS_DEBUG(ctx->opts)) {
		if (!!strcmp(sn, ctx->sni)) {
			/*
			 * This may happen if the client resumes a session, but
			 * uses a different SNI hostname when resuming than it
			 * used when the session was created.  OpenSSL
			 * correctly ignores the SNI in the ClientHello in this
			 * case, but since we have already sent the SNI onwards
			 * to the original destination, there is no way back.
			 * We log an error and hope this never happens.
			 */
			log_err_printf("Warning: SNI parser yielded different "
			               "hostname than OpenSSL callback for "
			               "the same ClientHello message: "
			               "[%s] != [%s]\n", ctx->sni, sn);
		}
	}

	/* generate a new certificate with sn as additional altSubjectName
	 * and replace it both in the current SSL ctx and in the cert cache */
	if (!ctx->immutable_cert &&
	    !ssl_x509_names_match((sslcrt = SSL_get_certificate(ssl)), sn)) {
		X509 *newcrt;
		SSL_CTX *newsslctx;

		if (OPTS_DEBUG(ctx->opts)) {
			log_dbg_printf("Certificate cache: UPDATE "
			               "(SNI mismatch)\n");
		}
		newcrt = ssl_x509_forge(ctx->opts->cacrt, ctx->opts->cakey,
		                        sslcrt, sn, ctx->opts->key);
		if (!newcrt) {
			ctx->enomem = 1;
			return SSL_TLSEXT_ERR_NOACK;
		}
		cachemgr_fkcrt_set(ctx->origcrt, newcrt);
		if (OPTS_DEBUG(ctx->opts)) {
			log_dbg_printf("===> Updated forged server "
			               "certificate:\n");
			pxy_debug_crt(newcrt);
		}
		if (WANT_CONNECT_LOG(ctx)) {
			if (ctx->ssl_names) {
				free(ctx->ssl_names);
			}
			ctx->ssl_names = ssl_x509_names_to_str(newcrt);
			if (!ctx->ssl_names) {
				ctx->enomem = 1;
			}
		}
		newsslctx = pxy_srcsslctx_create(ctx, newcrt, ctx->opts->chain,
		                                 ctx->opts->key);
		if (!newsslctx) {
			X509_free(newcrt);
			ctx->enomem = 1;
			return SSL_TLSEXT_ERR_NOACK;
		}
		SSL_set_SSL_CTX(ssl, newsslctx); /* decr's old incr new refc */
		SSL_CTX_free(newsslctx);
		X509_free(newcrt);
	} else if (OPTS_DEBUG(ctx->opts)) {
		log_dbg_printf("Certificate cache: KEEP (SNI match or "
		               "target mode)\n");
	}

	return SSL_TLSEXT_ERR_OK;
}
#endif /* !OPENSSL_NO_TLSEXT */

/*
 * Create new SSL context for outgoing connections to the original destination.
 * If hostname sni is provided, use it for Server Name Indication.
 */
static SSL *
pxy_dstssl_create(pxy_conn_ctx_t *ctx)
{
	SSL_CTX *sslctx;
	SSL *ssl;
	SSL_SESSION *sess;

	sslctx = SSL_CTX_new(ctx->opts->sslmethod());
	if (!sslctx) {
		ctx->enomem = 1;
		return NULL;
	}

	SSL_CTX_set_options(sslctx, SSL_OP_ALL);
#ifdef SSL_OP_TLS_ROLLBACK_BUG
	SSL_CTX_set_options(sslctx, SSL_OP_TLS_ROLLBACK_BUG);
#endif /* SSL_OP_TLS_ROLLBACK_BUG */
#ifdef SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
	SSL_CTX_set_options(sslctx, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
#endif /* SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION */
#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
	SSL_CTX_set_options(sslctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
#endif /* SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS */
#ifdef SSL_OP_NO_TICKET
	SSL_CTX_set_options(sslctx, SSL_OP_NO_TICKET);
#endif /* SSL_OP_NO_TICKET */
#ifdef SSL_OP_NO_COMPRESSION
	if (!ctx->opts->sslcomp) {
		SSL_CTX_set_options(sslctx, SSL_OP_NO_COMPRESSION);
	}
#endif /* SSL_OP_NO_COMPRESSION */

#ifdef SSL_OP_NO_SSLv2
#ifdef WITH_SSLV2
	if (ctx->opts->no_ssl2) {
#endif /* WITH_SSLV2 */
		SSL_CTX_set_options(sslctx, SSL_OP_NO_SSLv2);
#ifdef WITH_SSLV2
	}
#endif /* WITH_SSLV2 */
#endif /* !SSL_OP_NO_SSLv2 */
#ifdef SSL_OP_NO_SSLv3
	if (ctx->opts->no_ssl3) {
		SSL_CTX_set_options(sslctx, SSL_OP_NO_SSLv3);
	}
#endif /* SSL_OP_NO_SSLv3 */
#ifdef SSL_OP_NO_TLSv1
	if (ctx->opts->no_tls10) {
		SSL_CTX_set_options(sslctx, SSL_OP_NO_TLSv1);
	}
#endif /* SSL_OP_NO_TLSv1 */
#ifdef SSL_OP_NO_TLSv1_1
	if (ctx->opts->no_tls11) {
		SSL_CTX_set_options(sslctx, SSL_OP_NO_TLSv1_1);
	}
#endif /* SSL_OP_NO_TLSv1_1 */
#ifdef SSL_OP_NO_TLSv1_2
	if (ctx->opts->no_tls12) {
		SSL_CTX_set_options(sslctx, SSL_OP_NO_TLSv1_2);
	}
#endif /* SSL_OP_NO_TLSv1_2 */

	SSL_CTX_set_cipher_list(sslctx, ctx->opts->ciphers);
	SSL_CTX_set_verify(sslctx, SSL_VERIFY_NONE, NULL);

	ssl = SSL_new(sslctx);
	SSL_CTX_free(sslctx); /* SSL_new() increments refcount */
	if (!ssl) {
		ctx->enomem = 1;
		return NULL;
	}
#ifndef OPENSSL_NO_TLSEXT
	if (ctx->sni) {
		SSL_set_tlsext_host_name(ssl, ctx->sni);
	}
#endif /* !OPENSSL_NO_TLSEXT */

#ifdef SSL_MODE_RELEASE_BUFFERS
	/* lower memory footprint for idle connections */
	SSL_set_mode(ssl, SSL_get_mode(ssl) | SSL_MODE_RELEASE_BUFFERS);
#endif /* SSL_MODE_RELEASE_BUFFERS */

	/* session resuming based on remote endpoint address and port */
	sess = cachemgr_dsess_get((struct sockaddr *)&ctx->addr,
	                          ctx->addrlen, ctx->sni); /* new sess inst */
	if (sess) {
		if (OPTS_DEBUG(ctx->opts)) {
			log_dbg_printf("Attempt reuse dst SSL session\n");
		}
		SSL_set_session(ssl, sess); /* increments sess refcount */
		SSL_SESSION_free(sess);
	}

	return ssl;
}

/*
 * Free bufferenvent and close underlying socket properly.
 * For OpenSSL bufferevents, this will shutdown the SSL connection.
 */
static void
bufferevent_free_and_close_fd(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	evutil_socket_t fd = bufferevent_getfd(bev);
	SSL *ssl = NULL;

	if (ctx->req_ssl && !ctx->passthrough) {
		ssl = bufferevent_openssl_get_ssl(bev); /* does not inc refc */
	}

#ifdef DEBUG_PROXY
	if (OPTS_DEBUG(ctx->opts)) {
		log_dbg_printf("            %p free_and_close_fd\n",
		               (void*)bev);
	}
#endif /* DEBUG_PROXY */

	bufferevent_free(bev); /* does not free SSL unless the option
	                          BEV_OPT_CLOSE_ON_FREE was set */
	if (ssl) {
		pxy_ssl_shutdown(ctx->opts, ctx->evbase, ssl, fd);
	} else {
		evutil_closesocket(fd);
	}
}

/*
 * Set up a bufferevent structure for either a dst or src connection,
 * optionally with or without SSL.  Sets all callbacks, enables read
 * and write events, but does not call bufferevent_socket_connect().
 *
 * For dst connections, pass -1 as fd.  Pass a pointer to an initialized
 * SSL struct as ssl if the connection should use SSL.
 *
 * Returns pointer to initialized bufferevent structure, as returned
 * by bufferevent_socket_new() or bufferevent_openssl_socket_new().
 */
static struct bufferevent *
pxy_bufferevent_setup(pxy_conn_ctx_t *ctx, evutil_socket_t fd, SSL *ssl)
{
	struct bufferevent *bev;

	if (ssl) {
		bev = bufferevent_openssl_socket_new(ctx->evbase, fd, ssl,
				((fd == -1) ? BUFFEREVENT_SSL_CONNECTING
				           : BUFFEREVENT_SSL_ACCEPTING),
				BEV_OPT_DEFER_CALLBACKS);
#if 0
		if(fd != -1){
			printf("client bufferevent setup\n");
		}
#endif
	} else {
		bev = bufferevent_socket_new(ctx->evbase, fd,
				BEV_OPT_DEFER_CALLBACKS);
	}
	if (!bev) {
		log_err_printf("Error creating bufferevent socket\n");
		return NULL;
	}
#if LIBEVENT_VERSION_NUMBER >= 0x02010000
	if (ssl) {
		/* Prevent unclean (dirty) shutdowns to cause error
		 * events on the SSL socket bufferevent. */
		bufferevent_openssl_set_allow_dirty_shutdown(bev, 1);
	}
#endif /* LIBEVENT_VERSION_NUMBER >= 0x02010000 */
	bufferevent_setcb(bev, pxy_bev_readcb, pxy_bev_writecb,
	                  pxy_bev_eventcb, ctx);
	bufferevent_enable(bev, EV_READ|EV_WRITE);
#ifdef DEBUG_PROXY
	if (OPTS_DEBUG(ctx->opts)) {
		log_dbg_printf("            %p pxy_bufferevent_setup\n",
		               (void*)bev);
	}
#endif /* DEBUG_PROXY */
	return bev;
}

/*
 * Filter a single line of HTTP request headers.
 * Also fills in some context fields for logging.
 *
 * Returns NULL if the current line should be deleted from the request.
 * Returns a newly allocated string if the current line should be replaced.
 * Returns `line' if the line should be kept.
 */
static char *
pxy_http_reqhdr_filter_line(const char *line, pxy_conn_ctx_t *ctx)
{
	/* parse information for connect log */
	if (!ctx->http_method) {
		/* first line */
		char *space1, *space2;

		space1 = strchr(line, ' ');
		space2 = space1 ? strchr(space1 + 1, ' ') : NULL;
		if (!space1) {
			/* not HTTP */
			ctx->seen_req_header = 1;
		} else {
			ctx->http_method = malloc(space1 - line + 1);
			if (ctx->http_method) {
				memcpy(ctx->http_method, line, space1 - line);
				ctx->http_method[space1 - line] = '\0';
			} else {
				ctx->enomem = 1;
				return NULL;
			}
			space1++;
			if (!space2) {
				/* HTTP/0.9 */
				ctx->seen_req_header = 1;
				space2 = space1 + strlen(space1);
			}
			ctx->http_uri = malloc(space2 - space1 + 1);
			if (ctx->http_uri) {
				memcpy(ctx->http_uri, space1, space2 - space1);
				ctx->http_uri[space2 - space1] = '\0';
			} else {
				ctx->enomem = 1;
				return NULL;
			}
		}
	} else {
		/* not first line */
		char *newhdr;

		if (!ctx->http_host && !strncasecmp(line, "Host:", 5)) {
			ctx->http_host = strdup(util_skipws(line + 5));
			if (!ctx->http_host) {
				ctx->enomem = 1;
				return NULL;
			}
		} else if (!strncasecmp(line, "Content-Type:", 13)) {
			ctx->http_content_type = strdup(util_skipws(line + 13));
			if (!ctx->http_content_type) {
				ctx->enomem = 1;
				return NULL;
			}
		} else if (!strncasecmp(line, "Connection:", 11)) {
			ctx->sent_http_conn_close = 1;
			if (!(newhdr = strdup("Connection: close"))) {
				ctx->enomem = 1;
				return NULL;
			}
			return newhdr;
		} else if (!strncasecmp(line, "Accept-Encoding:", 16) ||
		           !strncasecmp(line, "Keep-Alive:", 11)) {
			return NULL;
		} else if (line[0] == '\0') {
			ctx->seen_req_header = 1;
			if (!ctx->sent_http_conn_close) {
				newhdr = strdup("Connection: close\r\n");
				if (!newhdr) {
					ctx->enomem = 1;
					return NULL;
				}
				return newhdr;
			}
		}
	}

	return (char*)line;
}

/*
 * Filter a single line of HTTP response headers.
 *
 * Returns NULL if the current line should be deleted from the response.
 * Returns a newly allocated string if the current line should be replaced.
 * Returns `line' if the line should be kept.
 */
static char *
pxy_http_resphdr_filter_line(const char *line, pxy_conn_ctx_t *ctx)
{
	/* parse information for connect log */
	if (!ctx->http_status_code) {
		/* first line */
		char *space1, *space2;

		space1 = strchr(line, ' ');
		space2 = space1 ? strchr(space1 + 1, ' ') : NULL;
		if (!space1 || !!strncmp(line, "HTTP", 4)) {
			/* not HTTP or HTTP/0.9 */
			ctx->seen_resp_header = 1;
		} else {
			size_t len_code, len_text;

			if (space2) {
				len_code = space2 - space1 - 1;
				len_text = strlen(space2 + 1);
			} else {
				len_code = strlen(space1 + 1);
				len_text = 0;
			}
			ctx->http_status_code = malloc(len_code + 1);
			ctx->http_status_text = malloc(len_text + 1);
			if (!ctx->http_status_code || !ctx->http_status_text) {
				ctx->enomem = 1;
				return NULL;
			}
			memcpy(ctx->http_status_code, space1 + 1, len_code);
			ctx->http_status_code[len_code] = '\0';
			if (space2) {
				memcpy(ctx->http_status_text,
				       space2 + 1, len_text);
			}
			ctx->http_status_text[len_text] = '\0';
		}
	} else {
		/* not first line */
		if (!ctx->http_content_length &&
		    !strncasecmp(line, "Content-Length:", 15)) {
			ctx->http_content_length =
				strdup(util_skipws(line + 15));
			if (!ctx->http_content_length) {
				ctx->enomem = 1;
				return NULL;
			}
		} else if (
		    /* HPKP: Public Key Pinning Extension for HTTP
		     * (draft-ietf-websec-key-pinning)
		     * remove to prevent public key pinning */
		    !strncasecmp(line, "Public-Key-Pins:", 16) ||
		    !strncasecmp(line, "Public-Key-Pins-Report-Only:", 28) ||
		    /* HSTS: HTTP Strict Transport Security (RFC 6797)
		     * remove to allow users to accept bad certs */
		    !strncasecmp(line, "Strict-Transport-Security:", 26) ||
		    /* Alternate Protocol
		     * remove to prevent switching to QUIC, SPDY et al */
		    !strncasecmp(line, "Alternate-Protocol:", 19)) {
			return NULL;
		} else if (line[0] == '\0') {
			ctx->seen_resp_header = 1;
		}
	}

	return (char*)line;
}

/*
 * Return 1 if uri is an OCSP GET URI, 0 if not.
 */
static int
pxy_ocsp_is_valid_uri(const char *uri, pxy_conn_ctx_t *ctx)
{
	char *buf_url;
	size_t sz_url;
	char *buf_b64;
	size_t sz_b64;
	unsigned char *buf_asn1;
	size_t sz_asn1;
	int ret;

	buf_url = strrchr(uri, '/');
	if (!buf_url)
		return 0;
	buf_url++;

	/*
	 * Do some quick checks to avoid unnecessary buffer allocations and
	 * decoding URL, Base64 and ASN.1:
	 * -   OCSP requests begin with a SEQUENCE (0x30), so the first Base64
	 *     byte is 'M' or, unlikely but legal, the URL encoding thereof.
	 * -   There should be no query string in OCSP GET requests.
	 * -   Encoded OCSP request ASN.1 blobs are longer than 32 bytes.
	 */
	if (buf_url[0] != 'M' && buf_url[0] != '%')
		return 0;
	if (strchr(uri, '?'))
		return 0;
	sz_url = strlen(buf_url);
	if (sz_url < 32)
		return 0;
	buf_b64 = url_dec(buf_url, sz_url, &sz_b64);
	if (!buf_b64) {
		ctx->enomem = 1;
		return 0;
	}
	buf_asn1 = base64_dec(buf_b64, sz_b64, &sz_asn1);
	if (!buf_asn1) {
		ctx->enomem = 1;
		free(buf_b64);
		return 0;
	}
	ret = ssl_is_ocspreq(buf_asn1, sz_asn1);
	free(buf_asn1);
	free(buf_b64);
	return ret;
}

/*
 * Called after a request header was completely read.
 * If the request is an OCSP request, deny the request by sending an
 * OCSP response of type tryLater and close the connection to the server.
 *
 * Reference:
 * RFC 2560: X.509 Internet PKI Online Certificate Status Protocol (OCSP)
 */
static void
pxy_ocsp_deny(pxy_conn_ctx_t *ctx)
{
	struct evbuffer *inbuf, *outbuf;
	static const char ocspresp[] =
		"HTTP/1.0 200 OK\r\n"
		"Content-Type: application/ocsp-response\r\n"
		"Content-Length: 5\r\n"
		"Connection: close\r\n"
		"\r\n"
		"\x30\x03"      /* OCSPResponse: SEQUENCE */
		"\x0a\x01"      /* OCSPResponseStatus: ENUMERATED */
		"\x03";         /* tryLater (3) */

	if (!ctx->http_method)
		return;
	if (!strncasecmp(ctx->http_method, "GET", 3) &&
	    pxy_ocsp_is_valid_uri(ctx->http_uri, ctx))
		goto deny;
	if (!strncasecmp(ctx->http_method, "POST", 4) &&
	    ctx->http_content_type &&
	    !strncasecmp(ctx->http_content_type,
	                 "application/ocsp-request", 24))
		goto deny;
	return;

deny:
	inbuf = bufferevent_get_input(ctx->src.bev);
	outbuf = bufferevent_get_output(ctx->src.bev);

	if (evbuffer_get_length(inbuf) > 0) {
		if (WANT_CONTENT_LOG(ctx)) {
			logbuf_t *lb;
			lb = logbuf_new_alloc(evbuffer_get_length(inbuf),
			                      NULL, NULL);
			if (lb &&
			    (evbuffer_copyout(inbuf, lb->buf, lb->sz) != -1)) {
				if (log_content_submit(ctx->logctx, lb,
				                       1/*req*/) == -1) {
					logbuf_free(lb);
					log_err_printf("Warning: Content log "
					               "submission failed\n");
				}
			}
		}
		evbuffer_drain(inbuf, evbuffer_get_length(inbuf));
	}
	bufferevent_free_and_close_fd(ctx->dst.bev, ctx);
	ctx->dst.closed = 1;
	evbuffer_add_printf(outbuf, ocspresp);
	ctx->ocsp_denied = 1;
	if (WANT_CONTENT_LOG(ctx)) {
		logbuf_t *lb;
		lb = logbuf_new_copy(ocspresp, sizeof(ocspresp) - 1,
		                     NULL, NULL);
		if (lb) {
			if (log_content_submit(ctx->logctx, lb,
			                       0/*resp*/) == -1) {
				logbuf_free(lb);
				log_err_printf("Warning: Content log "
				               "submission failed\n");
			}
		}
	}
}

void
pxy_conn_terminate_free(pxy_conn_ctx_t *ctx)
{
	log_err_printf("Terminating connection%s!\n",
	               ctx->enomem ? " (out of memory)" : "");
	if (ctx->dst.bev && !ctx->dst.closed) {
		bufferevent_free_and_close_fd(ctx->dst.bev, ctx);
	}
	if (ctx->src.bev && !ctx->src.closed) {
		bufferevent_free_and_close_fd(ctx->src.bev, ctx);
	}
	pxy_conn_ctx_free(ctx);
}

static int
pxy_replace_ETag(char *etag, char *response,size_t type){

	char * pos;
	const char *ETag_Sample;
	if(type == 0)
		ETag_Sample = ETAG_SAMPLE0;
	else
		ETag_Sample = ETAG_SAMPLE1;

	while((pos = strstr(response,ETag_Sample))){
		memcpy(pos + GOOGLE_DR_ETAG_PREFIX_SIZE + 1,etag,strlen(ETag_Sample));
	}
	return 1;
}

static int
pxy_gen_ETag(pxy_conn_ctx_t* ctx,char* response,size_t type){
	size_t esize;
	if(type == 0){
		esize = GOOGLE_DR_ETAG_SIZE0;
	}else{
		esize = GOOGLE_DR_ETAG_SIZE1;
	}
	char* etag = malloc(sizeof(char) * esize + 1);
	memset(etag,'\0',esize + 1);
	srand(time(NULL));
	size_t i;
	int j;
	for(i = 0;i < esize;++i){
		j = rand() % 3;
		if(j == 0){
			ctx->Uploader_ID[i] = '0' + rand() % 10;
		}else if(j == 1){
			ctx->Uploader_ID[i] = 'a' + rand() % 26;
		}else{
			ctx->Uploader_ID[i] = 'A' + rand() % 26;
		}
	}

	pxy_replace_ETag(etag,response,type);

	return 1;
}


static int
pxy_gen_uploader_id(pxy_conn_ctx_t* ctx){
	if(ctx == NULL){
		return -1;
	}

	if(ctx->Uploader_ID){
		free(ctx->Uploader_ID);
	}
	ctx->Uploader_ID = malloc(sizeof(char) * GOOGLE_DR_UPLOADER_ID_SIZE);

	srand(time(NULL));
	int i,j;
	for(i = 0;i < GOOGLE_DR_UPLOADER_ID_SIZE;++i){
		j = rand() % 3;
		if(j == 0){
			ctx->Uploader_ID[i] = '0' + rand() % 10;
		}else if(j == 1){
			ctx->Uploader_ID[i] = 'a' + rand() % 26;
		}else{
			ctx->Uploader_ID[i] = 'A' + rand() % 26;
		}
	}

	return 1;
}

static int
pxy_replace_uploader_id(pxy_conn_ctx_t* ctx,const char *response){
//	char* result;
	char* pos;
	const char *UpIDSample = "AEnB2Up2ao2-uhfOFLDeVXUlyehoncRb9TRRmbyDtF5nCEEJsU56Iv1-Y3tu8KMpYBSgc8bAg-YliLWB_4444vvMYYbbow7O7w";

	/*
	result = malloc(strlen(response) + 1);
	if(result == NULL){
		fprintf(stderr, "out of memory, CAN NOT MALLOC Google Dr response\n");
		exit(EXIT_FAILURE);
	}

	memset(result, '\0', strlen(response));
	memcpy(result, response,strlen(response));
	*/

	while((pos = strstr(response,UpIDSample))){
//		printf("11-------------------111\n");
		memcpy(pos,ctx->Uploader_ID,strlen(UpIDSample));
	}
	return 1;
}

static int
pxy_replace_id(char *id, char* response){
	char *id_sample = "0BzCkQYBmdM-2SjVfWlFYZ1RtdUU";
	char *id_pos;

	while((id_pos = strstr(response,id_sample))){
		memcpy(id_pos + 12 ,id,GOOGLE_DR_ID_SIZE);
	}
	return 1;
}

static int
pxy_gen_id(pxy_conn_ctx_t * ctx,char* response){
	size_t i,j;
	char *randID;
//	char *randUpID;
//	char *rsp;
//	char *ID_pos;
//	const char *UpIDSample = "AEnB2Up2ao2-uhfOFLDeVXUlyehoncRb9TRRmbyDtF5nCEEJsU56Iv1-Y3tu8KMpYBSgc8bAg-YliLWB_4444vvMYYbbow7O7w";

#if 0
	rsp = malloc(sizeof(char) * strlen(gdriveRsp2) + 1);
	if(rsp == NULL){
		fprintf(stderr, "out of memory, CAN NOT MALLOC Google Dr response\n");
		exit(EXIT_FAILURE);
	}
	memcpy(rsp,gdriveRsp2,strlen(gdriveRsp2));
	rsp[strlen(gdriveRsp2)] ='\0';
//	printf("%s\n",rsp);
#endif
	randID = malloc(sizeof(char) * GOOGLE_DR_ID_SIZE + 1);
//	randUpID = malloc(sizeof(char) * GOOGLE_DR_UPLOADER_ID_SIZE + 1);

	if(randID == NULL){
		fprintf(stderr,"out of memory, CAN NOT MALLOC Google Dr random ID\n");
		exit(EXIT_FAILURE);
	}

	srand(time(NULL));
#if 0
	for(i = 0;i < GOOGLE_DR_UPLOADER_ID_SIZE;++i){
		j = rand() % 3;
		if(j == 0){
			randUpID[i] = '0' + rand() % 10;
		}else if(j == 1){
			randUpID[i] = 'a' + rand() % 26;
		}else{
			randUpID[i] = 'A' + rand() % 26;
		}
	}

	while((ID_pos = strstr(rsp,UpIDSample))){
		memcpy(ID_pos, randID, GOOGLE_DR_ID_SIZE);
	}
#endif

	for(i = 0;i < GOOGLE_DR_ID_SIZE;++i){
		j = rand() % 3;
		if(j == 0){
			randID[i] = '0' + rand() % 10;
		}else if(j == 1){
			randID[i] = 'a' + rand() % 26;
		}else{
			randID[i] = 'A' + rand() % 26;
		}
	}
	randID[GOOGLE_DR_ID_SIZE] = '\0';

#if 0
	while((ID_pos = strstr(rsp,UpIDSample))){
		memcpy(ID_pos,ctx->Uploader_ID,strlen(UpIDSample));
	}

#endif
	pxy_replace_id(randID,response);
	free(randID);

	return 1;
}

static int
pxy_get_bytes(pxy_conn_ctx_t* ctx,char *request,unsigned long long *total,
				unsigned long long *start,unsigned long long *end){
	if(total != NULL && start == NULL && end == NULL){
		char *p = strstr(request,"x-upload-content-length: ");
		assert(p);
		if(p == NULL){
			return 0;
		}
		p = p + strlen("x-upload-content-length: ");
		int i = 0;
		while(p[i] >= '0' && p[i] <= '9'){
			i++;
		}
		char* total_tmp = malloc(i+1);
		memcpy(total_tmp,p,i);
		total_tmp[i] = '\0';
		*total = atoll(total_tmp);
		free(total_tmp);
	}

	if(total != NULL && start != NULL && end != NULL){
		char *p = strstr(request,"content-range: bytes ");
		assert(p);
		p = p + strlen("content-range: bytes ");
//		int rv = 1;
		if(p[0] == '*'){
			p++;
			assert(p[0] == '/');
			p++;

			int i=0;
			while(p[i] >= '0' && p[i] <= '9'){
				i++;
			}
			char* total_tmp = malloc(i+1);
			memcpy(total_tmp,p,i);
			total_tmp[i] = '\0';
			*total = atoll(total_tmp);
			free(total_tmp);
			return 0;
		}
		int i = 0;
		while(p[i] != '-'){
		   ++i;
		}
		if(ctx->str_start ){
			free(ctx->str_start);
		}
		ctx->str_start = malloc(i+1);
		memcpy(ctx->str_start,p,i);
		ctx->str_start[i] = '\0';
		*start = atoll(ctx->str_start);

		p = p + i + 1;
		i = 0;
		while(p[i] != '/'){
			++i;
		}
		if(ctx->str_end)
			free(ctx->str_end);

		ctx->str_end = malloc(i+1);
		memcpy(ctx->str_end,p,i);
		ctx->str_end[i] = '\0';
		*end = atoll(ctx->str_end);
	}

    return 1;
}

static char*
pxy_gen_response1(pxy_conn_ctx_t* ctx){
	char* response;

	response = malloc(sizeof(char) * strlen(gdriveRsp1) + 10);
	if(!response){
		exit(EXIT_FAILURE);
	}

	memset(response,'\0',strlen(gdriveRsp1) + 10);
	memcpy(response,gdriveRsp1,strlen(gdriveRsp1));
	pxy_replace_uploader_id(ctx,response);
	return response;
}

static char *
pxy_gen_response2(pxy_conn_ctx_t* ctx){
	char* response;
	response = malloc(sizeof(char) * strlen(gdriveRsp2) + 10);
	if(!response){
		exit(EXIT_FAILURE);
	}

	memset(response,'\0',strlen(gdriveRsp2) + 10);
	memcpy(response,gdriveRsp2,strlen(gdriveRsp2));
	pxy_replace_uploader_id(ctx,response);
	pxy_gen_id(ctx,response);
#if 0
	pxy_gen_ETag(ctx,response,1);
	pxy_gen_ETag(ctx,response,2);
#endif
	return response;
}

static char *
pxy_gen_response3(pxy_conn_ctx_t* ctx){
    char* result;
	char* p;

	size_t range_size = strlen("Range: bytes=") + strlen("0")
						+ 1 + strlen(ctx->str_end) + 2;
	size_t md5_size = strlen("X-Range-MD5: ") + 32;

	size_t total_size = strlen(gdriveRsp3_Part1) + range_size + md5_size
					+ strlen(gdriveRsp3_Part2) + 1;
	result = malloc(total_size) ;
	if(result == NULL){
		fprintf(stderr,"out of memory");
		exit(EXIT_FAILURE);
	}
	memset(result,'\0',total_size);

	memcpy(result,gdriveRsp3_Part1,strlen(gdriveRsp3_Part1));
	p = result + strlen(gdriveRsp3_Part1);

	memcpy(p, "Range: bytes=",strlen("Range: bytes="));
	p += strlen("Range: bytes=");

	memcpy(p,"0",strlen("0"));
	p += strlen("0");

	*p++ = '-';

	memcpy(p,ctx->str_end,strlen(ctx->str_end));
	p += strlen(ctx->str_end);

	*p++ = '\r';
	*p++ = '\n';

	memcpy(p,"X-Range-MD5: ",strlen("X-Range-MD5: "));
	p += strlen("X-Range-MD5: ");

	unsigned char md5[16];
	MD5(ctx->fragment,ctx->total_recv,md5);
	int i;
	for(i = 0; i < 16;++i){
//		printf("%02x",md5[i]);
		snprintf(p,3,"%02x",md5[i]);
		p = p + 2;
	}
#if 0
	printf("\n");
	printf("%s\n",result);
#endif

	*p++ = '\r';
	*p++ = '\n';

	memcpy(p,gdriveRsp3_Part2,strlen(gdriveRsp3_Part2));
	pxy_replace_uploader_id(ctx,result);
#if 0
	while((ID_pos = strstr(result,UpIDSample))){
		memcpy(ID_pos,ctx->Uploader_ID,strlen(UpIDSample));
	}
#endif
	return result;
}

/*
 * Callback for read events on the up- and downstram connection bufferevents.
 * Called when there is data ready in the input evbuffer.
 */
static void
pxy_bev_readcb(struct bufferevent *bev, void *arg)
{
	/*
	double start_time = time_milli();
	fprintf(stderr,"bev_readcb start time %0.5f\n",start_time);
	*/
	pxy_conn_ctx_t *ctx = arg;
	pxy_conn_desc_t *other = (bev==ctx->src.bev) ? &ctx->dst : &ctx->src;
#if 0
	printf("readcb start: %f\n",time_milli());
#endif
#ifdef DEBUG_PROXY
	if (OPTS_DEBUG(ctx->opts)) {
		log_dbg_printf("%p %p %s readcb\n", arg, (void*)bev,
		               (bev == ctx->src.bev) ? "src" : "dst");
	}
#endif /* DEBUG_PROXY */
#if 0
	printf("in readcb\n");
#endif

	if (!ctx->connected) {
		log_err_printf("readcb called when other end not connected - "
		               "aborting.\n");
		/* XXX should signal main loop instead of calling exit() */
		log_fini();
		exit(EXIT_FAILURE);
	}

	struct evbuffer *inbuf = bufferevent_get_input(bev);
	if (other->closed) {
		evbuffer_drain(inbuf, evbuffer_get_length(inbuf));
		return;
	}

	struct evbuffer *outbuf = bufferevent_get_output(other->bev);

	/* request header munging */
	if (ctx->spec->http && !ctx->seen_req_header && (bev == ctx->src.bev)
	    && !ctx->passthrough) {
		logbuf_t *lb = NULL, *tail = NULL;
		char *line;
		while ((line = evbuffer_readln(inbuf, NULL,
		                               EVBUFFER_EOL_CRLF))) {
			char *replace;
			if (WANT_CONTENT_LOG(ctx)) {
				logbuf_t *tmp;
				tmp = logbuf_new_printf(NULL, NULL,
				                        "%s\r\n", line);
				if (tail) {
					if (tmp) {
						tail->next = tmp;
						tail = tail->next;
					}
				} else {
					lb = tail = tmp;
				}
			}
			replace = pxy_http_reqhdr_filter_line(line, ctx);
			if (replace == line) {
//				printf("readcb %s\n", line);
				evbuffer_add_printf(outbuf, "%s\r\n", line);
			} else if (replace) {
//				printf("readcb %s\n", replace);
				evbuffer_add_printf(outbuf, "%s\r\n", replace);
				free(replace);
			}
			free(line);
			if (ctx->seen_req_header) {
				/* request header complete */
				if (ctx->opts->deny_ocsp) {
					pxy_ocsp_deny(ctx);
				}
				break;
			}
		}
		if (lb && WANT_CONTENT_LOG(ctx)) {
			if (log_content_submit(ctx->logctx, lb,
			                       1/*req*/) == -1) {
				logbuf_free(lb);
				log_err_printf("Warning: Content log "
				               "submission failed\n");
			}
		}
		if (!ctx->seen_req_header)
			return;
	} else
	/* response header munging */
	if (ctx->spec->http && !ctx->seen_resp_header && (bev == ctx->dst.bev)
	    && !ctx->passthrough) {
		logbuf_t *lb = NULL, *tail = NULL;
		char *line;
		while ((line = evbuffer_readln(inbuf, NULL,
		                               EVBUFFER_EOL_CRLF))) {
			char *replace;
			if (WANT_CONTENT_LOG(ctx)) {
				logbuf_t *tmp;
				tmp = logbuf_new_printf(NULL, NULL,
				                        "%s\r\n", line);
				if (tail) {
					if (tmp) {
						tail->next = tmp;
						tail = tail->next;
					}
				} else {
					lb = tail = tmp;
				}
			}
			replace = pxy_http_resphdr_filter_line(line, ctx);
			if (replace == line) {
//				printf("readcb %s\n", line);
				evbuffer_add_printf(outbuf, "%s\r\n", line);
			} else if (replace) {
//				printf("readcb %s\n", replace);
				evbuffer_add_printf(outbuf, "%s\r\n", replace);
				free(replace);
			}
			free(line);
			if (ctx->seen_resp_header) {
				/* response header complete: log connection */
				if (WANT_CONNECT_LOG(ctx)) {
					//pxy_log_connect_http(ctx);
				}
				break;
			}
		}
		if (lb && WANT_CONTENT_LOG(ctx)) {
			if (log_content_submit(ctx->logctx, lb,
			                       0/*resp*/) == -1) {
				logbuf_free(lb);
				log_err_printf("Warning: Content log "
				               "submission failed\n");
			}
		}
		if (!ctx->seen_resp_header)
			return;
	}

	/* out of memory condition? */
	if (ctx->enomem) {
		pxy_conn_terminate_free(ctx);
		return;
	}

	/* no data left after parsing headers? */
	if (evbuffer_get_length(inbuf) == 0)
		return;

	if (WANT_CONTENT_LOG(ctx)) {
		logbuf_t *lb;
		lb = logbuf_new_alloc(evbuffer_get_length(inbuf), NULL, NULL);
		if (lb && (evbuffer_copyout(inbuf, lb->buf, lb->sz) != -1)) {
			if (log_content_submit(ctx->logctx, lb,
			                       (bev == ctx->src.bev)) == -1) {
				logbuf_free(lb);
				log_err_printf("Warning: Content log "
				               "submission failed\n");
			}
		}
	}
//	printf("------------------------sni %s\n", ctx->sni);
	
	evbuffer_add_buffer(outbuf,inbuf);
	if (evbuffer_get_length(outbuf) >= OUTBUF_LIMIT) {
		/* temporarily disable data source;
		 * set an appropriate watermark. */
		bufferevent_setwatermark(other->bev, EV_WRITE,
				OUTBUF_LIMIT/2, OUTBUF_LIMIT);
		bufferevent_disable(bev, EV_READ);
	}
	/*
	double end_time = time_milli();
	fprintf(stderr,"bev_readcb end time %0.5f\n",end_time);
	fprintf(stderr," ------------- elasped time %0.5f\n",end_time - start_time);
	*/
}

/*
 * Callback for write events on the up- and downstream connection bufferevents.
 * Called when either all data from the output evbuffer has been written,
 * or if the outbuf is only half full again after having been full.
 */
static void
pxy_bev_writecb(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	pxy_conn_desc_t *other = (bev==ctx->src.bev) ? &ctx->dst : &ctx->src;

#ifdef DEBUG_PROXY
	if (OPTS_DEBUG(ctx->opts)) {
		log_dbg_printf("%p %p %s writecb\n", arg, (void*)bev,
		               (bev == ctx->src.bev) ? "src" : "dst");
	}
#endif /* DEBUG_PROXY */

	struct evbuffer *outbuf = bufferevent_get_output(bev);
	if (evbuffer_get_length(outbuf) > 0) {
		/* data source temporarily disabled;
		 * re-enable and reset watermark to 0. */
		bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
		if (!other->closed) {
			bufferevent_enable(other->bev, EV_READ);
		}
	} else if (other->closed) {
		/* finished writing and other end is closed;
		 * close this end too and clean up memory */
		bufferevent_free_and_close_fd(bev, ctx);
		pxy_conn_ctx_free(ctx);
	}
}

/*
 * Callback for meta events on the up- and downstream connection bufferevents.
 * Called when EOF has been reached, a connection has been made, and on errors.
 */
static void
pxy_bev_eventcb(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	pxy_conn_desc_t *this = (bev==ctx->src.bev) ? &ctx->src : &ctx->dst;
	pxy_conn_desc_t *other = (bev==ctx->src.bev) ? &ctx->dst : &ctx->src;

#ifdef DEBUG_PROXY
	if (OPTS_DEBUG(ctx->opts)) {
		log_dbg_printf("%p %p eventcb %s %s%s%s%s\n", arg, (void*)bev,
		               (bev == ctx->src.bev) ? "src" : "dst",
		               events & BEV_EVENT_CONNECTED ? "connected" : "",
		               events & BEV_EVENT_ERROR ? "error" : "",
		               events & BEV_EVENT_TIMEOUT ? "timeout" : "",
		               events & BEV_EVENT_EOF ? "eof" : "");
	}
#endif /* DEBUG_PROXY */

	if (events & BEV_EVENT_CONNECTED) {
		if (bev != ctx->dst.bev) {
#if 0
			printf("src event call back\n");
			printf("src connect event_cb %f\n",time_milli());
#endif
#ifdef DEBUG_PROXY
			if (OPTS_DEBUG(ctx->opts)) {
				log_dbg_printf("src buffer event connected: "
				               "ignoring event\n");
			}
#endif /* DEBUG_PROXY */
//			printf("before goto connected\n");
			goto connected;
		}

		/* dst has connected */
		ctx->connected = 1;
#if 0
		printf("client side socket in an eventbuffer\n");
#endif
		/* wrap client-side socket in an eventbuffer */
//		printf("dst call back %f \n",time_milli());
		if (ctx->req_ssl && !ctx->passthrough) {
//			printf("before create srcssl %f\n",time_milli());
			ctx->src.ssl = pxy_srcssl_create(ctx, this->ssl);
//			printf("after create srcssl %f\n",time_milli());
			if (!ctx->src.ssl) {
#if 0
				printf("can not create src.ssl\n");
#endif
				bufferevent_free_and_close_fd(bev, ctx);
				ctx->dst.bev = NULL;
				ctx->dst.ssl = NULL;
				if (ctx->opts->passthrough && !ctx->enomem) {
					ctx->passthrough = 1;
					ctx->connected = 0;
					log_dbg_printf("No cert found; "
					               "falling back "
					               "to passthrough\n");
					pxy_fd_readcb(ctx->fd, 0, ctx);
					return;
				}
				evutil_closesocket(ctx->fd);
				pxy_conn_ctx_free(ctx);
				return;
			}
		}
//		printf("before set src bev %f\n",time_milli());
		ctx->src.bev = pxy_bufferevent_setup(ctx, ctx->fd,
		                                     ctx->src.ssl);
//		printf("after set src bev %f\n",time_milli());
		if (!ctx->src.bev) {
			if (ctx->src.ssl) {
				SSL_free(ctx->src.ssl);
				ctx->src.ssl = NULL;
			}
			bufferevent_free_and_close_fd(bev, ctx);
			evutil_closesocket(ctx->fd);
			pxy_conn_ctx_free(ctx);
			return;
		}

		/* prepare logging, part 2 */
		if (WANT_CONNECT_LOG(ctx) || WANT_CONTENT_LOG(ctx)) {
			ctx->dst_str = sys_sockaddr_str((struct sockaddr *)
			                                &ctx->addr,
			                                ctx->addrlen);
			if (!ctx->dst_str) {
				ctx->enomem = 1;
				pxy_conn_terminate_free(ctx);
				return;
			}

#ifdef HAVE_LOCAL_PROCINFO
			if (ctx->opts->lprocinfo) {
				/* fetch process info */
				if (proc_pid_for_addr(&ctx->lproc.pid,
				        (struct sockaddr*)&ctx->lproc.srcaddr,
				        ctx->lproc.srcaddrlen) == 0 &&
				    ctx->lproc.pid != -1 &&
				    proc_get_info(ctx->lproc.pid,
				                  &ctx->lproc.exec_path,
				                  &ctx->lproc.uid,
				                  &ctx->lproc.gid) == 0) {
					/* fetch user/group names */
					ctx->lproc.user = sys_user_str(
					                ctx->lproc.uid);
					ctx->lproc.group = sys_group_str(
					                ctx->lproc.gid);
					if (!ctx->lproc.user ||
					    !ctx->lproc.group) {
						ctx->enomem = 1;
						pxy_conn_terminate_free(ctx);
						return;
					}
				}
			}
#endif /* HAVE_LOCAL_PROCINFO */
		}
		if (WANT_CONTENT_LOG(ctx)) {
			if (log_content_open(&ctx->logctx, ctx->opts,
			                     ctx->src_str, ctx->dst_str,
#ifdef HAVE_LOCAL_PROCINFO
			                     ctx->lproc.exec_path,
			                     ctx->lproc.user,
			                     ctx->lproc.group
#else /* HAVE_LOCAL_PROCINFO */
			                     NULL, NULL, NULL
#endif /* HAVE_LOCAL_PROCINFO */
			                    ) == -1) {
				if (errno == ENOMEM)
					ctx->enomem = 1;
				pxy_conn_terminate_free(ctx);
				return;
			}
		}
//		printf("dst event call back finish %f \n", time_milli());
connected:
		/* log connection if we don't analyze any headers */
		if ((!this->ssl || (bev == ctx->src.bev)) &&
		    (!ctx->spec->http || ctx->passthrough) &&
		    WANT_CONNECT_LOG(ctx)) {
//			pxy_log_connect_nonhttp(ctx);
		}
		if (OPTS_DEBUG(ctx->opts)) {
			if (this->ssl) {
				/* for SSL, we get two connect events */
				log_dbg_printf("SSL connected %s %s \n",
				               bev == ctx->dst.bev ?
				               "to" : "from",
				               bev == ctx->dst.bev ?
				               ctx->dst_str : ctx->src_str);
//				               SSL_get_version(this->ssl),
//				               SSL_get_cipher(this->ssl));
			} else {
				/* for TCP, we get only a dst connect event,
				 * since src was already connected from the
				 * beginning; mirror SSL debug output anyway
				 * in order not to confuse anyone who might be
				 * looking closely at the output */
				log_dbg_printf("TCP connected to %s\n",
				               ctx->dst_str);
				log_dbg_printf("TCP connected from %s\n",
				               ctx->src_str);
			}
		}

		return;
	}

	if (events & BEV_EVENT_ERROR) {
		unsigned long sslerr;
		int have_sslerr = 0;

		/* Can happen for socket errs, ssl errs;
		 * may happen for unclean ssl socket shutdowns. */
		sslerr = bufferevent_get_openssl_error(bev);
//		printf("error ! %s \n",evutil_socket_error_to_string(	EVUTIL_SOCKET_ERROR()));
		if (sslerr){
			//printf("sslerr %d\n",sslerr);
			have_sslerr = 1;
		}
		if (!errno && !sslerr) {
#if LIBEVENT_VERSION_NUMBER >= 0x02010000
			/* We have disabled notification for unclean shutdowns
			 * so this should not happen; log a warning. */
			log_err_printf("Warning: Spurious error from "
			               "bufferevent (errno=0,sslerr=0)\n");
#else /* LIBEVENT_VERSION_NUMBER < 0x02010000 */
			/* Older versions of libevent will report these. */
			if (OPTS_DEBUG(ctx->opts)) {
				log_dbg_printf("Unclean SSL shutdown. %d\n",errno);
			}
#endif /* LIBEVENT_VERSION_NUMBER < 0x02010000 */
		} else if (ERR_GET_REASON(sslerr) ==
		           SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE) {
			/* these can happen due to client cert auth,
			 * only log error if debugging is activated */
			log_dbg_printf("Error from bufferevent: "
			               "%i:%s %lu:%i:%s:%i:%s:%i:%s\n",
			               errno,
			               errno ? strerror(errno) : "-",
			               sslerr,
			               ERR_GET_REASON(sslerr),
			               sslerr ?
			               ERR_reason_error_string(sslerr) : "-",
			               ERR_GET_LIB(sslerr),
			               sslerr ?
			               ERR_lib_error_string(sslerr) : "-",
			               ERR_GET_FUNC(sslerr),
			               sslerr ?
			               ERR_func_error_string(sslerr) : "-");
			while ((sslerr = bufferevent_get_openssl_error(bev))) {
				log_dbg_printf("Additional SSL error: "
				               "%lu:%i:%s:%i:%s:%i:%s\n",
				               sslerr,
				               ERR_GET_REASON(sslerr),
				               ERR_reason_error_string(sslerr),
				               ERR_GET_LIB(sslerr),
				               ERR_lib_error_string(sslerr),
				               ERR_GET_FUNC(sslerr),
				               ERR_func_error_string(sslerr));
			}
		} else {
			/* real errors */
			log_err_printf("Error from bufferevent: "
			               "%i:%s %lu:%i:%s:%i:%s:%i:%s\n",
			               errno,
			               errno ? strerror(errno) : "-",
			               sslerr,
			               ERR_GET_REASON(sslerr),
			               sslerr ?
			               ERR_reason_error_string(sslerr) : "-",
			               ERR_GET_LIB(sslerr),
			               sslerr ?
			               ERR_lib_error_string(sslerr) : "-",
			               ERR_GET_FUNC(sslerr),
			               sslerr ?
			               ERR_func_error_string(sslerr) : "-");
			while ((sslerr = bufferevent_get_openssl_error(bev))) {
				log_err_printf("Additional SSL error: "
				               "%lu:%i:%s:%i:%s:%i:%s\n",
				               sslerr,
				               ERR_GET_REASON(sslerr),
				               ERR_reason_error_string(sslerr),
				               ERR_GET_LIB(sslerr),
				               ERR_lib_error_string(sslerr),
				               ERR_GET_FUNC(sslerr),
				               ERR_func_error_string(sslerr));
			}
		}

		log_dbg_printf("Error  %s %s \n",
					   bev == ctx->dst.bev ?
					   "dst" : "scr",
					   bev == ctx->dst.bev ?
					   ctx->dst_str : ctx->src_str);

		if (!ctx->connected) {
			/* the callout to the original destination failed,
			 * e.g. because it asked for client cert auth, so
			 * close the accepted socket and clean up */
			if (bev == ctx->dst.bev && ctx->dst.ssl &&
			    ctx->opts->passthrough && have_sslerr) {
				/* ssl callout failed, fall back to plain
				 * TCP passthrough of SSL connection */
				bufferevent_free_and_close_fd(bev, ctx);
				ctx->dst.bev = NULL;
				ctx->dst.ssl = NULL;
				ctx->passthrough = 1;
				log_dbg_printf("SSL dst connection failed; fal"
				               "ling back to passthrough\n");
				pxy_fd_readcb(ctx->fd, 0, ctx);
				return;
			}
			evutil_closesocket(ctx->fd);
			other->closed = 1;
		} else if (!other->closed) {
			/* if the other end is still open and doesn't have data
			 * to send, close it, otherwise its writecb will close
			 * it after writing what's left in the output buffer */
			struct evbuffer *outbuf;
			outbuf = bufferevent_get_output(other->bev);
			if (evbuffer_get_length(outbuf) == 0) {
				bufferevent_free_and_close_fd(other->bev, ctx);
				other->closed = 1;
			}
		}
		goto leave;
	}

	if (events & BEV_EVENT_EOF) {
		if (!other->closed) {
			struct evbuffer *inbuf, *outbuf;
			inbuf = bufferevent_get_input(bev);
			outbuf = bufferevent_get_output(other->bev);
			if (evbuffer_get_length(inbuf) > 0) {
				evbuffer_add_buffer(outbuf, inbuf);
			} else {
				/* if the other end is still open and doesn't
				 * have data to send, close it, otherwise its
				 * writecb will close it after writing what's
				 * left in the output buffer. */
				if (evbuffer_get_length(outbuf) == 0) {
					bufferevent_free_and_close_fd(
							other->bev, ctx);
					other->closed = 1;
				}
			}
		}
		goto leave;
	}

	log_err_printf("Unknown bufferevent 0x%02X\n", (int)events);
	return;

leave:
	/* we only get a single disconnect event here for both connections */
	if (OPTS_DEBUG(ctx->opts)) {
		log_dbg_printf("%s disconnected to %s\n",
		               this->ssl ? "SSL" : "TCP",
		               ctx->dst_str);
		log_dbg_printf("%s disconnected from %s\n",
		               this->ssl ? "SSL" : "TCP",
		               ctx->src_str);
	}

	this->closed = 1;
	bufferevent_free_and_close_fd(bev, ctx);
	if (other->closed) {
		pxy_conn_ctx_free(ctx);
	}
}

/*
 * Complete the connection.  This gets called after finding out where to
 * connect to.
 */
static void
pxy_conn_connect(pxy_conn_ctx_t *ctx)
{
	if (!ctx->addrlen) {
		unsigned char buff[1024];
		recv(ctx->fd,buff,sizeof(buff),MSG_PEEK);
#if 0
		printf("ctx->addrlen == 0 | %s \n",buff);
#endif
		log_err_printf("No target address; aborting connection\n");
		evutil_closesocket(ctx->fd);
		pxy_conn_ctx_free(ctx);
		return;
	}

	/* create server-side socket and eventbuffer */
	if (ctx->req_ssl && !ctx->passthrough) {
		ctx->dst.ssl = pxy_dstssl_create(ctx);
		if (!ctx->dst.ssl) {
			log_err_printf("Error creating SSL\n");
			evutil_closesocket(ctx->fd);
			pxy_conn_ctx_free(ctx);
			return;
		}
	}
	ctx->dst.bev = pxy_bufferevent_setup(ctx, -1, ctx->dst.ssl);
	if (!ctx->dst.bev) {
		if (ctx->dst.ssl) {
			SSL_free(ctx->dst.ssl);
			ctx->dst.ssl = NULL;
		}
		evutil_closesocket(ctx->fd);
		pxy_conn_ctx_free(ctx);
		return;
	}

	if (OPTS_DEBUG(ctx->opts)) {
		char *ip = sys_sockaddr_str((struct sockaddr *)&ctx->addr,
		                            ctx->addrlen);
		log_dbg_printf("Connecting to %s\n", ip);
		if (ip)
			free(ip);
	}

	/* initiate connection */
	//double endTime = time_milli();
//	printf("connect Time %f\n",endTime);
	bufferevent_socket_connect(ctx->dst.bev,
	                           (struct sockaddr *)&ctx->addr,
	                           ctx->addrlen);
}

#ifndef OPENSSL_NO_TLSEXT
/*
 * The SNI hostname has been resolved.  Fill the first resolved address into
 * the context and continue connecting.
 */
static void
pxy_sni_resolve_cb(int errcode, struct evutil_addrinfo *ai, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
//	printf("sni_resolve_cb %f\n",time_milli());
	if (errcode) {
		log_err_printf("Cannot resolve SNI hostname '%s': %s\n",
		               ctx->sni, evutil_gai_strerror(errcode));
		evutil_closesocket(ctx->fd);
		pxy_conn_ctx_free(ctx);
		return;
	}
	memcpy(&ctx->addr, ai->ai_addr, ai->ai_addrlen);
	ctx->addrlen = ai->ai_addrlen;
	evutil_freeaddrinfo(ai);
	/* print port of dst */
#if 0
	if(((struct sockaddr*)ai)->sa_family == AF_INET){
		printf("sni resovle port %d \n",((struct sockaddr_in*)ai)->sin_port);
	}else{
		printf("port %d \n",((struct sockaddr_in6*)ai)->sin6_port);
	}
#endif
	pxy_conn_connect(ctx);
}
#endif /* !OPENSSL_NO_TLSEXT */

/*
 * The src fd is readable.  This is used to sneak-preview the SNI on SSL
 * connections.  If ctx->ev is NULL, it was called manually for a non-SSL
 * connection.  If ctx->passthrough is set, it was called a second time
 * after the first ssl callout failed because of client cert auth.
 */
#ifndef OPENSSL_NO_TLSEXT
#define MAYBE_UNUSED
#else /* OPENSSL_NO_TLSEXT */
#define MAYBE_UNUSED UNUSED
#endif /* OPENSSL_NO_TLSEXT */
/*
static void conn_mtd_readcb(MAYBE_UNUSED evutil_socket_t fd, UNUSED short what, void *arg){
	pxy_conn_ctx_t * arg;
	char response[] = "HTTP/1.1 200 Connection established\r\n\r\n";
	//struct bufferevent *bev;
	//struct evbuffer * evbuff;

	if (ctx->spec->ssl && !ctx->passthrough ) {
		unsigned char buf[1024];
		ssize_t n;

		n = recv(fd, buf, sizeof(buf), MSG_PEEK);
//		printf("buff %s\n",buf);
		if (n == -1) {
			log_err_printf("Error peeking on fd, aborting "
			               "connection\n");
			evutil_closesocket(fd);
			pxy_conn_ctx_free(ctx);
			return;
		}
		if (n == 0) {
			evutil_closesocket(fd);
			pxy_conn_ctx_free(ctx);
			return;
		}
		bev = bufferevent_openssl_socket_new(ctx->evbase,fd,ctx->src.ssl,
				BUFFEREVENT_SSL_ACCEPTING,BEV_OPT_DEFER_CALLBACKS);
		if(ctx->src.ssl){
			bufferevent_openssl_set_allow_dirty_shutdown(bev,1);
		}
		bufferevent_setcb(bev,NULL,pxy_fd_readcb,NULL);
		evbuff = evbuffer_new(void);
		evbuffer_add_buffer(evbuff,response,sizeof(response));
		bufferevent_write_buff(bev,evbuff);

}
*/

static void conn_resovle_cb(int errcode,struct evutil_addrinfo *ai,void *arg){
	pxy_conn_ctx_t *ctx = arg;

	if(errcode) {
		printf("Can not resolve CONNECT hostname '%s' : %s\n",
				ctx->sni,evutil_gai_strerror(errcode));
		evutil_closesocket(ctx->fd);
		pxy_conn_ctx_free(ctx);
		return;
	}
#if 0
	printf("in conn_resolve_cb\n");
#endif
	memcpy(&ctx->addr,ai->ai_addr,ai->ai_addrlen);
	ctx->addrlen = ai->ai_addrlen;
	evutil_freeaddrinfo(ai);
	pxy_conn_connect(ctx);
}

static void setup_dst_addr_from_conn(pxy_conn_ctx_t* ctx,unsigned char *buff){
	char method[100],url[1024], protocol[100];
	unsigned short port;
	int iport;
	char host[1024];
//	int err;
#if 0
	printf("setup_dst_addr_from_conn \n");
#endif
	if(sscanf((char*)buff,"%[^ ] %[^ ] %[^ ]",method,url,protocol) != 3){
		return;
	}
	if(!strcmp(method,"CONNECT")){
		struct evutil_addrinfo hints;
//		struct evutil_addrinfo *answer = NULL;
		char sniport[6];
		if(sscanf(url,"%[^:]:%d",host,&iport) == 2){
			port = (unsigned short) iport;
		}else if(sscanf(url,"%s",host) == 1){
			port = 443;
		}else {
			return;
		}
		memset(&hints,0,sizeof(hints));

		hints.ai_family = ctx->af;
		hints.ai_flags = EVUTIL_AI_ADDRCONFIG;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		snprintf(sniport,sizeof(sniport),"%i",port);
		evdns_getaddrinfo(ctx->dnsbase, host,"443" ,&hints,
				conn_resovle_cb, ctx);
		/*
		err = evutil_getaddrinfo(host,"443",&hints,&answer);
		if(err != 0){
			printf("Error host %s \n",host);
			return;
		}
		assert(answer);
		*/
	}
	return;
}

/* parse request, if it is CONNECT METHOD,retrun 1,otherwise 0*/
static int parse_req(unsigned char *buf, pxy_conn_ctx_t *ctx){
	char method[100],url[1024], protocol[100];
	if(sscanf((char*)buf,"%[^ ] %[^ ] %[^ ]",method,url,protocol) != 3){
		printf("can not parse request!\n");
		return 0;
	}
	if(!strcmp(method,"CONNECT")){
		char host[100];
		int iport;
		if(sscanf(url,"%[^:]:%d",host,&iport) == 2){
			goto success;
		}else if(sscanf(url,"%s",host) == 1){
			goto success;
		}else {
			return 0;
		}
success:
		ctx->conn_host = malloc((strlen(host) + 1) * sizeof(char));
		memcpy(ctx->conn_host,host,strlen(host));
		ctx->conn_host[strlen(host)] = '\0';
		return 1;
	}
	return 0;
}

static void pxy_http_resolve_cb(int errcode,struct evutil_addrinfo *ai,void *arg){
	pxy_conn_ctx_t *ctx = arg;

	if(errcode) {
		printf("Can not resolve CONNECT hostname '%s' : %s\n",
				ctx->sni,evutil_gai_strerror(errcode));
		evutil_closesocket(ctx->fd);
		pxy_conn_ctx_free(ctx);
		return;
	}
#if 0
	printf("in conn_http_resolve_cb\n");
#endif
	memcpy(&ctx->addr,ai->ai_addr,ai->ai_addrlen);
	ctx->addrlen = ai->ai_addrlen;
	evutil_freeaddrinfo(ai);
	pxy_conn_connect(ctx);
}
static void
pxy_fd_readcb(MAYBE_UNUSED evutil_socket_t fd, UNUSED short what, void *arg)
#undef MAYBE_UNUSED
{
	pxy_conn_ctx_t *ctx = arg;
	unsigned char buf[1024];
#if 0
	printf("start of pxy_fd_readcb\n");
#endif
#ifndef OPENSSL_NO_TLSEXT
	/* for SSL, peek clientHello and parse SNI from it */
	if (/*ctx->spec->ssl &&*/ !ctx->passthrough /*&& ctx->ev*/) {
		ssize_t n;

		/*	read content from client */
		//double startTime = time_milli();
		n = recv(fd, buf, sizeof(buf), MSG_PEEK);
//		printf("receive client hello Time %f\n",startTime);
#if 0
		printf("first recv: %s\n",buf);
#endif
		if (n == -1) {
			log_err_printf("Error peeking on fd, aborting "
					"connection\n");
			evutil_closesocket(fd);
			pxy_conn_ctx_free(ctx);
			return;
		}
		if (n == 0) {
			/* socket got closed while we were waiting */
			evutil_closesocket(fd);
			pxy_conn_ctx_free(ctx);
			return;
		}
#if 0
		if(parse_req(buf)){
			char response[] = "HTTP/1.0 200 Connection established\r\n\r\n";
			printf("parese_req CONNECT METHOD\n");
			ctx->req_ssl = 1;
			n = recv(fd, buf, sizeof(buf), 0);
			event_free(ctx->ev);
			ctx->ev = event_new(ctx->evbase, fd, EV_READ,
					pxy_fd_readcb, ctx);
			if (!ctx->ev) {
				printf("Error create event after handling CONNECT request\n");
				evutil_closesocket(fd);
				pxy_conn_ctx_free(ctx);
				return;
			}
			event_add(ctx->ev, NULL);
			n = send(fd,response,sizeof(response) - 1,0);
			return;

			/*
			   sleep(1);
			   memset(cHello,0,sizeof(cHello));
			   n = recv(fd,cHello,sizeof(cHello),MSG_PEEK);
			   printf("client hello: %d\n",(int)n);
			   for(int i =0;i < n ;++i){
			   printf("%02x ",cHello[i]);
			   }
			   printf("\n");
			   assert(n > 0);
			   ctx->sni = ssl_tls_clienthello_parse_sni(cHello, &n);
			   */
		}
#endif
		ctx->sni = ssl_tls_clienthello_parse_sni(buf, &n);
		if (OPTS_DEBUG(ctx->opts)) {
			log_dbg_printf("SNI peek: [%s] [%s]\n",
					ctx->sni ? ctx->sni : "n/a",
					(!ctx->sni && (n == -1)) ?
					"incomplete" : "complete");
		}
		if (!ctx->sni && (n == -1) && (ctx->sni_peek_retries++ < 50)) {
			/* ssl_tls_clienthello_parse_sni indicates that we
			 * should retry later when we have more data, and we
			 * haven't reached the maximum retry count yet.
			 * Reschedule this event as timeout-only event in
			 * order to prevent busy looping over the read event.
			 * Because we only peeked at the pending bytes and
			 * never actually read them, fd is still ready for
			 * reading now.  We use 25 * 0.2 s = 5 s timeout. */
			struct timeval retry_delay = {0, 100};

//			printf("in retrying\n");
			event_free(ctx->ev);
			ctx->ev = event_new(ctx->evbase, fd, 0,
					pxy_fd_readcb, ctx);
			if (!ctx->ev) {
				log_err_printf("Error creating retry "
						"event, aborting "
						"connection\n");
				evutil_closesocket(fd);
				pxy_conn_ctx_free(ctx);
				return;
			}
			event_add(ctx->ev, &retry_delay);
			return;
		}
		event_free(ctx->ev);
		ctx->ev = NULL;

#if 0
		/*	if can not get sni from clienthello	*/
		if(!ctx->sni && ctx->conn_host){
			setup_dst_addr_from_conn(ctx,buf);
			return;
		}
#endif
	}
	if(!ctx->sni){
		ctx->sni = malloc(sizeof(char) * strlen(ctx->conn_host));
		memcpy(ctx->sni, ctx->conn_host,strlen(ctx->conn_host));
		ctx->sni[strlen(ctx->conn_host)] = '\0';
	}
	if (ctx->sni /*&& !ctx->addrlen && ctx->spec->sni_port*/) {
		char sniport[6];
		struct evutil_addrinfo hints;

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = ctx->af;
		hints.ai_flags = EVUTIL_AI_ADDRCONFIG;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;

		snprintf(sniport, sizeof(sniport), "%i", ctx->spec->sni_port);
		evdns_getaddrinfo(ctx->dnsbase, ctx->sni, "443", &hints,
				pxy_sni_resolve_cb, ctx);
		return;
	}
#endif /* !OPENSSL_NO_TLSEXT */
#if 0
	if(!ctx->spec->ssl){
		unsigned char buff[1024];
		char method[100],url[1024],protocol[100];
		char host[100],path[1024];
		int iport;
		unsigned short port;
		struct evutil_addrinfo hints;
		struct evutil_addrinfo *answer = NULL;
		char sniport[6];
		recv(fd,buff,sizeof buff,MSG_PEEK);
		printf("buff %s \n",buff);
		if((sscanf((char*)buff,"%[^ ] %[^ ] %[^ ]",method,url,protocol))==3){
			int err;
			if( strncasecmp(url,"http://",7) == 0){
				(void) strncpy( url, "http", 4);
				if( sscanf(url,"http://%[^:/]:%d:%s",host,&iport,path) == 3){
					port = (unsigned short )iport;
				}else if(sscanf(url,"http://%[^/]%s",host,path) == 2) {
					port = 80;
				}else if(sscanf(url, "http://%[^:/]:%d",host,&iport) == 2){
					port = (unsigned short) iport;
					*path = '\0';
				}else if(sscanf (url,"http://%[^/]",host) == 1){
					port = 80;
					*path = '\0';
				}
			}

			memset(&hints,0,sizeof(hints));

			hints.ai_family = AF_UNSPEC;
			hints.ai_flags = EVUTIL_AI_ADDRCONFIG;
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_protocol = IPPROTO_TCP;
			snprintf(sniport,sizeof(sniport),"%i",port);

			evdns_getaddrinfo(ctx->dnsbase, host,sniport, &hints,
					pxy_http_resolve_cb, ctx);
			/*
			   err = evutil_getaddrinfo("www.google.com","443",&hints,&answer);
			   if(err != 0){
			   printf("!Error host %s\n",host);
			   printf("!Error host %s %s %s %s \n",method,host,sniport,path);
			   printf("Error http resolve %s \n",evutil_gai_strerror(err));
			   return;
			   }
			   assert(answer);
			   */
		}

		printf("!ctx->spec->ssl == 0 %s\n", buff);

	}
#endif
	//	pxy_conn_connect(ctx);
}

static void
pxy_first_request_parse(evutil_socket_t fd, UNUSED short what, void *arg){
	pxy_conn_ctx_t *ctx = arg;
	unsigned char buf[1024];
	ssize_t n;
	n = recv(fd, buf, sizeof(buf), MSG_PEEK);
	if (n == -1) {
		log_err_printf("Error peeking on fd, aborting "
					   "connection\n");
		evutil_closesocket(fd);
		pxy_conn_ctx_free(ctx);
		return;
	}
	if (n == 0) {
		/* socket got closed while we were waiting */
		evutil_closesocket(fd);
		pxy_conn_ctx_free(ctx);
		return;
	}
	if(parse_req(buf,ctx)){
		char response[] = "HTTP/1.0 200 Connection established\r\n\r\n";
		//double startTime;
		ctx->req_ssl = 1;
		n = recv(fd, buf, sizeof(buf), 0);
		event_free(ctx->ev);
		ctx->ev = event_new(ctx->evbase, fd, EV_READ,
							pxy_fd_readcb, ctx);
		if (!ctx->ev) {
			printf("Error create event after handling CONNECT request\n");
			evutil_closesocket(fd);
			pxy_conn_ctx_free(ctx);
			return;
		}
		event_add(ctx->ev, NULL);
		n = send(fd,response,sizeof(response) - 1,0);
		return;
	}else{
//		fprintf(stderr,"\n\n\n\n\n\n");
		ctx->req_ssl = 0;
		char method[100],url[1024],protocol[100];
		char host[100],path[1024];
		int iport;
		unsigned short port;
		struct evutil_addrinfo hints;
		char sniport[6];
		if((sscanf((char*)buf,"%[^ ] %[^ ] %[^ ]",method,url,protocol))==3){
			if( strncasecmp(url,"http://",7) == 0){
				(void) strncpy( url, "http", 4);
				if( sscanf(url,"http://%[^:/]:%d:%s",host,&iport,path) == 3){
					port = (unsigned short )iport;
				}else if(sscanf(url,"http://%[^/]%s",host,path) == 2) {
					port = 80;
				}else if(sscanf(url, "http://%[^:/]:%d",host,&iport) == 2){
					port = (unsigned short) iport;
					*path = '\0';
				}else if(sscanf (url,"http://%[^/]",host) == 1){
					port = 80;
					*path = '\0';
				}
			}

			memset(&hints,0,sizeof(hints));

			hints.ai_family = AF_UNSPEC;
			hints.ai_flags = EVUTIL_AI_ADDRCONFIG;
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_protocol = IPPROTO_TCP;
			snprintf(sniport,sizeof(sniport),"%i",port);

#if 0
			printf("host %s, sniport %s\n", host,sniport);
#endif
			evdns_getaddrinfo(ctx->dnsbase, host, sniport, &hints,
		                  pxy_http_resolve_cb, ctx);
#if 0
			err = evutil_getaddrinfo("www.google.com","443",&hints,&answer);
			if(err != 0){
				printf("!Error host %s\n",host);
				printf("!Error host %s %s %s %s \n",method,host,sniport,path);
				printf("Error http resolve %s \n",evutil_gai_strerror(err));
				return;
			}
			assert(answer);
#endif
		}else{
			assert(0);
		}
#if 0
		printf("!ctx->spec->ssl == 0 %s\n", buff);
#endif

	}

}

/*
 * Callback for accept events on the socket listener bufferevent.
 * Called when a new incoming connection has been accepted.
 * Initiates the connecion to the server.  The incoming connection
 * from the client is not being activated until we have a successful
 * connection to the server, because we need the server's certificate
 * in order to set up the SSL session to the client.
 * For consistency, plain TCP works the same way, even if we could
 * start reading from the client while waiting on the connection to
 * the server to connect.
 */
void
pxy_conn_setup(evutil_socket_t fd,
               struct sockaddr *peeraddr, int peeraddrlen,
               pxy_thrmgr_ctx_t *thrmgr,
               proxyspec_t *spec, opts_t *opts)
{
	pxy_conn_ctx_t *ctx;

	/* create per connection pair state and attach to thread */
	ctx = pxy_conn_ctx_new(spec, opts, thrmgr, fd);
#if 0
	printf("pxy_conn_setup\n");
#endif
	if (!ctx) {
		log_err_printf("Error allocating memory\n");
		evutil_closesocket(fd);
		return;
	}

	ctx->af = peeraddr->sa_family;

	/* determine original destination of connection */
	/*
	if (spec->natlookup) {
		ctx->addrlen = sizeof(struct sockaddr_storage);
		if (spec->natlookup((struct sockaddr *)&ctx->addr, &ctx->addrlen,
		                    fd, peeraddr, peeraddrlen) == -1) {
			log_err_printf("Connection not found in NAT "
			               "state table, aborting connection\n");
			evutil_closesocket(fd);
			pxy_conn_ctx_free(ctx);
			return;
		}
	} else if (spec->connect_addrlen > 0) {
		ctx->addrlen = spec->connect_addrlen;
		memcpy(&ctx->addr, &spec->connect_addr, ctx->addrlen);
	} else {
		if (!ctx->spec->ssl) {
			log_err_printf("SNI mode used for non-SSL connection; "
			               "aborting connection\n");
			evutil_closesocket(fd);
			pxy_conn_ctx_free(ctx);
			return;
		}
	}
	*/

	/* prepare logging, part 1 */
	if (WANT_CONNECT_LOG(ctx) || WANT_CONTENT_LOG(ctx)) {
		ctx->src_str = sys_sockaddr_str(peeraddr, peeraddrlen);
		if (!ctx->src_str)
			goto memout;
#ifdef HAVE_LOCAL_PROCINFO
		if (ctx->opts->lprocinfo) {
			memcpy(&ctx->lproc.srcaddr, peeraddr, peeraddrlen);
			ctx->lproc.srcaddrlen = peeraddrlen;
		}
#endif /* HAVE_LOCAL_PROCINFO */
	}

	/* for SSL, defer dst connection setup to initial_readcb */
#if 0
	if (ctx->spec->ssl) {
		ctx->ev = event_new(ctx->evbase, fd, EV_READ, pxy_fd_readcb,
		                    ctx);
		if (!ctx->ev)
			goto memout;
		event_add(ctx->ev, NULL);
	} else {
		ctx->ev = event_new(ctx->evbase, fd, EV_READ, pxy_fd_readcb,
		                    ctx);
		if (!ctx->ev)
			goto memout;
		event_add(ctx->ev, NULL);
		printf("Enter pxy_fd_readcb from here\n");
//		pxy_fd_readcb(fd, 0, ctx);
	}
#endif
	ctx->ev = event_new(ctx->evbase,fd,EV_READ,pxy_first_request_parse,ctx);
	if(!ctx->ev)
		goto memout;
	event_add(ctx->ev,NULL);
	return;

memout:
	log_err_printf("Aborting connection setup (out of memory)!\n");
	evutil_closesocket(fd);
	pxy_conn_ctx_free(ctx);
	return;
}

/* vim: set noet ft=c: */
