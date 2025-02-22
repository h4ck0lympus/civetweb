#define CUSTOM_HARNESS
#include "civetweb.h"
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

// stupid solution but this works i swear....

typedef struct ssl_st SSL;
typedef int volatile stop_flag_t;
typedef int SOCKET;

#define NUM_WEBDAV_LOCKS 10

#define PATH_MAX 4096
#define UTF8_PATH_MAX (PATH_MAX)

union usa {
	struct sockaddr sa;
	struct sockaddr_in sin;
#if defined(USE_IPV6)
	struct sockaddr_in6 sin6;
#endif
#if defined(USE_X_DOM_SOCKET)
	struct sockaddr_un sun;
#endif
};

/* Enum const for all options must be in sync with
 * static struct mg_option config_options[]
 * This is tested in the unit test (test/private.c)
 * "Private Config Options"
 */
enum {
	/* Once for each server */
	LISTENING_PORTS,
	NUM_THREADS,
	PRESPAWN_THREADS,
	RUN_AS_USER,
	CONFIG_TCP_NODELAY, /* Prepended CONFIG_ to avoid conflict with the
	                     * socket option typedef TCP_NODELAY. */
	MAX_REQUEST_SIZE,
	LINGER_TIMEOUT,
	CONNECTION_QUEUE_SIZE,
	LISTEN_BACKLOG_SIZE,
#if defined(__linux__)
	ALLOW_SENDFILE_CALL,
#endif
#if defined(_WIN32)
	CASE_SENSITIVE_FILES,
#endif
	THROTTLE,
	ENABLE_KEEP_ALIVE,
	REQUEST_TIMEOUT,
	KEEP_ALIVE_TIMEOUT,
#if defined(USE_WEBSOCKET)
	WEBSOCKET_TIMEOUT,
	ENABLE_WEBSOCKET_PING_PONG,
#endif
	DECODE_URL,
	DECODE_QUERY_STRING,
#if defined(USE_LUA)
	LUA_BACKGROUND_SCRIPT,
	LUA_BACKGROUND_SCRIPT_PARAMS,
#endif
#if defined(USE_HTTP2)
	ENABLE_HTTP2,
#endif

	/* Once for each domain */
	DOCUMENT_ROOT,
	FALLBACK_DOCUMENT_ROOT,

	ACCESS_LOG_FILE,
	ERROR_LOG_FILE,

	CGI_EXTENSIONS,
	CGI_ENVIRONMENT,
	CGI_INTERPRETER,
	CGI_INTERPRETER_ARGS,
#if defined(USE_TIMERS)
	CGI_TIMEOUT,
#endif
	CGI_BUFFERING,

	CGI2_EXTENSIONS,
	CGI2_ENVIRONMENT,
	CGI2_INTERPRETER,
	CGI2_INTERPRETER_ARGS,
#if defined(USE_TIMERS)
	CGI2_TIMEOUT,
#endif
	CGI2_BUFFERING,

#if defined(USE_4_CGI)
	CGI3_EXTENSIONS,
	CGI3_ENVIRONMENT,
	CGI3_INTERPRETER,
	CGI3_INTERPRETER_ARGS,
#if defined(USE_TIMERS)
	CGI3_TIMEOUT,
#endif
	CGI3_BUFFERING,

	CGI4_EXTENSIONS,
	CGI4_ENVIRONMENT,
	CGI4_INTERPRETER,
	CGI4_INTERPRETER_ARGS,
#if defined(USE_TIMERS)
	CGI4_TIMEOUT,
#endif
	CGI4_BUFFERING,
#endif

	PUT_DELETE_PASSWORDS_FILE, /* must follow CGI_* */
	PROTECT_URI,
	AUTHENTICATION_DOMAIN,
	ENABLE_AUTH_DOMAIN_CHECK,
	SSI_EXTENSIONS,
	ENABLE_DIRECTORY_LISTING,
	ENABLE_WEBDAV,
	GLOBAL_PASSWORDS_FILE,
	INDEX_FILES,
	ACCESS_CONTROL_LIST,
	EXTRA_MIME_TYPES,
	SSL_CERTIFICATE,
	SSL_CERTIFICATE_CHAIN,
	URL_REWRITE_PATTERN,
	HIDE_FILES,
	SSL_DO_VERIFY_PEER,
	SSL_CACHE_TIMEOUT,
	SSL_CA_PATH,
	SSL_CA_FILE,
	SSL_VERIFY_DEPTH,
	SSL_DEFAULT_VERIFY_PATHS,
	SSL_CIPHER_LIST,
	SSL_PROTOCOL_VERSION,
	SSL_SHORT_TRUST,

#if defined(USE_LUA)
	LUA_PRELOAD_FILE,
	LUA_SCRIPT_EXTENSIONS,
	LUA_SERVER_PAGE_EXTENSIONS,
#if defined(MG_EXPERIMENTAL_INTERFACES)
	LUA_DEBUG_PARAMS,
#endif
#endif
#if defined(USE_DUKTAPE)
	DUKTAPE_SCRIPT_EXTENSIONS,
#endif

#if defined(USE_WEBSOCKET)
	WEBSOCKET_ROOT,
	FALLBACK_WEBSOCKET_ROOT,
#endif
#if defined(USE_LUA) && defined(USE_WEBSOCKET)
	LUA_WEBSOCKET_EXTENSIONS,
#endif

	ACCESS_CONTROL_ALLOW_ORIGIN,
	ACCESS_CONTROL_ALLOW_METHODS,
	ACCESS_CONTROL_ALLOW_HEADERS,
	ACCESS_CONTROL_EXPOSE_HEADERS,
	ACCESS_CONTROL_ALLOW_CREDENTIALS,
	ERROR_PAGES,
#if !defined(NO_CACHING)
	STATIC_FILE_MAX_AGE,
	STATIC_FILE_CACHE_CONTROL,
#endif
#if !defined(NO_SSL)
	STRICT_HTTPS_MAX_AGE,
#endif
	ADDITIONAL_HEADER,
	ALLOW_INDEX_SCRIPT_SUB_RES,

	NUM_OPTIONS
};

struct socket {
	SOCKET sock;             /* Listening socket */
	union usa lsa;           /* Local socket address */
	union usa rsa;           /* Remote socket address */
	unsigned char is_ssl;    /* Is port SSL-ed */
	unsigned char ssl_redir; /* Is port supposed to redirect everything to SSL
	                          * port */
	unsigned char
	    is_optional; /* Shouldn't cause us to exit if we can't bind to it */
	unsigned char in_use; /* 0: invalid, 1: valid, 2: free */
};

struct mg_connection {
	int connection_type; /* see CONNECTION_TYPE_* above */
	int protocol_type;   /* see PROTOCOL_TYPE_*: 0=http/1.x, 1=ws, 2=http/2 */
	int request_state;   /* 0: nothing sent, 1: header partially sent, 2: header
	                     fully sent */
#if defined(USE_HTTP2)
	struct mg_http2_connection http2;
#endif

	struct mg_request_info request_info;
	struct mg_response_info response_info;

	struct mg_context *phys_ctx;
	struct mg_domain_context *dom_ctx;

#if defined(USE_SERVER_STATS)
	int conn_state; /* 0 = undef, numerical value may change in different
	                 * versions. For the current definition, see
	                 * mg_get_connection_info_impl */
#endif
	SSL *ssl;               /* SSL descriptor */
	struct socket client;   /* Connected client */
	time_t conn_birth_time; /* Time (wall clock) when connection was
	                         * established */
#if defined(USE_SERVER_STATS)
	time_t conn_close_time; /* Time (wall clock) when connection was
	                         * closed (or 0 if still open) */
	double processing_time; /* Processing time for one request. */
#endif
	struct timespec req_time; /* Time (since system start) when the request
	                           * was received */
	int64_t num_bytes_sent;   /* Total bytes sent to client */
	int64_t content_len;      /* How many bytes of content can be read
	                           * !is_chunked: Content-Length header value
	                           *              or -1 (until connection closed,
	                           *                     not allowed for a request)
	                           * is_chunked: >= 0, appended gradually
	                           */
	int64_t consumed_content; /* How many bytes of content have been read */
	int is_chunked;           /* Transfer-Encoding is chunked:
	                           * 0 = not chunked,
	                           * 1 = chunked, not yet, or some data read,
	                           * 2 = chunked, has error,
	                           * 3 = chunked, all data read except trailer,
	                           * 4 = chunked, all data read
	                           */
	char *buf;                /* Buffer for received data */
	char *path_info;          /* PATH_INFO part of the URL */

	int must_close;       /* 1 if connection must be closed */
	int accept_gzip;      /* 1 if gzip encoding is accepted */
	int in_error_handler; /* 1 if in handler for user defined error
	                       * pages */
#if defined(USE_WEBSOCKET)
	int in_websocket_handling; /* 1 if in read_websocket */
#endif
#if defined(USE_ZLIB) && defined(USE_WEBSOCKET)                                \
    && defined(MG_EXPERIMENTAL_INTERFACES)
	/* Parameters for websocket data compression according to rfc7692 */
	int websocket_deflate_server_max_windows_bits;
	int websocket_deflate_client_max_windows_bits;
	int websocket_deflate_server_no_context_takeover;
	int websocket_deflate_client_no_context_takeover;
	int websocket_deflate_initialized;
	int websocket_deflate_flush;
	z_stream websocket_deflate_state;
	z_stream websocket_inflate_state;
#endif
	int handled_requests; /* Number of requests handled by this connection
	                       */
	int buf_size;         /* Buffer size */
	int request_len;      /* Size of the request + headers in a buffer */
	int data_len;         /* Total size of data in a buffer */
	int status_code;      /* HTTP reply status code, e.g. 200 */
	int throttle;         /* Throttling, bytes/sec. <= 0 means no
	                       * throttle */

	time_t last_throttle_time; /* Last time throttled data was sent */
	int last_throttle_bytes;   /* Bytes sent this second */
	pthread_mutex_t mutex;     /* Used by mg_(un)lock_connection to ensure
	                            * atomic transmissions for websockets */
#if defined(USE_LUA) && defined(USE_WEBSOCKET)
	void *lua_websocket_state; /* Lua_State for a websocket connection */
#endif

	void *tls_user_ptr; /* User defined pointer in thread local storage,
	                     * for quick access */
};

struct twebdav_lock {
	uint64_t locktime;
	char token[33];
	char path[UTF8_PATH_MAX * 2];
	char user[UTF8_PATH_MAX * 2];
};

typedef struct ssl_ctx_st SSL_CTX;

struct mg_domain_context {
	SSL_CTX *ssl_ctx;                 /* SSL context */
	char *config[NUM_OPTIONS];        /* Civetweb configuration parameters */
	struct mg_handler_info *handlers; /* linked list of uri handlers */
	int64_t ssl_cert_last_mtime;

	/* Server nonce */
	uint64_t auth_nonce_mask;  /* Mask for all nonce values */
	unsigned long nonce_count; /* Used nonces, used for authentication */

#if defined(USE_LUA) && defined(USE_WEBSOCKET)
	/* linked list of shared lua websockets */
	struct mg_shared_lua_websocket_list *shared_lua_websockets;
#endif

	/* Linked list of domains */
	struct mg_domain_context *next;
};


struct mg_context {

	/* Part 1 - Physical context:
	 * This holds threads, ports, timeouts, ...
	 * set for the entire server, independent from the
	 * addressed hostname.
	 */

	/* Connection related */
	int context_type; /* See CONTEXT_* above */

	struct socket *listening_sockets;
	struct mg_pollfd *listening_socket_fds;
	unsigned int num_listening_sockets;

	struct mg_connection *worker_connections; /* The connection struct, pre-
	                                           * allocated for each worker */

#if defined(USE_SERVER_STATS)
	volatile ptrdiff_t active_connections;
	volatile ptrdiff_t max_active_connections;
	volatile ptrdiff_t total_connections;
	volatile ptrdiff_t total_requests;
	volatile int64_t total_data_read;
	volatile int64_t total_data_written;
#endif

	/* Thread related */
	stop_flag_t stop_flag;        /* Should we stop event loop */
	pthread_mutex_t thread_mutex; /* Protects client_socks or queue */

	pthread_t masterthreadid;            /* The master thread ID */
	unsigned int cfg_max_worker_threads; /* How many worker-threads we are
	                                        allowed to create, total */

	unsigned int spawned_worker_threads; /* How many worker-threads currently
	                                        exist (modified by master thread) */
	unsigned int
	    idle_worker_thread_count; /* How many worker-threads are currently
	                                 sitting around with nothing to do */
	/* Access to this value MUST be synchronized by thread_mutex */

	pthread_t *worker_threadids;      /* The worker thread IDs */
	unsigned long starter_thread_idx; /* thread index which called mg_start */

	/* Connection to thread dispatching */
#if defined(ALTERNATIVE_QUEUE)
	struct socket *client_socks;
	void **client_wait_events;
#else
	struct socket *squeue; /* Socket queue (sq) : accepted sockets waiting for a
	                       worker thread */
	volatile int sq_head;  /* Head of the socket queue */
	volatile int sq_tail;  /* Tail of the socket queue */
	pthread_cond_t sq_full;  /* Signaled when socket is produced */
	pthread_cond_t sq_empty; /* Signaled when socket is consumed */
	volatile int sq_blocked; /* Status information: sq is full */
	int sq_size;             /* No of elements in socket queue */
#if defined(USE_SERVER_STATS)
	int sq_max_fill;
#endif /* USE_SERVER_STATS */
#endif /* ALTERNATIVE_QUEUE */

	/* Memory related */
	unsigned int max_request_size; /* The max request size */

#if defined(USE_SERVER_STATS)
	struct mg_memory_stat ctx_memory;
#endif

	/* WebDAV lock structures */
	struct twebdav_lock webdav_lock[NUM_WEBDAV_LOCKS];

	/* Operating system related */
	char *systemName;  /* What operating system is running */
	time_t start_time; /* Server start time, used for authentication
	                    * and for diagnstics. */

#if defined(USE_TIMERS)
	struct ttimers *timers;
#endif

	/* Lua specific: Background operations and shared websockets */
#if defined(USE_LUA)
	void *lua_background_state;   /* lua_State (here as void *) */
	pthread_mutex_t lua_bg_mutex; /* Protect background state */
	int lua_bg_log_available;     /* Use Lua background state for access log */
#endif

	int user_shutdown_notification_socket;   /* mg_stop() will close this
	                                            socket... */
	int thread_shutdown_notification_socket; /* to cause poll() in all threads
	                                            to return immediately */

	/* Server nonce */
	pthread_mutex_t nonce_mutex; /* Protects ssl_ctx, handlers,
	                              * ssl_cert_last_mtime, nonce_count, and
	                              * next (linked list) */

	/* Server callbacks */
	struct mg_callbacks callbacks; /* User-defined callback function */
	void *user_data;               /* User-defined data */

	/* Part 2 - Logical domain:
	 * This holds hostname, TLS certificate, document root, ...
	 * set for a domain hosted at the server.
	 * There may be multiple domains hosted at one physical server.
	 * The default domain "dd" is the first element of a list of
	 * domains.
	 */
	struct mg_domain_context dd; /* default domain */
};


#define MAX_CONNECTIONS 4

static struct mg_context *ctx = NULL; // server context
static unsigned short PORT_NUM_HTTP = 0; // port number we are running the server on
static uint64_t call_count = 0; // how many times we have called the fuzzer 

const char *init_options[] = {
    "listening_ports","0", // automatically pick free tcp port at runtime
    "document_root",".",
    NULL
};

static void civetweb_exit(void) {
    mg_stop(ctx);
    ctx = NULL;
}

// https://github.com/civetweb/civetweb/blob/7f95a2632ef651402c15c39b72c4620382dd82bf/fuzztest/fuzzmain.c#L74
static void civetweb_init(void) {
    struct mg_callbacks callbacks;
    struct mg_server_port ports[8];
    memset(&callbacks, 0, sizeof(callbacks));
    memset(ports, 0, sizeof(ports));
    
    // we should look at the implementation in server 
    // global state whether or not loop is ran 
    ctx = mg_start(&callbacks, NULL, init_options);
    if (!ctx) {
        fprintf(stderr, "Failed to start CivetWeb\n");
        exit(1);
    }
    int ret = mg_get_server_ports(ctx, 8, ports);
    if (ret < 1) {
        fprintf(stderr, "Failed to get CivetWeb ports\n");
        exit(1);
    }
    PORT_NUM_HTTP = ports[0].port;
    sleep(5);
    atexit(civetweb_exit);
}

struct ThreadArgs {
    const uint8_t *data;
    size_t len;
} typedef ThreadArgs;

static void* fuzz_thread(void *arg) {
    ThreadArgs *t = (ThreadArgs*)arg;
    
    struct mg_connection *conn = (struct mg_connection*) malloc(sizeof(struct mg_connection));
    if (!conn) {
        fprintf(stderr, "Failed to allocate memory for struct mg_connection\n");
        return NULL;
    }
    memset(conn, 0, sizeof(struct mg_connection));
    conn->buf = (char*) t->data;
    conn->buf_size = t->len;
    conn->request_len = t->len;
    conn->data_len = t->len;
    
    struct mg_context fake_ctx;
    conn->phys_ctx = &fake_ctx;

    process_new_connection(conn);
    free(conn);
    return NULL;
}

int LLVMFuzzerTestOneInput(const char *data, size_t size) {
    // each thread should atleast get 1 byte of data to send
    if (size < MAX_CONNECTIONS) return 0;
    // if calling for the first time, initialize civet web
    if (call_count == 0) civetweb_init();
    call_count = 1;

    // divide data into 4 chunks, each thread gets equal amount of data
    size_t chunkSize = size / MAX_CONNECTIONS;
    pthread_t thr[4];
    ThreadArgs ta[4];

    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        ta[i].data = (const uint8_t*) data + (i * chunkSize);
        ta[i].len = chunkSize;
        pthread_create(&thr[i], NULL, fuzz_thread, &ta[i]);
    }

    for (int i = 0; i < 4; i++) {
        pthread_join(thr[i], NULL);
    }

    return 0;
}

