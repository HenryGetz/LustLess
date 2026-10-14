/*
 * fake_pipewire.c — a self-contained stand-in for libpipewire-0.3.so.0.
 *
 * Compiled at test time (see tests/pipewire_sys_fake.rs) with:
 *
 *     cc -shared -fPIC -O2 -o <tmp>/libpipewire-0.3.so.0 tests/fixtures/fake_pipewire.c
 *
 * and loaded with `pipewire_sys::load_named(<that path>)`. It is a faithful *transcription of
 * the 0.3.48 ABI* (headers read from ubuntu:22.04, under /usr/include/pipewire-0.3/pipewire and
 * /usr/include/spa-0.2/spa), not a reimplementation: it defines the pipewire-owned structs
 * and vtables with their real member order so that the Rust FFI layer's offsets and callback
 * signatures either match or the test fails loudly.
 *
 * It deliberately does not include any pipewire header (they may not be installed on a test
 * host): every struct below is spelled out by hand from the extracted 0.3.48 headers.
 *
 * Behaviour it fakes, all deterministic and single-threaded (the Rust test drives threads):
 *
 *  - `pw_get_library_version` -> "fake-0.3.48" (asserted against `PwLibrary::version()`).
 *  - `pw_core` begins with a real `struct spa_interface` whose `cb.funcs` is a
 *    `struct pw_core_methods` (version, add_listener, hello, sync, pong, error,
 *    get_registry, create_object, destroy); `get_registry` therefore sits at byte 48 and
 *    returns a `pw_registry` with its own `pw_registry_methods` table.
 *  - `pw_stream_add_listener` remembers the caller's events/hook; `pw_stream_connect` checks
 *    that `params[0]` is a well-formed format object pod and copies the bytes out for the
 *    test to compare against `pipewire_pod::enum_format_pod`.
 *  - `pw_main_loop_run`, when entered, fires `param_changed` with a hand-built format pod
 *    (video/raw/BGRx/64x48), then `process`, then blocks until `pw_main_loop_quit`.
 *  - `pw_stream_dequeue_buffer` returns a `pw_buffer` with one readable `SPA_DATA_MemPtr`
 *    plane pointing at a static 64x48 BGRx frame with a *non-packed* stride (320 not 256),
 *    so the consumer must honour `chunk.stride`.
 *  - the registry emits a single Node `global` carrying `restricted=1`.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* SPA / pipewire layout types (0.3.48 member order, spelled by hand)  */
/* ------------------------------------------------------------------ */

struct spa_list {
    struct spa_list *next;
    struct spa_list *prev;
};

struct spa_callbacks {
    const void *funcs;
    void *data;
};

/* spa/utils/hook.h: { const char *type; uint32_t version; struct spa_callbacks cb; } */
struct spa_interface {
    const char *type;
    uint32_t version;
    struct spa_callbacks cb;
};

/* spa/utils/hook.h: 48 bytes on both 0.3.48 and 1.0.x. */
struct spa_hook {
    struct spa_list link;
    struct spa_callbacks cb;
    void (*removed)(struct spa_hook *hook);
    void *priv;
};

/* spa/buffer/buffer.h */
struct spa_chunk {
    uint32_t offset;
    uint32_t size;
    int32_t stride;
    int32_t flags;
};

struct spa_meta {
    uint32_t type;
    uint32_t size;
    void *data;
};

struct spa_data {
    uint32_t type;
    uint32_t flags;
    int64_t fd;
    uint32_t mapoffset;
    uint32_t maxsize;
    void *data;
    struct spa_chunk *chunk;
};

struct spa_buffer {
    uint32_t n_metas;
    uint32_t n_datas;
    struct spa_meta *metas;
    struct spa_data *datas;
};

/* pipewire/stream.h — the 0.3.48 three-field form. We only ever touch `buffer` (offset 0),
 * which is identical in the 1.0.x five-field superset the Rust side models. */
struct pw_buffer {
    struct spa_buffer *buffer;
    void *user_data;
    uint64_t size;
};

/* spa/utils/dict.h */
struct spa_dict_item {
    const char *key;
    const char *value;
};

struct spa_dict {
    uint32_t flags;
    uint32_t n_items;
    const struct spa_dict_item *items;
};

/* pipewire/stream.h — 0.3.48 member order (version + 11 callbacks). */
struct pw_stream_events {
    uint32_t version;
    void (*destroy)(void *data);
    void (*state_changed)(void *data, int old, int state, const char *error);
    void (*control_info)(void *data, uint32_t id, const void *control);
    void (*io_changed)(void *data, uint32_t id, void *area, uint32_t size);
    void (*param_changed)(void *data, uint32_t id, const void *param);
    void (*add_buffer)(void *data, struct pw_buffer *buffer);
    void (*remove_buffer)(void *data, struct pw_buffer *buffer);
    void (*process)(void *data);
    void (*drained)(void *data);
    void (*command)(void *data, const void *command);
    void (*trigger_done)(void *data);
};

/* pipewire/core.h */
struct pw_registry_events {
    uint32_t version;
    void (*global)(void *object, uint32_t id, uint32_t permissions, const char *type,
                   uint32_t version, const struct spa_dict *props);
    void (*global_remove)(void *object, uint32_t id);
};

struct pw_core_methods {
    uint32_t version;
    int (*add_listener)(void *object, struct spa_hook *listener, const void *events, void *data);
    int (*hello)(void *object, uint32_t version);
    int (*sync)(void *object, uint32_t id, int seq);
    int (*pong)(void *object, uint32_t id, int seq);
    int (*error)(void *object, uint32_t id, int seq, int res, const char *message);
    struct pw_registry *(*get_registry)(void *object, uint32_t version, size_t user_data_size);
    void *(*create_object)(void *object, const char *factory_name, const char *type,
                           uint32_t version, const struct spa_dict *props, size_t user_data_size);
    int (*destroy)(void *object, void *proxy);
};

struct pw_registry_methods {
    uint32_t version;
    int (*add_listener)(void *object, struct spa_hook *listener,
                        const struct pw_registry_events *events, void *data);
    void *(*bind)(void *object, uint32_t id, const char *type, uint32_t version,
                  size_t user_data_size);
    int (*destroy)(void *object, uint32_t id);
};

/* ------------------------------------------------------------------ */
/* Constants (values verified against the 0.3.48 headers).             */
/* ------------------------------------------------------------------ */

#define SPA_TYPE_Id 3u
#define SPA_TYPE_Rectangle 0xau
#define SPA_TYPE_Object 0xfu
#define SPA_TYPE_OBJECT_Format 0x40003u

#define SPA_PARAM_Format 4u

#define SPA_FORMAT_mediaType 1u
#define SPA_FORMAT_mediaSubtype 2u
#define SPA_FORMAT_VIDEO_format 0x20001u
#define SPA_FORMAT_VIDEO_size 0x20003u

#define SPA_MEDIA_TYPE_video 2u
#define SPA_MEDIA_SUBTYPE_raw 1u
#define SPA_VIDEO_FORMAT_BGRx 8u

#define SPA_DATA_MemPtr 1u
#define SPA_DATA_FLAG_READABLE 1u

#define FAKE_WIDTH 64u
#define FAKE_HEIGHT 48u
#define FAKE_PACKED (FAKE_WIDTH * 4u)     /* 256: what a packed reader would assume */
#define FAKE_STRIDE (FAKE_PACKED + 64u)   /* 320: deliberately non-packed */
#define FAKE_PAD_BYTE 0xeeu               /* marker in the row padding */

/* ------------------------------------------------------------------ */
/* Opaque objects.                                                     */
/* ------------------------------------------------------------------ */

struct pw_loop {
    int unused;
};
struct pw_main_loop {
    struct pw_loop loop;
    volatile int quit;
};
struct pw_context {
    int unused;
};
/* A real pw_core / pw_registry begins with a struct spa_interface; the Rust layer relies on
 * that when it dispatches get_registry/add_listener through the vtable. */
struct pw_core {
    struct spa_interface iface;
};
struct pw_registry {
    struct spa_interface iface;
};
struct pw_properties {
    int unused;
};
struct pw_stream {
    int unused;
};

/* ------------------------------------------------------------------ */
/* Static fake frame + buffer plumbing.                                */
/* ------------------------------------------------------------------ */

static unsigned char g_frame[(size_t)FAKE_STRIDE * FAKE_HEIGHT];

static struct spa_chunk g_chunk = {
    .offset = 0,
    .size = (uint32_t)(FAKE_STRIDE * (FAKE_HEIGHT - 1) + FAKE_PACKED),
    .stride = (int32_t)FAKE_STRIDE,
    .flags = 0,
};

static struct spa_data g_datas[1] = {
    {
        .type = SPA_DATA_MemPtr,
        .flags = SPA_DATA_FLAG_READABLE,
        .fd = -1,
        .mapoffset = 0,
        .maxsize = (uint32_t)(FAKE_STRIDE * FAKE_HEIGHT),
        .data = g_frame,
        .chunk = &g_chunk,
    },
};

static struct spa_buffer g_spa_buffer = {
    .n_metas = 0,
    .n_datas = 1,
    .metas = NULL,
    .datas = g_datas,
};

static struct pw_buffer g_pw_buffer = {
    .buffer = &g_spa_buffer,
    .user_data = NULL,
    .size = 0,
};

/* ------------------------------------------------------------------ */
/* Cross-call state shared with the Rust test via exported getters.    */
/* ------------------------------------------------------------------ */

static const struct pw_stream_events *g_stream_events;
static struct spa_hook *g_stream_hook;
static void *g_stream_data;
static struct pw_core *g_last_core;
static struct pw_stream *g_last_stream;

static unsigned char g_params[8192];
static int g_params_len;
static int g_params_ok;

/* ------------------------------------------------------------------ */
/* Pod builder (spa/pod wire format, same encoding as pipewire_pod).   */
/* ------------------------------------------------------------------ */

struct pbuf {
    unsigned char b[512];
    size_t n;
};

static void put_u32(struct pbuf *out, uint32_t v) {
    memcpy(out->b + out->n, &v, 4);
    out->n += 4;
}

static void put_pod(struct pbuf *out, uint32_t type, const unsigned char *body, size_t n) {
    put_u32(out, (uint32_t)n);
    put_u32(out, type);
    memcpy(out->b + out->n, body, n);
    out->n += n;
    while (out->n % 8 != 0)
        out->b[out->n++] = 0;
}

static void put_id_pod(struct pbuf *out, uint32_t id) {
    unsigned char body[4];
    memcpy(body, &id, 4);
    put_pod(out, SPA_TYPE_Id, body, 4);
}

static void put_rect_pod(struct pbuf *out, uint32_t w, uint32_t h) {
    unsigned char body[8];
    memcpy(body, &w, 4);
    memcpy(body + 4, &h, 4);
    put_pod(out, SPA_TYPE_Rectangle, body, 8);
}

static void put_prop_key(struct pbuf *body, uint32_t key) {
    put_u32(body, key);
    put_u32(body, 0); /* property flags */
}

/* Build a SPA_TYPE_OBJECT_Format object pod describing video/raw/BGRx/64x48. */
static void build_format_pod(struct pbuf *out) {
    struct pbuf body;
    memset(&body, 0, sizeof(body));
    put_u32(&body, SPA_TYPE_OBJECT_Format);
    put_u32(&body, 0); /* object id */

    put_prop_key(&body, SPA_FORMAT_mediaType);
    put_id_pod(&body, SPA_MEDIA_TYPE_video);
    put_prop_key(&body, SPA_FORMAT_mediaSubtype);
    put_id_pod(&body, SPA_MEDIA_SUBTYPE_raw);
    put_prop_key(&body, SPA_FORMAT_VIDEO_format);
    put_id_pod(&body, SPA_VIDEO_FORMAT_BGRx);
    put_prop_key(&body, SPA_FORMAT_VIDEO_size);
    put_rect_pod(&body, FAKE_WIDTH, FAKE_HEIGHT);

    put_pod(out, SPA_TYPE_Object, body.b, body.n);
}

/* ------------------------------------------------------------------ */
/* Registry                                                             */
/* ------------------------------------------------------------------ */

static int fake_registry_add_listener(void *object, struct spa_hook *listener,
                                      const struct pw_registry_events *events, void *data) {
    static const struct spa_dict_item items[] = {
        {"restricted", "1"},
    };
    static const struct spa_dict dict = {0, 1, items};
    (void)object;
    (void)listener;
    if (events != NULL && events->global != NULL)
        events->global(data, 42, 0, "PipeWire:Interface:Node", 3, &dict);
    return 0;
}

static struct pw_registry_methods registry_methods = {
    .version = 0,
    .add_listener = fake_registry_add_listener,
    .bind = NULL,
    .destroy = NULL,
};

static struct pw_registry *fake_get_registry(void *object, uint32_t version,
                                             size_t user_data_size) {
    struct pw_registry *r;
    (void)object;
    (void)version;
    (void)user_data_size;
    r = (struct pw_registry *)calloc(1, sizeof(*r));
    if (r == NULL)
        return NULL;
    r->iface.type = "PipeWire:Interface:Registry";
    r->iface.version = 3;
    r->iface.cb.funcs = &registry_methods;
    r->iface.cb.data = r;
    return r;
}

static struct pw_core_methods core_methods = {
    .version = 0,
    .add_listener = NULL,
    .hello = NULL,
    .sync = NULL,
    .pong = NULL,
    .error = NULL,
    .get_registry = fake_get_registry,
    .create_object = NULL,
    .destroy = NULL,
};

/* ------------------------------------------------------------------ */
/* Library entry points                                                 */
/* ------------------------------------------------------------------ */

void pw_init(int *argc, char ***argv) {
    unsigned x, y;
    (void)argc;
    (void)argv;
    for (y = 0; y < FAKE_HEIGHT; y++) {
        unsigned char *row = g_frame + (size_t)y * FAKE_STRIDE;
        for (x = 0; x < FAKE_WIDTH; x++) {
            row[x * 4 + 0] = (unsigned char)(x & 0xffu);
            row[x * 4 + 1] = (unsigned char)(y & 0xffu);
            row[x * 4 + 2] = 0x80u;
            row[x * 4 + 3] = 0x00u;
        }
        for (x = FAKE_PACKED; x < FAKE_STRIDE; x++)
            row[x] = FAKE_PAD_BYTE;
    }
    g_params_len = 0;
    g_params_ok = 0;
    g_stream_hook = NULL;
    g_stream_events = NULL;
    g_stream_data = NULL;
}

void pw_deinit(void) {}

const char *pw_get_library_version(void) {
    return "fake-0.3.48";
}

struct pw_main_loop *pw_main_loop_new(const struct spa_dict *props) {
    struct pw_main_loop *loop;
    (void)props;
    loop = (struct pw_main_loop *)calloc(1, sizeof(*loop));
    return loop;
}

void pw_main_loop_destroy(struct pw_main_loop *loop) {
    free(loop);
}

struct pw_loop *pw_main_loop_get_loop(struct pw_main_loop *loop) {
    return &loop->loop;
}

int pw_main_loop_run(struct pw_main_loop *loop) {
    struct pbuf pod;
    memset(&pod, 0, sizeof(pod));
    build_format_pod(&pod);

    if (g_stream_events != NULL) {
        if (g_stream_events->param_changed != NULL)
            g_stream_events->param_changed(g_stream_data, SPA_PARAM_Format, pod.b);
        if (g_stream_events->process != NULL)
            g_stream_events->process(g_stream_data);
    }

    while (!loop->quit)
        usleep(1000);
    return 0;
}

int pw_main_loop_quit(struct pw_main_loop *loop) {
    loop->quit = 1;
    return 0;
}

void pw_loop_destroy(struct pw_loop *loop) {
    (void)loop; /* embedded in pw_main_loop */
}

struct pw_context *pw_context_new(struct pw_loop *main_loop, struct pw_properties *props,
                                  size_t user_data_size) {
    (void)main_loop;
    (void)user_data_size;
    if (props != NULL)
        free(props);
    return (struct pw_context *)calloc(1, sizeof(struct pw_context));
}

void pw_context_destroy(struct pw_context *context) {
    free(context);
}

const struct pw_properties *pw_context_get_properties(struct pw_context *context) {
    (void)context;
    return NULL;
}

struct pw_core *pw_context_connect_fd(struct pw_context *context, int fd,
                                      struct pw_properties *props, size_t user_data_size) {
    struct pw_core *core;
    (void)context;
    (void)user_data_size;
    if (props != NULL)
        free(props);
    /* pipewire owns the fd from here; we just close it. */
    if (fd >= 0)
        close(fd);
    core = (struct pw_core *)calloc(1, sizeof(*core));
    if (core == NULL)
        return NULL;
    core->iface.type = "PipeWire:Interface:Core";
    core->iface.version = 3;
    core->iface.cb.funcs = &core_methods;
    core->iface.cb.data = core;
    g_last_core = core;
    return core;
}

int pw_core_disconnect(struct pw_core *core) {
    if (core == g_last_core)
        g_last_core = NULL;
    free(core);
    return 0;
}

void pw_proxy_destroy(void *proxy) {
    free(proxy);
}

struct pw_stream *pw_stream_new(struct pw_core *core, const char *name,
                                struct pw_properties *props) {
    struct pw_stream *stream;
    (void)core;
    (void)name;
    if (props != NULL)
        free(props); /* ownership is taken per the header contract */
    stream = (struct pw_stream *)calloc(1, sizeof(*stream));
    g_last_stream = stream;
    return stream;
}

void pw_stream_destroy(struct pw_stream *stream) {
    if (stream == g_last_stream)
        g_last_stream = NULL;
    free(stream);
}

void pw_stream_add_listener(struct pw_stream *stream, struct spa_hook *listener,
                            const struct pw_stream_events *events, void *data) {
    (void)stream;
    g_stream_hook = listener;
    g_stream_events = events;
    g_stream_data = data;
}

int pw_stream_connect(struct pw_stream *stream, int direction, uint32_t target_id, int flags,
                      const void *const *params, uint32_t n_params) {
    (void)stream;
    (void)direction;
    (void)target_id;
    (void)flags;
    g_params_len = 0;
    g_params_ok = 0;
    if (params != NULL && n_params >= 1 && params[0] != NULL) {
        const unsigned char *p = (const unsigned char *)params[0];
        uint32_t size, type;
        memcpy(&size, p, 4);
        memcpy(&type, p + 4, 4);
        if (type == SPA_TYPE_Object && size >= 8) {
            uint32_t obj_type;
            memcpy(&obj_type, p + 8, 4);
            if (obj_type == SPA_TYPE_OBJECT_Format) {
                size_t total = ((size_t)8 + size + 7u) & ~(size_t)7u;
                if (total <= sizeof(g_params)) {
                    memcpy(g_params, p, total);
                    g_params_len = (int)total;
                    g_params_ok = 1;
                }
            }
        }
    }
    return 0;
}

int pw_stream_disconnect(struct pw_stream *stream) {
    (void)stream;
    return 0;
}

struct pw_buffer *pw_stream_dequeue_buffer(struct pw_stream *stream) {
    (void)stream;
    return &g_pw_buffer;
}

int pw_stream_queue_buffer(struct pw_stream *stream, struct pw_buffer *buffer) {
    (void)stream;
    (void)buffer;
    return 0;
}

struct pw_properties *pw_properties_new_string(const char *args) {
    (void)args;
    return (struct pw_properties *)calloc(1, sizeof(struct pw_properties));
}

int pw_properties_set(struct pw_properties *properties, const char *key, const char *value) {
    (void)properties;
    (void)key;
    (void)value;
    return 0;
}

void pw_properties_free(struct pw_properties *properties) {
    free(properties);
}

/* ------------------------------------------------------------------ */
/* Test-only getters (resolved by the Rust test via dlsym on the       */
/* PwLibrary handle, so no header needs to be shared).                 */
/* ------------------------------------------------------------------ */

int fake_pw_params_ok(void) {
    return g_params_ok;
}

const unsigned char *fake_pw_params_data(void) {
    return g_params;
}

int fake_pw_params_size(void) {
    return g_params_len;
}

void *fake_pw_last_core(void) {
    return g_last_core;
}

void *fake_pw_last_stream(void) {
    return g_last_stream;
}
