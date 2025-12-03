__thread int tls_shared;
static __thread int tls_local_shared;

int get_tls_local_shared(void) { return tls_local_shared; }
void bump_tls_local_shared(void) { tls_local_shared += 16; }
