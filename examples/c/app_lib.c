__thread int tls_shared;
__thread int tls_shared2;
static __thread int tls_local_shared;

int get_tls_local_shared(void) { return tls_local_shared; }
int get_tls_shared(void) { return tls_shared; }
int get_tls_shared2(void) { return tls_shared2; }
void bump_tls_local_shared(void) { tls_local_shared += 16; }
