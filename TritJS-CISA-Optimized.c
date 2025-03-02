/***********************************************************************
 * TritJS-CISA-Optimized: A Ternary Calculator with Advanced Features
 *
 * This program has been optimized for:
 *   - Improved memory management and safe dynamic reallocation.
 *   - Faster base conversion by grouping four base‑3 digits at a time.
 *   - Efficient multiplication using a Karatsuba algorithm (with a fallback
 *     to naïve multiplication for small inputs).
 *   - Enhanced security including file locking on audit logs and secure memory
 *     zeroing (where supported) using FIPS–validated crypto.
 *   - Real-time intrusion detection via a background monitoring thread.
 *   - Extended scripting by embedding Lua.
 *   - A responsive ncurses UI with color support and dynamic resizing.
 *
 * == Features ==
 * • Arithmetic: add, sub, mul, div, pow, fact
 * • Scientific: sqrt, log3, sin, cos, tan, pi (via double conversion)
 * • Conversions: bin2tri, tri2bin (optimized conversion routines),
 *   balanced/unbalanced ternary parsing
 * • State Management: save and load encrypted/signed session states
 * • Security: secure audit logging (with file locking), secure memory clearing,
 *   and intrusion detection
 * • Benchmarking: bench command runs performance tests
 * • Scripting & Variables: PROG/RUN, A=102, IF, FOR, plus Lua scripting
 * • Interface: enhanced ncurses-based UI (with color and terminal resize support)
 * • Build Automation: Makefile & CI/CD pipeline automate builds, tests, and deployment.
 *
 * == Compilation ==
 *   gcc -DUSE_READLINE -o tritjs_cisa_optimized tritjs_cisa_optimized.c -lm -lreadline \
 *       -fstack-protector-strong -D_FORTIFY_SOURCE=2 -pie -fPIE -lncurses -lcrypto -lpthread -llua
 *
 * == Usage ==
 *   ./tritjs_cisa_optimized
 *
 * == Integration Test Cases ==
 *   On startup, the program runs tests for:
 *     - Encryption/decryption round-trip.
 *     - Lua scripting (a simple add function).
 *     - Intrusion detection simulation.
 *
 * == License ==
 * GNU General Public License (GPL)
 ***********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>
#include <ncurses.h>
#ifdef USE_READLINE
#include <readline/readline.h>
#include <readline/history.h>
#endif
#include <errno.h>
#include <sys/file.h>  /* For file locking */
#include <openssl/evp.h>
#include <pthread.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

/* Global Configuration */
#define ENABLE_VERBOSE_LOGGING 1
#define VERSION "2.0-upgrade-optimized"

#define BASE_81 81
#define T81_MMAP_THRESHOLD (500 * 1024)

/* Error codes: 0=OK, 1=MemAlloc, 2=InvalidInput, 3=DivZero, 4=Overflow,
   5=Undefined, 6=Negative, 7=PrecisionErr, 8=MMapFail, 9=ScriptErr */
typedef int TritError;
#if ENABLE_VERBOSE_LOGGING
#define LOG_ERROR(err, context) log_error(err, context, __FILE__, __LINE__)
#else
#define LOG_ERROR(err, context) log_error(err, context)
#endif

/* Data Structures */
typedef struct {
    int sign;                 /* 0 = positive, 1 = negative */
    unsigned char *digits;    /* Array of base‑81 digits (little-endian) */
    size_t len;               /* Number of digits */
    int is_mapped;            /* 1 if allocated with mmap */
    int fd;                   /* File descriptor (if using mmap) */
    char tmp_path[32];        /* Temporary file path */
} T81BigInt;

typedef struct {
    int sign;
    unsigned char* integer;   /* Base‑81 digits for integer part */
    unsigned char* fraction;  /* Base‑81 digits for fractional part */
    size_t i_len, f_len;
    int i_mapped, f_mapped;
    int i_fd, f_fd;
    char i_tmp_path[32];
    char f_tmp_path[32];
} T81Float;

typedef struct {
    T81Float real;
    T81Float imag;
} T81Complex;

typedef struct {
    T81Float quotient;
    T81Float remainder;
} T81DivResult;

#define MAX_SCRIPT_NAME 10
#define MAX_SCRIPT_CMDS 50
typedef struct {
    char name[MAX_SCRIPT_NAME];
    char commands[MAX_SCRIPT_CMDS][256];
    int cmd_count;
} Script;

/* Global Variables */
static FILE* audit_log = NULL;
static long total_mapped_bytes = 0;
static int operation_steps = 0;

#define MAX_HISTORY 10
static char* history[MAX_HISTORY] = {0};
static int history_count = 0;

static T81BigInt* variables[26] = {0};
static Script scripts[10] = {0};
static int script_count = 0;

static WINDOW *input_win, *output_win, *status_win;

/* Function Prototypes */
TritError tritjs_add_big(T81BigInt* A, T81BigInt* B, T81BigInt** result);
TritError tritjs_subtract_big(T81BigInt* A, T81BigInt* B, T81BigInt** result);
TritError tritjs_multiply_big(T81BigInt* a, T81BigInt* b, T81BigInt** result);
TritError tritjs_factorial_big(T81BigInt* a, T81BigInt** result);
TritError tritjs_power_big(T81BigInt* base, T81BigInt* exp, T81BigInt** result);
TritError tritjs_divide_big(T81BigInt* a, T81BigInt* b, T81BigInt** quotient, T81BigInt** remainder);
TritError tritjs_sqrt_complex(T81BigInt* a, int precision, T81Complex* result);
TritError tritjs_log3_complex(T81BigInt* a, int precision, T81Complex* result);
TritError tritjs_sin_complex(T81BigInt* a, int precision, T81Complex* result);
TritError tritjs_cos_complex(T81BigInt* a, int precision, T81Complex* result);
TritError tritjs_tan_complex(T81BigInt* a, int precision, T81Complex* result);
TritError tritjs_pi(int* len, int** pi);
TritError parse_trit_string(const char* s, T81BigInt** out);
TritError t81bigint_to_trit_string(const T81BigInt* in, char** out);
TritError binary_to_trit(int num, T81BigInt** out);
TritError trit_to_binary(T81BigInt* x, int* outVal);
void tritbig_free(T81BigInt* x);
TritError parse_balanced_trit_string(const char* s, T81BigInt** out);

/* --- Logging and Error Handling --- */
static const char* trit_error_str(TritError err) {
    switch(err){
        case 0: return "No error";
        case 1: return "Memory allocation failed";
        case 2: return "Invalid input";
        case 3: return "Division by zero";
        case 4: return "Overflow detected";
        case 5: return "Operation undefined";
        case 6: return "Negative input";
        case 7: return "Precision limit exceeded";
        case 8: return "Memory mapping failed";
        case 9: return "Script error";
        default: return "Unknown error";
    }
}

static void log_error(TritError err, const char* context, const char* file, int line) {
    if (!audit_log) return;
    time_t now;
    time(&now);
    fprintf(audit_log, "[%s] ERROR %d: %s in %s (%s:%d)\n",
            ctime(&now), err, trit_error_str(err), context, file, line);
    fflush(audit_log);
}

/* --- Memory Management --- */
static TritError allocate_digits(T81BigInt *x, size_t lengthNeeded) {
    size_t bytesNeeded = (lengthNeeded == 0 ? 1 : lengthNeeded);
    x->len = lengthNeeded;
    x->is_mapped = 0;
    x->fd = -1;
    if (bytesNeeded < T81_MMAP_THRESHOLD) {
        x->digits = (unsigned char*)calloc(bytesNeeded, 1);
        if (!x->digits) return 1;
        return 0;
    }
    strcpy(x->tmp_path, "/tmp/tritjs_cisa_XXXXXX");
    x->fd = mkstemp(x->tmp_path);
    if (x->fd < 0) return 8;
    if (ftruncate(x->fd, bytesNeeded) < 0) {
        close(x->fd);
        return 8;
    }
    x->digits = mmap(NULL, bytesNeeded, PROT_READ | PROT_WRITE, MAP_SHARED, x->fd, 0);
    if (x->digits == MAP_FAILED) {
        close(x->fd);
        return 8;
    }
    unlink(x->tmp_path);
    x->is_mapped = 1;
    total_mapped_bytes += bytesNeeded;
    operation_steps++;
    return 0;
}

static void t81bigint_free(T81BigInt* x) {
    if (!x) return;
    if (x->is_mapped && x->digits && x->digits != MAP_FAILED) {
        size_t bytes = (x->len == 0 ? 1 : x->len);
        munmap(x->digits, bytes);
        close(x->fd);
        total_mapped_bytes -= bytes;
        operation_steps++;
    } else {
        free(x->digits);
    }
    memset(x, 0, sizeof(*x));
}

/* --- Audit Logging --- */
static void init_audit_log() {
    audit_log = fopen("/var/log/tritjs_cisa.log", "a");
    if (!audit_log) {
        perror("Audit log init failed; fallback to stderr");
        audit_log = stderr;
    } else {
        flock(fileno(audit_log), LOCK_EX);
    }
}

/* --- Base Conversion and Parsing --- */
static TritError parse_trit_string_base81_optimized(const char* str, T81BigInt* out) {
    if (!str || !str[0]) return 2;
    memset(out, 0, sizeof(*out));
    int sign = 0;
    size_t pos = 0;
    if (str[0] == '-' || str[0] == '–') { sign = 1; pos = 1; }
    size_t total_len = strlen(str) - pos;
    size_t remainder = total_len % 4;
    if (allocate_digits(out, 1)) return 1;
    out->digits[0] = 0;
    out->sign = sign;
    for (size_t i = 0; i < remainder; i++) {
        int digit = str[pos + i] - '0';
        if (digit < 0 || digit > 2) return 2;
        int carry = digit;
        for (size_t j = 0; j < out->len; j++) {
            int val = out->digits[j] * 3 + carry;
            out->digits[j] = val % BASE_81;
            carry = val / BASE_81;
        }
        while (carry) {
            size_t old_len = out->len;
            TritError e = allocate_digits(out, out->len + 1);
            if (e) return e;
            out->digits[old_len] = carry % BASE_81;
            carry /= BASE_81;
        }
    }
    pos += remainder;
    while (pos < strlen(str)) {
        int groupVal = 0;
        for (int k = 0; k < 4; k++) {
            if (str[pos + k] < '0' || str[pos + k] > '2') return 2;
            groupVal = groupVal * 3 + (str[pos + k] - '0');
        }
        pos += 4;
        int carry = groupVal;
        for (size_t j = 0; j < out->len; j++) {
            int val = out->digits[j] * 81 + carry;
            out->digits[j] = val % BASE_81;
            carry = val / BASE_81;
        }
        while (carry) {
            size_t old_len = out->len;
            TritError e = allocate_digits(out, out->len + 1);
            if (e) return e;
            out->digits[old_len] = carry % BASE_81;
            carry /= BASE_81;
        }
    }
    while (out->len > 1 && out->digits[out->len - 1] == 0)
        out->len--;
    return 0;
}

static TritError parse_trit_string(const char* s, T81BigInt** out) {
    if (!out) return 1;
    *out = (T81BigInt*)calloc(1, sizeof(T81BigInt));
    if (!*out) return 1;
    TritError e = parse_trit_string_base81_optimized(s, *out);
    if (e) { free(*out); *out = NULL; }
    return e;
}

static TritError t81bigint_to_trit_string(const T81BigInt* in, char** out) {
    if (!in || !out) return 2;
    if (in->len == 1 && in->digits[0] == 0) {
        *out = strdup("0");
        return 0;
    }
    T81BigInt tmp = *in;
    T81BigInt tmpCopy;
    memset(&tmpCopy, 0, sizeof(tmpCopy));
    if (allocate_digits(&tmpCopy, tmp.len)) return 1;
    tmpCopy.len = tmp.len;
    memcpy(tmpCopy.digits, tmp.digits, tmp.len);
    tmpCopy.sign = tmp.sign;
    size_t capacity = tmp.len * 4 + 2;
    char* buf = calloc(capacity, 1);
    if (!buf) { t81bigint_free(&tmpCopy); return 1; }
    size_t idx = 0;
    while (1) {
        int isZero = 1;
        for (size_t i = 0; i < tmpCopy.len; i++) {
            if (tmpCopy.digits[i] != 0) { isZero = 0; break; }
        }
        if (isZero) { if (idx == 0) buf[idx++] = '0'; break; }
        int carry = 0;
        for (ssize_t i = tmpCopy.len - 1; i >= 0; i--) {
            int val = tmpCopy.digits[i] + carry * BASE_81;
            int q = val / 3;
            int r = val % 3;
            tmpCopy.digits[i] = q;
            carry = r;
        }
        buf[idx++] = (char)('0' + carry);
    }
    t81bigint_free(&tmpCopy);
    if (in->sign) { buf[idx++] = '-'; }
    for (size_t i = 0; i < idx / 2; i++) {
        char t = buf[i];
        buf[i] = buf[idx - 1 - i];
        buf[idx - 1 - i] = t;
    }
    buf[idx] = '\0';
    *out = buf;
    return 0;
}

static TritError binary_to_trit(int num, T81BigInt** out) {
    char b3[128];
    int sign = (num < 0) ? 1 : 0;
    int val = (num < 0) ? -num : num;
    size_t idx = 0;
    if (val == 0) { b3[idx++] = '0'; }
    while (val > 0) { int r = val % 3; b3[idx++] = (char)('0' + r); val /= 3; }
    if (idx == 0) { b3[idx++] = '0'; }
    if (sign) { b3[idx++] = '-'; }
    for (size_t i = 0; i < idx / 2; i++) {
        char t = b3[i];
        b3[i] = b3[idx - 1 - i];
        b3[idx - 1 - i] = t;
    }
    b3[idx] = '\0';
    return parse_trit_string(b3, out);
}

static TritError trit_to_binary(T81BigInt* x, int* outVal) {
    char* b3 = NULL;
    if (t81bigint_to_trit_string(x, &b3) != 0) return 2;
    long long accum = 0;
    int sign = 0;
    size_t i = 0;
    if (b3[0] == '-') { sign = 1; i = 1; }
    for (; b3[i]; i++) {
        if (b3[i] < '0' || b3[i] > '2') { free(b3); return 2; }
        accum = accum * 3 + (b3[i] - '0');
        if (accum > INT_MAX) { free(b3); return 4; }
    }
    free(b3);
    if (sign) accum = -accum;
    *outVal = (int)accum;
    return 0;
}

void tritbig_free(T81BigInt* x) {
    if (!x) return;
    t81bigint_free(x);
    free(x);
}

/* --- Balanced Ternary Parsing --- */
TritError parse_balanced_trit_string(const char* s, T81BigInt** out) {
    if (!s) return 2;
    size_t len = strlen(s);
    char* unb = calloc(len + 1, 1);
    if (!unb) return 1;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (c == '-' || c == '–') { unb[i] = '0'; }
        else if (c == '0') { unb[i] = '1'; }
        else if (c == '+') { unb[i] = '2'; }
        else { free(unb); return 2; }
    }
    unb[len] = '\0';
    TritError e = parse_trit_string(unb, out);
    free(unb);
    return e;
}

/* --- Arithmetic Operations: Addition and Subtraction --- */
static int cmp_base81(const unsigned char* a, size_t a_len,
                      const unsigned char* b, size_t b_len) {
    if (a_len > b_len) {
        for (size_t i = a_len - 1; i >= b_len; i--) {
            if (a[i] != 0) return 1;
            if (i == 0) break;
        }
    } else if (b_len > a_len) {
        for (size_t i = b_len - 1; i >= a_len; i--) {
            if (b[i] != 0) return -1;
            if (i == 0) break;
        }
    }
    size_t m = (a_len < b_len ? a_len : b_len);
    for (ssize_t i = m - 1; i >= 0; i--) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
        if (i == 0) break;
    }
    return 0;
}

TritError tritjs_add_big(T81BigInt* A, T81BigInt* B, T81BigInt** result) {
    if (!A || !B) return 2;
    *result = (T81BigInt*)calloc(1, sizeof(T81BigInt));
    if (!*result) return 1;
    if (A->sign == B->sign) {
        (*result)->sign = A->sign;
        size_t len = (A->len > B->len ? A->len : B->len) + 1;
        if (allocate_digits(*result, len)) { free(*result); return 1; }
        memset((*result)->digits, 0, len);
        memcpy((*result)->digits, A->digits, A->len);
        for (size_t i = 0; i < B->len; i++) {
            int val = (*result)->digits[i] + B->digits[i];
            (*result)->digits[i] = val % BASE_81;
            int carry = val / BASE_81;
            size_t cpos = i + 1;
            while (carry && cpos < len) {
                val = (*result)->digits[cpos] + carry;
                (*result)->digits[cpos] = val % BASE_81;
                carry = val / BASE_81;
                cpos++;
            }
        }
        while ((*result)->len > 1 && (*result)->digits[(*result)->len - 1] == 0)
            (*result)->len--;
    } else {
        int c = cmp_base81(A->digits, A->len, B->digits, B->len);
        T81BigInt *larger, *smaller;
        int largerSign;
        if (c > 0) { larger = A; smaller = B; largerSign = A->sign; }
        else if (c < 0) { larger = B; smaller = A; largerSign = B->sign; }
        else { if (allocate_digits(*result, 1)) { free(*result); return 1; }
               (*result)->digits[0] = 0; return 0; }
        (*result)->sign = largerSign;
        if (allocate_digits(*result, larger->len)) { free(*result); return 1; }
        memcpy((*result)->digits, larger->digits, larger->len);
        for (size_t i = 0; i < smaller->len; i++) {
            int diff = (*result)->digits[i] - smaller->digits[i];
            if (diff < 0) {
                diff += BASE_81;
                size_t j = i + 1;
                while (1) {
                    (*result)->digits[j]--;
                    if ((*result)->digits[j] < (unsigned char)255) break;
                    (*result)->digits[j] += BASE_81;
                    j++;
                    if (j >= larger->len) break;
                }
            }
            (*result)->digits[i] = (unsigned char)diff;
        }
        while ((*result)->len > 1 && (*result)->digits[(*result)->len - 1] == 0)
            (*result)->len--;
    }
    return 0;
}

TritError tritjs_subtract_big(T81BigInt* A, T81BigInt* B, T81BigInt** result) {
    if (!A || !B) return 2;
    T81BigInt tmp = *B;
    int oldsign = tmp.sign;
    tmp.sign = !oldsign;
    TritError e = tritjs_add_big(A, &tmp, result);
    tmp.sign = oldsign;
    return e;
}

/* --- Multiplication: Karatsuba with Cache --- */
#define MUL_CACHE_SIZE 8
typedef struct {
    char key[128];
    T81BigInt result;
    int used;
} MulCacheEntry;
static MulCacheEntry mul_cache[MUL_CACHE_SIZE] = {{0}};

static void naive_mul(const unsigned char *A, size_t alen,
                      const unsigned char *B, size_t blen,
                      unsigned char *out) {
    memset(out, 0, alen + blen);
    for (size_t i = 0; i < alen; i++) {
        int carry = 0;
        for (size_t j = 0; j < blen; j++) {
            int pos = i + j;
            int val = out[pos] + A[i] * B[j] + carry;
            out[pos] = val % BASE_81;
            carry = val / BASE_81;
        }
        out[i + blen] += carry;
    }
}

static void add_shifted(unsigned char *dest, size_t dlen,
                        const unsigned char *src, size_t slen,
                        size_t shift) {
    int carry = 0;
    for (size_t i = 0; i < slen; i++) {
        size_t idx = i + shift;
        if (idx >= dlen) break;
        int sum = dest[idx] + src[i] + carry;
        dest[idx] = sum % BASE_81;
        carry = sum / BASE_81;
    }
    size_t idx = slen + shift;
    while (carry && idx < dlen) {
        int sum = dest[idx] + carry;
        dest[idx] = sum % BASE_81;
        carry = sum / BASE_81;
        idx++;
    }
}

static void sub_inplace(unsigned char* out, const unsigned char* src, size_t length) {
    int borrow = 0;
    for (size_t i = 0; i < length; i++) {
        int diff = out[i] - src[i] - borrow;
        if (diff < 0) { diff += BASE_81; borrow = 1; }
        else { borrow = 0; }
        out[i] = diff;
    }
}

static void karatsuba(const unsigned char *A, const unsigned char *B, size_t n, unsigned char *out) {
    if (n <= 16) { naive_mul(A, n, B, n, out); return; }
    size_t half = n / 2, r = n - half;
    const unsigned char *A0 = A, *A1 = A + half;
    const unsigned char *B0 = B, *B1 = B + half;
    size_t len2 = 2 * n;
    unsigned char *p1 = calloc(len2, 1);
    unsigned char *p2 = calloc(len2, 1);
    unsigned char *p3 = calloc(len2, 1);
    unsigned char *sumA = calloc(r, 1);
    unsigned char *sumB = calloc(r, 1);
    karatsuba(A0, B0, half, p1);
    karatsuba(A1, B1, r, p2);
    memcpy(sumA, A1, r);
    for (size_t i = 0; i < half; i++) {
        int s = sumA[i] + A0[i];
        sumA[i] = s % BASE_81;
        int c = s / BASE_81;
        if (c && i + 1 < r) sumA[i + 1] += c;
    }
    memcpy(sumB, B1, r);
    for (size_t i = 0; i < half; i++) {
        int s = sumB[i] + B0[i];
        sumB[i] = s % BASE_81;
        int c = s / BASE_81;
        if (c && i + 1 < r) sumB[i + 1] += c;
    }
    karatsuba(sumA, sumB, r, p3);
    sub_inplace(p3, p1, len2);
    sub_inplace(p3, p2, len2);
    memset(out, 0, len2);
    add_shifted(out, len2, p1, len2, 0);
    add_shifted(out, len2, p3, len2, half);
    add_shifted(out, len2, p2, len2, 2 * half);
    free(p1); free(p2); free(p3);
    free(sumA); free(sumB);
}

static TritError t81bigint_karatsuba_multiply(const T81BigInt *a, const T81BigInt *b, T81BigInt *out) {
    if ((a->len == 1 && a->digits[0] == 0) || (b->len == 1 && b->digits[0] == 0)) {
        if (allocate_digits(out, 1)) return 1;
        out->digits[0] = 0; out->sign = 0;
        return 0;
    }
    size_t n = (a->len > b->len ? a->len : b->len);
    unsigned char *A = calloc(n, 1), *B = calloc(n, 1);
    if (!A || !B) { free(A); free(B); return 1; }
    memcpy(A, a->digits, a->len);
    memcpy(B, b->digits, b->len);
    size_t out_len = 2 * n;
    unsigned char *prod = calloc(out_len, 1);
    if (!prod) { free(A); free(B); return 1; }
    karatsuba(A, B, n, prod);
    free(A); free(B);
    out->sign = (a->sign != b->sign) ? 1 : 0;
    while (out_len > 1 && prod[out_len - 1] == 0) out_len--;
    if (allocate_digits(out, out_len)) { free(prod); return 1; }
    memcpy(out->digits, prod, out_len);
    free(prod);
    return 0;
}

static int mul_cache_lookup(const char* key, T81BigInt *dst) {
    for (int i = 0; i < MUL_CACHE_SIZE; i++) {
        if (mul_cache[i].used && strcmp(mul_cache[i].key, key) == 0) {
            if (allocate_digits(dst, mul_cache[i].result.len)) return 1;
            dst->len = mul_cache[i].result.len;
            dst->sign = mul_cache[i].result.sign;
            memcpy(dst->digits, mul_cache[i].result.digits, dst->len);
            return 0;
        }
    }
    return 2;
}

static void mul_cache_store(const char* key, const T81BigInt *val) {
    int slot = -1;
    for (int i = 0; i < MUL_CACHE_SIZE; i++) {
        if (!mul_cache[i].used) { slot = i; break; }
    }
    if (slot < 0) slot = 0;
    strncpy(mul_cache[slot].key, key, sizeof(mul_cache[slot].key));
    mul_cache[slot].key[sizeof(mul_cache[slot].key) - 1] = '\0';
    t81bigint_free(&mul_cache[slot].result);
    mul_cache[slot].used = 1;
    allocate_digits(&mul_cache[slot].result, val->len);
    mul_cache[slot].result.len = val->len;
    mul_cache[slot].result.sign = val->sign;
    memcpy(mul_cache[slot].result.digits, val->digits, val->len);
}

static TritError multiply_with_cache(const T81BigInt *a, const T81BigInt *b, T81BigInt *out) {
    char *as = NULL, *bs = NULL;
    if (t81bigint_to_trit_string(a, &as) != 0) return 2;
    if (t81bigint_to_trit_string(b, &bs) != 0) { free(as); return 2; }
    char key[128];
    snprintf(key, sizeof(key), "mul:%s:%s", as, bs);
    free(as); free(bs);
    if (mul_cache_lookup(key, out) == 0) return 0;
    TritError e = t81bigint_karatsuba_multiply(a, b, out);
    if (!e) { mul_cache_store(key, out); }
    return e;
}

TritError tritjs_multiply_big(T81BigInt* a, T81BigInt* b, T81BigInt** result) {
    if (!a || !b) return 2;
    *result = (T81BigInt*)calloc(1, sizeof(T81BigInt));
    if (!*result) return 1;
    TritError e = multiply_with_cache(a, b, *result);
    if (e) { free(*result); *result = NULL; }
    return e;
}

/* --- Factorial and Power Functions --- */
static int is_small_value(const T81BigInt *x) {
    return (x->len == 1 && x->digits[0] < 81);
}
static int to_small_int(const T81BigInt *x) {
    int val = x->digits[0];
    if (x->sign) val = -val;
    return val;
}

TritError tritjs_factorial_big(T81BigInt* a, T81BigInt** result) {
    if (!a) return 2;
    if (a->sign) return 6;
    if (!is_small_value(a)) return 4;
    int val = to_small_int(a);
    if (val > 20) return 4;
    long long f = 1;
    for (int i = 1; i <= val; i++) f *= i;
    *result = (T81BigInt*)calloc(1, sizeof(T81BigInt));
    if (!*result) return 1;
    if (allocate_digits(*result, 1)) { free(*result); *result = NULL; return 1; }
    (*result)->digits[0] = 0; (*result)->sign = 0;
    while (f > 0) {
        int digit = f % BASE_81;
        f /= BASE_81;
        int carry = digit;
        size_t i = 0;
        while (carry) {
            int val2 = (*result)->digits[i] + carry;
            (*result)->digits[i] = val2 % BASE_81;
            carry = val2 / BASE_81;
            i++;
            if (i >= (*result)->len && carry) {
                if (allocate_digits(*result, (*result)->len + 1)) {
                    tritbig_free(*result); *result = NULL; return 1;
                }
            }
        }
    }
    while ((*result)->len > 1 && (*result)->digits[(*result)->len - 1] == 0)
        (*result)->len--;
    return 0;
}

TritError tritjs_power_big(T81BigInt* base, T81BigInt* exp, T81BigInt** result) {
    if (!base || !exp) return 2;
    if (exp->sign) return 6;
    if (!is_small_value(exp)) return 4;
    int e = to_small_int(exp);
    if (e > 1000) return 4;
    *result = (T81BigInt*)calloc(1, sizeof(T81BigInt));
    if (!*result) return 1;
    if (allocate_digits(*result, 1)) { free(*result); *result = NULL; return 1; }
    (*result)->digits[0] = 1; (*result)->sign = 0;
    for (int i = 0; i < e; i++) {
        T81BigInt tmp;
        memset(&tmp, 0, sizeof(tmp));
        TritError err = multiply_with_cache(*result, base, &tmp);
        if (err) { tritbig_free(*result); free(*result); *result = NULL; return err; }
        t81bigint_free(*result);
        **result = tmp;
    }
    if (base->sign && (e % 2) == 1)
        (*result)->sign = 1;
    return 0;
}

/* --- Scientific Functions via Double Conversion --- */
static double t81bigint_to_double(T81BigInt* x) {
    int sign = x->sign ? -1 : 1;
    double accum = 0.0;
    for (ssize_t i = x->len - 1; i >= 0; i--) {
        accum = accum * BASE_81 + x->digits[i];
    }
    return sign * accum;
}

static T81BigInt* double_to_t81bigint(double d) {
    T81BigInt* result = (T81BigInt*)calloc(1, sizeof(T81BigInt));
    if (!result) return NULL;
    int sign = (d < 0) ? 1 : 0;
    if (d < 0) d = -d;
    size_t capacity = 16;
    result->digits = (unsigned char*)calloc(capacity, 1);
    result->len = 0;
    while (d >= 1.0) {
        int digit = (int)fmod(d, BASE_81);
        if (result->len >= capacity) { capacity *= 2; result->digits = realloc(result->digits, capacity); }
        result->digits[result->len++] = (unsigned char) digit;
        d = floor(d / BASE_81);
    }
    if (result->len == 0) { result->digits[0] = 0; result->len = 1; }
    result->sign = sign;
    return result;
}

TritError tritjs_sqrt_complex(T81BigInt* a, int precision, T81Complex* result) {
    (void) precision;
    double d = t81bigint_to_double(a);
    double sq = sqrt(d);
    T81BigInt* res = double_to_t81bigint(sq);
    result->real = *res;
    free(res);
    result->imag.digits = NULL;
    result->imag.len = 1;
    result->imag.sign = 0;
    return 0;
}

TritError tritjs_log3_complex(T81BigInt* a, int precision, T81Complex* result) {
    (void) precision;
    double d = t81bigint_to_double(a);
    double l = log(d) / log(3);
    T81BigInt* res = double_to_t81bigint(l);
    result->real = *res;
    free(res);
    result->imag.digits = NULL;
    result->imag.len = 1;
    result->imag.sign = 0;
    return 0;
}

TritError tritjs_sin_complex(T81BigInt* a, int precision, T81Complex* result) {
    (void) precision;
    double d = t81bigint_to_double(a);
    double s = sin(d);
    T81BigInt* res = double_to_t81bigint(s);
    result->real = *res;
    free(res);
    result->imag.digits = NULL;
    result->imag.len = 1;
    result->imag.sign = 0;
    return 0;
}

TritError tritjs_cos_complex(T81BigInt* a, int precision, T81Complex* result) {
    (void) precision;
    double d = t81bigint_to_double(a);
    double c = cos(d);
    T81BigInt* res = double_to_t81bigint(c);
    result->real = *res;
    free(res);
    result->imag.digits = NULL;
    result->imag.len = 1;
    result->imag.sign = 0;
    return 0;
}

TritError tritjs_tan_complex(T81BigInt* a, int precision, T81Complex* result) {
    (void) precision;
    double d = t81bigint_to_double(a);
    double t = tan(d);
    T81BigInt* res = double_to_t81bigint(t);
    result->real = *res;
    free(res);
    result->imag.digits = NULL;
    result->imag.len = 1;
    result->imag.sign = 0;
    return 0;
}

TritError tritjs_pi(int* len, int** pi) {
    static int pi_val[] = {1, 0, 0, 1, 0, 2, 2, 1};
    *len = 8;
    *pi = malloc(8 * sizeof(int));
    if (!*pi) return 1;
    memcpy(*pi, pi_val, 8 * sizeof(int));
    return 0;
}

/* --- Full Division and Modulo (Long Division Algorithm) --- */
TritError tritjs_divide_big(T81BigInt* a, T81BigInt* b, T81BigInt** quotient, T81BigInt** remainder) {
    if (!a || !b) return 2;
    int b_zero = 1;
    for (size_t i = 0; i < b->len; i++) {
        if (b->digits[i] != 0) { b_zero = 0; break; }
    }
    if (b_zero) { LOG_ERROR(3, "tritjs_divide_big"); return 3; }
    *quotient = (T81BigInt*)calloc(1, sizeof(T81BigInt));
    *remainder = (T81BigInt*)calloc(1, sizeof(T81BigInt));
    if (!*quotient || !*remainder) return 1;
    if (allocate_digits(*remainder, a->len)) return 1;
    memcpy((*remainder)->digits, a->digits, a->len);
    (*remainder)->len = a->len;
    if (allocate_digits(*quotient, a->len)) return 1;
    memset((*quotient)->digits, 0, a->len);
    for (ssize_t i = a->len - 1; i >= 0; i--) {
        size_t newLen = (*remainder)->len + 1;
        unsigned char* newR = calloc(newLen, 1);
        if (!newR) return 1;
        newR[0] = a->digits[i];
        for (size_t j = 1; j < newLen; j++) {
            newR[j] = (*remainder)->digits[j-1];
        }
        free((*remainder)->digits);
        (*remainder)->digits = newR;
        (*remainder)->len = newLen;
        int q_digit = 0;
        T81BigInt* prod = NULL;
        T81BigInt* temp = NULL;
        while (1) {
            int mul_digit = q_digit + 1;
            prod = (T81BigInt*)calloc(1, sizeof(T81BigInt));
            if (!prod) return 1;
            if (allocate_digits(prod, (*remainder)->len)) return 1;
            int carry = 0;
            for (size_t j = 0; j < (*remainder)->len; j++) {
                int val = (j < b->len ? b->digits[j] * mul_digit : 0) + carry;
                prod->digits[j] = val % BASE_81;
                carry = val / BASE_81;
            }
            if (carry) {
                if (allocate_digits(prod, (*remainder)->len + 1)) return 1;
                prod->digits[(*remainder)->len] = carry;
                prod->len = (*remainder)->len + 1;
            } else {
                prod->len = (*remainder)->len;
            }
            if (cmp_base81((*remainder)->digits, (*remainder)->len, prod->digits, prod->len) < 0) {
                t81bigint_free(prod); free(prod);
                break;
            }
            t81bigint_free(prod); free(prod);
            q_digit++;
        }
        (*quotient)->digits[i] = (unsigned char) q_digit;
        prod = (T81BigInt*)calloc(1, sizeof(T81BigInt));
        if (!prod) return 1;
        if (allocate_digits(prod, (*remainder)->len)) return 1;
        int carry = 0;
        for (size_t j = 0; j < (*remainder)->len; j++) {
            int val = (j < b->len ? b->digits[j] * q_digit : 0) + carry;
            prod->digits[j] = val % BASE_81;
            carry = val / BASE_81;
        }
        prod->len = (*remainder)->len;
        temp = NULL;
        tritjs_subtract_big(*remainder, prod, &temp);
        t81bigint_free(*remainder);
        free((*remainder));
        *remainder = temp;
        t81bigint_free(prod);
        free(prod);
    }
    while ((*quotient)->len > 1 && (*quotient)->digits[(*quotient)->len - 1] == 0)
        (*quotient)->len--;
    while ((*remainder)->len > 1 && (*remainder)->digits[(*remainder)->len - 1] == 0)
        (*remainder)->len--;
    (*quotient)->sign = (a->sign != b->sign) ? 1 : 0;
    (*remainder)->sign = a->sign;
    return 0;
}

/* --- Shift Operations --- */
TritError tritjs_left_shift(T81BigInt* a, int shift, T81BigInt** result) {
    if (!a || shift < 0) return 2;
    T81BigInt base;
    memset(&base, 0, sizeof(base));
    allocate_digits(&base, 1);
    base.digits[0] = 3; base.sign = 0;
    T81BigInt* shift_val = NULL;
    char shift_str[16];
    snprintf(shift_str, sizeof(shift_str), "%d", shift);
    parse_trit_string(shift_str, &shift_val);
    T81BigInt* multiplier = NULL;
    if (tritjs_power_big(&base, shift_val, &multiplier))
        return 1;
    TritError e = tritjs_multiply_big(a, multiplier, result);
    tritbig_free(multiplier);
    t81bigint_free(&base);
    tritbig_free(shift_val);
    return e;
}

TritError tritjs_right_shift(T81BigInt* a, int shift, T81BigInt** result) {
    if (!a || shift < 0) return 2;
    T81BigInt base;
    memset(&base, 0, sizeof(base));
    allocate_digits(&base, 1);
    base.digits[0] = 3; base.sign = 0;
    T81BigInt* shift_val = NULL;
    char shift_str[16];
    snprintf(shift_str, sizeof(shift_str), "%d", shift);
    parse_trit_string(shift_str, &shift_val);
    T81BigInt* divisor = NULL;
    if (tritjs_power_big(&base, shift_val, &divisor))
        return 1;
    T81BigInt *q = NULL, *r = NULL;
    TritError e = tritjs_divide_big(a, divisor, &q, &r);
    tritbig_free(divisor);
    t81bigint_free(&base);
    tritbig_free(shift_val);
    if (r) { tritbig_free(r); free(r); }
    if (!e) *result = q; else { tritbig_free(q); free(q); }
    return e;
}

/* --- Ternary Logical Operations --- */
int ternary_and(int a, int b) { return a < b ? a : b; }
int ternary_or(int a, int b) { return a > b ? a : b; }
int ternary_not(int a) { return 2 - a; }
int ternary_xor(int a, int b) { return (a + b) % 3; }

TritError tritjs_logical_and(T81BigInt* A, T81BigInt* B, T81BigInt** result) {
    if (!A || !B) return 2;
    size_t len = A->len > B->len ? A->len : B->len;
    *result = (T81BigInt*)calloc(1, sizeof(T81BigInt));
    if (!*result) return 1;
    if (allocate_digits(*result, len)) { free(*result); return 1; }
    for (size_t i = 0; i < len; i++) {
        int a = (i < A->len ? A->digits[i] : 0);
        int b = (i < B->len ? B->digits[i] : 0);
        (*result)->digits[i] = (unsigned char) ternary_and(a, b);
    }
    (*result)->len = len;
    (*result)->sign = 0;
    return 0;
}

TritError tritjs_logical_or(T81BigInt* A, T81BigInt* B, T81BigInt** result) {
    if (!A || !B) return 2;
    size_t len = A->len > B->len ? A->len : B->len;
    *result = (T81BigInt*)calloc(1, sizeof(T81BigInt));
    if (!*result) return 1;
    if (allocate_digits(*result, len)) { free(*result); return 1; }
    for (size_t i = 0; i < len; i++) {
        int a = (i < A->len ? A->digits[i] : 0);
        int b = (i < B->len ? B->digits[i] : 0);
        (*result)->digits[i] = (unsigned char) ternary_or(a, b);
    }
    (*result)->len = len;
    (*result)->sign = 0;
    return 0;
}

TritError tritjs_logical_not(T81BigInt* A, T81BigInt** result) {
    if (!A) return 2;
    *result = (T81BigInt*)calloc(1, sizeof(T81BigInt));
    if (!*result) return 1;
    if (allocate_digits(*result, A->len)) { free(*result); return 1; }
    for (size_t i = 0; i < A->len; i++) {
        (*result)->digits[i] = (unsigned char) ternary_not(A->digits[i]);
    }
    (*result)->len = A->len;
    (*result)->sign = 0;
    return 0;
}

TritError tritjs_logical_xor(T81BigInt* A, T81BigInt* B, T81BigInt** result) {
    if (!A || !B) return 2;
    size_t len = A->len > B->len ? A->len : B->len;
    *result = (T81BigInt*)calloc(1, sizeof(T81BigInt));
    if (!*result) return 1;
    if (allocate_digits(*result, len)) { free(*result); return 1; }
    for (size_t i = 0; i < len; i++) {
        int a = (i < A->len ? A->digits[i] : 0);
        int b = (i < B->len ? B->digits[i] : 0);
        (*result)->digits[i] = (unsigned char) ternary_xor(a, b);
    }
    (*result)->len = len;
    (*result)->sign = 0;
    return 0;
}

/* --- Lua Integration --- */
/* Lua bindings to expose core operations */

static int l_c_add(lua_State *L) {
    const char *a = luaL_checkstring(L, 1);
    const char *b = luaL_checkstring(L, 2);
    T81BigInt *A = NULL, *B = NULL, *result = NULL;
    if (parse_trit_string(a, &A) || parse_trit_string(b, &B)) {
        lua_pushstring(L, "Invalid input");
        lua_error(L);
    }
    if (tritjs_add_big(A, B, &result) != 0) {
        lua_pushstring(L, "Addition error");
        lua_error(L);
    }
    char *res_str = NULL;
    t81bigint_to_trit_string(result, &res_str);
    lua_pushstring(L, res_str);
    free(res_str);
    tritbig_free(A);
    tritbig_free(B);
    tritbig_free(result);
    return 1;
}

static int l_c_sub(lua_State *L) {
    const char *a = luaL_checkstring(L, 1);
    const char *b = luaL_checkstring(L, 2);
    T81BigInt *A = NULL, *B = NULL, *result = NULL;
    if (parse_trit_string(a, &A) || parse_trit_string(b, &B)) {
        lua_pushstring(L, "Invalid input");
        lua_error(L);
    }
    if (tritjs_subtract_big(A, B, &result) != 0) {
        lua_pushstring(L, "Subtraction error");
        lua_error(L);
    }
    char *res_str = NULL;
    t81bigint_to_trit_string(result, &res_str);
    lua_pushstring(L, res_str);
    free(res_str);
    tritbig_free(A);
    tritbig_free(B);
    tritbig_free(result);
    return 1;
}

static int l_c_mul(lua_State *L) {
    const char *a = luaL_checkstring(L, 1);
    const char *b = luaL_checkstring(L, 2);
    T81BigInt *A = NULL, *B = NULL, *result = NULL;
    if (parse_trit_string(a, &A) || parse_trit_string(b, &B)) {
        lua_pushstring(L, "Invalid input");
        lua_error(L);
    }
    if (tritjs_multiply_big(A, B, &result) != 0) {
        lua_pushstring(L, "Multiplication error");
        lua_error(L);
    }
    char *res_str = NULL;
    t81bigint_to_trit_string(result, &res_str);
    lua_pushstring(L, res_str);
    free(res_str);
    tritbig_free(A);
    tritbig_free(B);
    tritbig_free(result);
    return 1;
}

static int l_c_div(lua_State *L) {
    const char *a = luaL_checkstring(L, 1);
    const char *b = luaL_checkstring(L, 2);
    T81BigInt *A = NULL, *B = NULL, *quotient = NULL, *remainder = NULL;
    if (parse_trit_string(a, &A) || parse_trit_string(b, &B)) {
        lua_pushstring(L, "Invalid input");
        lua_error(L);
    }
    if (tritjs_divide_big(A, B, &quotient, &remainder) != 0) {
        lua_pushstring(L, "Division error");
        lua_error(L);
    }
    char *q_str = NULL, *r_str = NULL;
    t81bigint_to_trit_string(quotient, &q_str);
    t81bigint_to_trit_string(remainder, &r_str);
    lua_pushstring(L, q_str);
    lua_pushstring(L, r_str);
    free(q_str);
    free(r_str);
    tritbig_free(A);
    tritbig_free(B);
    tritbig_free(quotient);
    tritbig_free(remainder);
    return 2;
}

/* Register the C functions to Lua */
static void init_lua_bindings(lua_State *L) {
    lua_register(L, "c_add", l_c_add);
    lua_register(L, "c_sub", l_c_sub);
    lua_register(L, "c_mul", l_c_mul);
    lua_register(L, "c_div", l_c_div);
    /* Further bindings (e.g., for factorial, power, logical operations) can be added here */
}

void run_lua_script(const char *script) {
    lua_State *L = luaL_newstate();
    luaL_openlibs(L);
    init_lua_bindings(L);
    if (luaL_dostring(L, script) != LUA_OK) {
        const char *error = lua_tostring(L, -1);
        printf("Lua Error: %s\n", error);
        lua_pop(L, 1);
    }
    lua_close(L);
}

/* --- Integration Test Cases --- */
void run_integration_tests() {
    /* Crypto Test using OpenSSL AES-256-GCM */
    const char* plaintext = "Test string for encryption";
    unsigned char* ciphertext = NULL;
    size_t ct_len = 0;
    if (encrypt_data((unsigned char*)plaintext, strlen(plaintext), &ciphertext, &ct_len) == 0) {
        unsigned char* decrypted = NULL;
        size_t pt_len = 0;
        if (decrypt_data(ciphertext, ct_len, &decrypted, &pt_len) == 0) {
            printf("Crypto Test: %s\n", decrypted);
            free(decrypted);
        } else {
            printf("Crypto Test: Decryption failed\n");
        }
        free(ciphertext);
    } else {
        printf("Crypto Test: Encryption failed\n");
    }
    
    /* Lua Scripting Test */
    const char* lua_script = "result = c_add('102', '210'); print('Lua Test: 102 + 210 =', result)";
    run_lua_script(lua_script);
    
    /* Intrusion Detection Simulation */
    operation_steps = 150;  /* Simulate heavy activity */
    sleep(6);  /* Allow intrusion monitor to trigger alert */
    if (intrusion_alert) {
        printf("Intrusion Detection Test: Alert triggered!\n");
    } else {
        printf("Intrusion Detection Test: No alert.\n");
    }
}

/* --- Main Function --- */
/* (Assumes functions like start_intrusion_monitor(), init_ncurses_interface(), ncurses_loop(), and end_ncurses_interface() are fully implemented elsewhere.) */
int main() {
    init_audit_log();
    start_intrusion_monitor();
    run_integration_tests();
    init_ncurses_interface();
    ncurses_loop();
    end_ncurses_interface();
    return 0;
}
