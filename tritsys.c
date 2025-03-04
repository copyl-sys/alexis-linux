/*
 * TritSys: Unified Ternary Computing System
 *
 * This program integrates the Axion kernel module and the TritJS-CISA-Optimized
 * utility into a robust ternary computing framework. It supports:
 *   - Pure ternary arithmetic using T81BigInt.
 *   - An Axion kernel module with AI-driven load balancing and just-in-time execution.
 *   - Extended matrix operations (addition, multiplication, and transposition) on T81BigInt elements.
 *   - Additional helper routines for deep-copying and multiplying T81BigInt values.
 *
 * Usage:
 *   - Kernel mode: Compile with __KERNEL__ defined (e.g., `gcc -D__KERNEL__ TritSys.c -o axion.o`).
 *   - User-space: Compile and run normally (e.g., `gcc TritSys.c -o tritsys -lncurses`).
 */

/* ============================================================
 * Section 1: Shared Header (ternary_common.h)
 * This section defines common macros, constants, data types, and function
 * prototypes used across the system.
 */

#ifndef TERNARY_COMMON_H
#define TERNARY_COMMON_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/wait.h>
/* Kernel-space memory allocation and logging */
#define TS_MALLOC(sz) kmalloc((sz), GFP_KERNEL)
#define TS_FREE(ptr) kfree(ptr)
#define TS_LOG(lvl, fmt, ...) do { if (log_level >= lvl) printk(KERN_INFO "[%s] " fmt, log_names[lvl], ##__VA_ARGS__); } while (0)
#else
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
/* User-space memory allocation and logging */
#define TS_MALLOC(sz) malloc(sz)
#define TS_FREE(ptr) free(ptr)
#define TS_LOG(lvl, fmt, ...) do { if (log_level >= lvl) fprintf(stderr, "[%s] " fmt, log_names[lvl], ##__VA_ARGS__); } while (0)
#endif

/* Ternary sign definitions */
#define TERNARY_NEGATIVE -1
#define TERNARY_ZERO      0
#define TERNARY_POSITIVE  1
#define BASE_81 81

/* Logging levels */
enum LogLevel { LOG_DEBUG = 0, LOG_INFO, LOG_WARN, LOG_ERROR };
static const char *log_names[] = {"DEBUG", "INFO", "WARN", "ERROR"};
extern int log_level;

/* Opcode definitions */
#define TADD 0x01
#define TMUL 0x03
#define TMAT_ADD 0x08
#define TMAT_MUL 0x09
#define THANOI   0x0A

/* Error codes */
typedef enum {
    TERNARY_NO_ERROR = 0,
    TERNARY_ERR_MEMALLOC,
    TERNARY_ERR_INVALID_INPUT,
    TERNARY_ERR_DIVZERO
} TernaryError;

/*
 * T81BigInt:
 *   - sign:   The sign of the number (-1, 0, or 1).
 *   - digits: Pointer to an array holding the balanced ternary digits.
 *   - len:    Number of digits allocated.
 *   - is_mapped: Flag indicating if the memory was allocated via mapping.
 *   - fd:     File descriptor used if memory is mapped.
 */
typedef struct {
    int sign;
    unsigned char *digits;
    size_t len;
    int is_mapped;
    int fd;
} T81BigInt;

/*
 * T81Matrix:
 *   - rows, cols: Dimensions of the matrix.
 *   - data:       Array of T81BigInt elements in row-major order.
 */
typedef struct {
    int rows;
    int cols;
    T81BigInt *data;
} T81Matrix;

/* Declare implemented T81BigInt functions */
TernaryError allocate_t81bigint(T81BigInt *x, size_t len);
void free_t81bigint(T81BigInt *x);

#endif /* TERNARY_COMMON_H */


/* ============================================================
 * Section 2: Axion Kernel Module
 * Implements the Axion kernel module. This module is compiled only when __KERNEL__
 * is defined. It provides communication with the TritJS utility via a shared buffer.
 */

#ifdef __KERNEL__
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>
#include <linux/device.h>
#include <linux/kthread.h>
#include <linux/mm.h>
#include "ternary_common.h"

#define DEVICE_NAME "axion"
#define SHARED_BUFFER_SIZE 4096
#define T81_MMAP_THRESHOLD (500 * 1024)

int log_level = LOG_INFO;  /* Global log level for kernel logging */

/*
 * Structure for TritJS calls. Holds operands (both scalar and matrix)
 * and a union for returning the result.
 */
struct tritjs_call {
    int op;
    T81BigInt in1;
    T81BigInt in2;
    T81Matrix mat_in1;
    T81Matrix mat_in2;
    union {
        T81BigInt scalar;
        T81Matrix matrix;
    } result;
};

/*
 * axion_state: Tracks module state including the shared buffer and wait queue.
 */
struct axion_state {
    void *shared_buffer;
    wait_queue_head_t tritjs_wait;
    volatile int request_pending;
};

#define AXION_CALL_TRITJS _IOWR('a', 1, struct tritjs_call)

static dev_t dev_num;
static struct cdev axion_cdev;
static struct class *axion_class;
static struct device *axion_device;
static struct axion_state state = { .request_pending = 0 };

/*
 * allocate_t81bigint:
 * Allocates memory for a T81BigInt. Uses kmalloc for small sizes; otherwise,
 * it uses memory mapping.
 */
TernaryError allocate_t81bigint(T81BigInt *x, size_t len) {
    size_t bytes = len ? len : 1;
    x->len = len;
    x->is_mapped = 0;
    x->fd = -1;
    if (bytes < T81_MMAP_THRESHOLD) {
        x->digits = kmalloc(bytes, GFP_KERNEL);
        if (!x->digits) {
            TS_LOG(LOG_ERROR, "Memory allocation failed\n");
            return TERNARY_ERR_MEMALLOC;
        }
        memset(x->digits, 0, bytes);
    } else {
        /* Use memory mapping for large allocations */
        struct file *file = shmem_file_setup("axion_t81", bytes, 0);
        if (IS_ERR(file))
            return TERNARY_ERR_MEMALLOC;
        x->fd = get_unused_fd_flags(O_RDWR);
        if (x->fd < 0) {
            fput(file);
            return TERNARY_ERR_MEMALLOC;
        }
        fd_install(x->fd, file);
        x->digits = vm_map_ram(NULL, bytes / PAGE_SIZE + 1, 0, PAGE_KERNEL);
        if (!x->digits) {
            close(x->fd);
            return TERNARY_ERR_MEMALLOC;
        }
        x->is_mapped = 1;
        memset(x->digits, 0, bytes);
    }
    return TERNARY_NO_ERROR;
}

/*
 * free_t81bigint:
 * Frees memory allocated for a T81BigInt. Accounts for both kmalloc and mapped memory.
 */
void free_t81bigint(T81BigInt *x) {
    if (!x || !x->digits)
        return;
    if (x->is_mapped) {
        vm_unmap_ram(x->digits, x->len / PAGE_SIZE + 1);
        close(x->fd);
    } else {
        kfree(x->digits);
    }
}

/*
 * call_tritjs:
 * Copies the TritJS call structure to the shared buffer, waits for a response,
 * then copies the result back. Returns 0 on success.
 */
static int call_tritjs(struct tritjs_call *call) {
    if (!state.shared_buffer)
        return -EINVAL;
    state.request_pending = 1;
    memcpy(state.shared_buffer, call, sizeof(*call));
    TS_LOG(LOG_DEBUG, "Waiting for TritJS response\n");
    if (wait_event_interruptible(state.tritjs_wait, !state.request_pending))
        return -ERESTARTSYS;
    memcpy(call, state.shared_buffer, sizeof(*call));
    return 0;
}

/*
 * axion_ioctl:
 * Implements the IOCTL interface. Receives TritJS call structures from user space,
 * processes them, and returns results.
 */
static long axion_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    if (cmd == AXION_CALL_TRITJS) {
        struct tritjs_call call;
        if (copy_from_user(&call, (void __user *)arg, sizeof(call)))
            return -EFAULT;
        if (call_tritjs(&call))
            return -EINVAL;
        if (copy_to_user((void __user *)arg, &call, sizeof(call)))
            return -EFAULT;
        return 0;
    }
    return -EINVAL;
}

/* File operations for the Axion device */
static const struct file_operations axion_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = axion_ioctl
};

/*
 * axion_init:
 * Initializes the Axion kernel module by registering the device, creating a
 * shared memory buffer, and initializing synchronization primitives.
 */
static int __init axion_init(void) {
    int ret = alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME);
    if (ret < 0)
        return ret;
    cdev_init(&axion_cdev, &axion_fops);
    if (cdev_add(&axion_cdev, dev_num, 1) < 0)
        goto err_dev;
    axion_class = class_create(THIS_MODULE, DEVICE_NAME);
    if (IS_ERR(axion_class)) {
        ret = PTR_ERR(axion_class);
        goto err_cdev;
    }
    axion_device = device_create(axion_class, NULL, dev_num, NULL, DEVICE_NAME);
    if (IS_ERR(axion_device)) {
        ret = PTR_ERR(axion_device);
        goto err_class;
    }
    state.shared_buffer = vmalloc(SHARED_BUFFER_SIZE);
    if (!state.shared_buffer) {
        ret = -ENOMEM;
        goto err_device;
    }
    init_waitqueue_head(&state.tritjs_wait);
    TS_LOG(LOG_INFO, "Axion initialized\n");
    return 0;
err_device:
    device_destroy(axion_class, dev_num);
err_class:
    class_destroy(axion_class);
err_cdev:
    cdev_del(&axion_cdev);
err_dev:
    unregister_chrdev_region(dev_num, 1);
    return ret;
}

/*
 * axion_exit:
 * Cleans up all resources allocated by the Axion kernel module.
 */
static void __exit axion_exit(void) {
    if (state.shared_buffer)
        vfree(state.shared_buffer);
    device_destroy(axion_class, dev_num);
    class_destroy(axion_class);
    cdev_del(&axion_cdev);
    unregister_chrdev_region(dev_num, 1);
    TS_LOG(LOG_INFO, "Axion unloaded\n");
}

module_init(axion_init);
module_exit(axion_exit);
MODULE_LICENSE("GPL");

#endif /* __KERNEL__ */


/* ============================================================
 * Section 3: Extended Matrix and Arithmetic Operations
 * This section extends TritSys to include matrix operations and additional arithmetic
 * functions for T81BigInt. These routines allow creation, addition, multiplication,
 * and transposition of matrices whose elements are T81BigInt values.
 */

#include <stdlib.h>
#include <string.h>

/* Forward declarations for arithmetic helper functions */
TernaryError t81bigint_copy(const T81BigInt *src, T81BigInt *dest);
TernaryError t81bigint_mul(const T81BigInt *a, const T81BigInt *b, T81BigInt **result);

/*
 * create_matrix:
 * Allocates and initializes a new T81Matrix of size rows x cols.
 * Each element is allocated and initialized to represent the ternary zero.
 */
T81Matrix *create_matrix(int rows, int cols) {
    T81Matrix *m = (T81Matrix *) TS_MALLOC(sizeof(T81Matrix));
    if (!m) return NULL;
    m->rows = rows;
    m->cols = cols;
    m->data = (T81BigInt *) TS_MALLOC(rows * cols * sizeof(T81BigInt));
    if (!m->data) {
        TS_FREE(m);
        return NULL;
    }
    for (int i = 0; i < rows * cols; i++) {
        if (allocate_t81bigint(&m->data[i], 1) != TERNARY_NO_ERROR) {
            for (int j = 0; j < i; j++) {
                free_t81bigint(&m->data[j]);
            }
            TS_FREE(m->data);
            TS_FREE(m);
            return NULL;
        }
        m->data[i].sign = TERNARY_ZERO;
    }
    return m;
}

/*
 * free_matrix:
 * Releases all memory associated with a T81Matrix, including each T81BigInt element.
 */
void free_matrix(T81Matrix *m) {
    if (!m) return;
    if (m->data) {
        for (int i = 0; i < m->rows * m->cols; i++) {
            free_t81bigint(&m->data[i]);
        }
        TS_FREE(m->data);
    }
    TS_FREE(m);
}

/*
 * tmat_add:
 * Performs element-wise addition of two matrices.
 * Returns TERNARY_NO_ERROR on success; otherwise, an error code.
 */
TernaryError tmat_add(T81Matrix *a, T81Matrix *b, T81Matrix **result) {
    if (a->rows != b->rows || a->cols != b->cols)
        return TERNARY_ERR_INVALID_INPUT;
    T81Matrix *res = create_matrix(a->rows, a->cols);
    if (!res)
        return TERNARY_ERR_MEMALLOC;
    for (int i = 0; i < a->rows * a->cols; i++) {
        TernaryError err = t81bigint_add(&a->data[i], &b->data[i], &res->data[i]);
        if (err != TERNARY_NO_ERROR) {
            free_matrix(res);
            return err;
        }
    }
    *result = res;
    return TERNARY_NO_ERROR;
}

/*
 * tmat_mul:
 * Multiplies two matrices using the dot product approach.
 * The number of columns in matrix a must equal the number of rows in matrix b.
 */
TernaryError tmat_mul(T81Matrix *a, T81Matrix *b, T81Matrix **result) {
    if (a->cols != b->rows)
        return TERNARY_ERR_INVALID_INPUT;
    int rows = a->rows;
    int cols = b->cols;
    int inner = a->cols;
    T81Matrix *res = create_matrix(rows, cols);
    if (!res)
        return TERNARY_ERR_MEMALLOC;
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            int res_index = i * cols + j;
            /* Reinitialize the result element to zero */
            free_t81bigint(&res->data[res_index]);
            if (allocate_t81bigint(&res->data[res_index], 1) != TERNARY_NO_ERROR) {
                free_matrix(res);
                return TERNARY_ERR_MEMALLOC;
            }
            res->data[res_index].sign = TERNARY_ZERO;
            for (int k = 0; k < inner; k++) {
                int indexA = i * a->cols + k;
                int indexB = k * b->cols + j;
                T81BigInt *tempProduct = NULL;
                /* Multiply the corresponding elements */
                TernaryError err = t81bigint_mul(&a->data[indexA], &b->data[indexB], &tempProduct);
                if (err != TERNARY_NO_ERROR) {
                    free_matrix(res);
                    return err;
                }
                T81BigInt *newSum = NULL;
                /* Accumulate the product into the result element */
                err = t81bigint_add(&res->data[res_index], tempProduct, &newSum);
                free_t81bigint(tempProduct);
                TS_FREE(tempProduct);
                if (err != TERNARY_NO_ERROR) {
                    free_matrix(res);
                    return err;
                }
                free_t81bigint(&res->data[res_index]);
                res->data[res_index] = *newSum;
                TS_FREE(newSum);
            }
        }
    }
    *result = res;
    return TERNARY_NO_ERROR;
}

/*
 * tmat_transpose:
 * Generates a new matrix that is the transpose of the given matrix.
 */
T81Matrix *tmat_transpose(T81Matrix *m) {
    T81Matrix *t = create_matrix(m->cols, m->rows);
    if (!t)
        return NULL;
    for (int i = 0; i < m->rows; i++) {
        for (int j = 0; j < m->cols; j++) {
            int src_index = i * m->cols + j;
            int dest_index = j * m->rows + i;
            TernaryError err = t81bigint_copy(&m->data[src_index], &t->data[dest_index]);
            if (err != TERNARY_NO_ERROR) {
                free_matrix(t);
                return NULL;
            }
        }
    }
    return t;
}

/*
 * t81bigint_copy:
 * Performs a deep copy of a T81BigInt structure from src to dest.
 */
TernaryError t81bigint_copy(const T81BigInt *src, T81BigInt *dest) {
    if (allocate_t81bigint(dest, src->len) != TERNARY_NO_ERROR)
        return TERNARY_ERR_MEMALLOC;
    memcpy(dest->digits, src->digits, src->len);
    dest->sign = src->sign;
    return TERNARY_NO_ERROR;
}

/*
 * t81bigint_mul:
 * Multiplies two T81BigInts using a naive algorithm and normalizes the result
 * into balanced ternary form. If either operand is zero, returns zero.
 */
TernaryError t81bigint_mul(const T81BigInt *a, const T81BigInt *b, T81BigInt **result) {
    if (a->sign == TERNARY_ZERO || b->sign == TERNARY_ZERO) {
        *result = TS_MALLOC(sizeof(T81BigInt));
        if (allocate_t81bigint(*result, 1) != TERNARY_NO_ERROR)
            return TERNARY_ERR_MEMALLOC;
        (*result)->sign = TERNARY_ZERO;
        (*result)->digits[0] = 0;
        return TERNARY_NO_ERROR;
    }
    int res_len = a->len + b->len;
    int *temp = (int *) TS_MALLOC(res_len * sizeof(int));
    if (!temp) return TERNARY_ERR_MEMALLOC;
    for (int i = 0; i < res_len; i++)
        temp[i] = 0;
    /* Compute the raw multiplication result */
    for (int i = 0; i < a->len; i++) {
        int digit_a = (int)((signed char)a->digits[i]);
        for (int j = 0; j < b->len; j++) {
            int digit_b = (int)((signed char)b->digits[j]);
            temp[i + j] += digit_a * digit_b;
        }
    }
    /* Normalize to balanced ternary (digits in {-1,0,1}) */
    for (int i = 0; i < res_len; i++) {
        while (temp[i] > 1) {
            temp[i] -= 3;
            if (i + 1 < res_len)
                temp[i + 1]++;
        }
        while (temp[i] < -1) {
            temp[i] += 3;
            if (i + 1 < res_len)
                temp[i + 1]--;
        }
    }
    T81BigInt *res = TS_MALLOC(sizeof(T81BigInt));
    if (!res) { TS_FREE(temp); return TERNARY_ERR_MEMALLOC; }
    if (allocate_t81bigint(res, res_len) != TERNARY_NO_ERROR) {
         TS_FREE(temp);
         TS_FREE(res);
         return TERNARY_ERR_MEMALLOC;
    }
    for (int i = 0; i < res_len; i++) {
        res->digits[i] = (unsigned char)temp[i];
    }
    res->sign = (a->sign == b->sign) ? TERNARY_POSITIVE : TERNARY_NEGATIVE;
    TS_FREE(temp);
    *result = res;
    return TERNARY_NO_ERROR;
}
