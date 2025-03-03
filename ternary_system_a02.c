/******************************************************************************
 * Ternary System Enhanced Program
 *
 * This file implements a ternary system with several new capabilities:
 *
 * 1. Full tritjs_eval_expression Parser
 *    -----------------------------------
 *    This parser evaluates arithmetic expressions written in a ternary system.
 *    Numbers are expressed using only the digits 0, 1, and 2. Supported
 *    operations include addition (+), subtraction (-), multiplication (*),
 *    and division (/). Parentheses can be used to override operator precedence.
 *
 * 2. Recursive Tower of Hanoi Solver with Ternary State Encoding
 *    ------------------------------------------------------------
 *    The classic Tower of Hanoi puzzle is solved recursively. Each disk’s
 *    current peg is encoded as a digit (0, 1, or 2) in a state array, which
 *    can be printed as a compact ternary number representing the overall state.
 *
 * 3. Matrix Serialization for TMAT_ADD / TMAT_MUL
 *    -----------------------------------------------
 *    This section supports creation, addition (TMAT_ADD), multiplication
 *    (TMAT_MUL), and file-based serialization/deserialization of matrices.
 *    Matrix elements are stored and written in a ternary representation.
 *
 * Help/Usage:
 *   - Expression evaluation:
 *         % ./ternary_system -expr "12+21*(2-1)"
 *   - Tower of Hanoi (n disks):
 *         % ./ternary_system -hanoi n
 *   - Matrix serialization (creates a sample 3x3 matrix and writes it to a file):
 *         % ./ternary_system -ser filename
 *   - Matrix deserialization (reads a matrix from a file and demonstrates addition
 *     and, if square, multiplication):
 *         % ./ternary_system -des filename
 *
 * Compilation example:
 *         gcc ternary_system_A01.cweb -o ternary_system
 *
 * Please and Thankyou!
 *****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

/*---------------------------------------------------------
  Expression Parser for Ternary Arithmetic Expressions
  ---------------------------------------------------------*/

/*
 * Global pointer used for parsing the expression string.
 * The parser expects numbers to be in ternary (digits 0, 1, 2).
 */
static const char *expr_str;

/* Error handling: prints an error message and exits. */
void error(const char *msg) {
    fprintf(stderr, "Error: %s\n", msg);
    exit(1);
}

/* Forward declarations for recursive descent parsing functions */
int parse_expr();
int parse_term();
int parse_factor();

/*
 * parse_number:
 *   Parses a ternary number from the current position in expr_str.
 *   Converts a string composed of digits '0', '1', '2' into its integer value.
 */
int parse_number() {
    int value = 0;
    if (!isdigit(*expr_str))
        error("Expected a digit");
    while (*expr_str && (*expr_str == '0' || *expr_str == '1' || *expr_str == '2')) {
        value = value * 3 + (*expr_str - '0');
        expr_str++;
    }
    return value;
}

/*
 * parse_factor:
 *   Parses a factor, which can be either a number or a parenthesized expression.
 */
int parse_factor() {
    while (*expr_str && isspace(*expr_str)) expr_str++;
    if (*expr_str == '(') {
        expr_str++;  /* Skip '(' */
        int value = parse_expr();
        if (*expr_str != ')')
            error("Expected ')'");
        expr_str++;  /* Skip ')' */
        return value;
    } else {
        return parse_number();
    }
}

/*
 * parse_term:
 *   Parses a term: factor { ('*' | '/') factor }
 */
int parse_term() {
    int value = parse_factor();
    while (*expr_str) {
        while (*expr_str && isspace(*expr_str)) expr_str++;
        if (*expr_str == '*' || *expr_str == '/') {
            char op = *expr_str;
            expr_str++;
            int next_value = parse_factor();
            if (op == '*')
                value = value * next_value;
            else {
                if (next_value == 0)
                    error("Division by zero");
                value = value / next_value;
            }
        } else {
            break;
        }
    }
    return value;
}

/*
 * parse_expr:
 *   Parses an expression: term { ('+' | '-') term }
 */
int parse_expr() {
    int value = parse_term();
    while (*expr_str) {
        while (*expr_str && isspace(*expr_str)) expr_str++;
        if (*expr_str == '+' || *expr_str == '-') {
            char op = *expr_str;
            expr_str++;
            int next_value = parse_term();
            if (op == '+')
                value = value + next_value;
            else
                value = value - next_value;
        } else {
            break;
        }
    }
    return value;
}

/*
 * tritjs_eval_expression:
 *   Entry point for evaluating a ternary expression.
 *   On success, returns the evaluated result as an integer.
 */
int tritjs_eval_expression(const char *expr) {
    expr_str = expr;
    int result = parse_expr();
    /* Ensure there are no unexpected characters remaining */
    while (*expr_str) {
        if (!isspace(*expr_str))
            error("Unexpected character in expression");
        expr_str++;
    }
    return result;
}

/*
 * int_to_ternary:
 *   Converts an integer to its ternary (base 3) string representation.
 *   The result is stored in the provided buffer (assumed to be large enough).
 */
void int_to_ternary(int n, char *buffer) {
    char temp[64];
    int i = 0;
    if (n == 0) {
        strcpy(buffer, "0");
        return;
    }
    int is_negative = 0;
    if (n < 0) {
        is_negative = 1;
        n = -n;
    }
    while (n > 0) {
        temp[i++] = '0' + (n % 3);
        n /= 3;
    }
    if (is_negative)
        temp[i++] = '-';
    temp[i] = '\0';
    /* Reverse the string */
    int len = strlen(temp);
    for (int j = 0; j < len; j++) {
        buffer[j] = temp[len - j - 1];
    }
    buffer[len] = '\0';
}

/*---------------------------------------------------------
  Recursive Tower of Hanoi with Ternary State Encoding
  ---------------------------------------------------------*/

/*
 * In this implementation, the state of the Tower of Hanoi is represented
 * by an array of integers. Each disk's position is encoded as a trit (0, 1, or 2),
 * corresponding to the peg on which the disk currently resides. Disk 0 is the smallest.
 */

/*
 * print_state:
 *   Prints the current state of the disks as a ternary number,
 *   where the most significant digit corresponds to the largest disk.
 */
void print_state(int *state, int n) {
    printf("State: ");
    for (int i = n - 1; i >= 0; i--) {
        printf("%d", state[i]);
    }
    printf("\n");
}

/*
 * hanoi_move:
 *   Executes a move by updating the state array and printing the move details.
 */
void hanoi_move(int disk, int from, int to, int *state) {
    printf("Move disk %d from peg %d to peg %d\n", disk, from, to);
    state[disk] = to;
    print_state(state, disk + 1);  /* Print state for disks up to the moved disk */
}

/*
 * solve_hanoi_recursive:
 *   Recursively solves the Tower of Hanoi puzzle for n disks.
 *   The function uses a standard recursive algorithm while updating the ternary state.
 */
void solve_hanoi_recursive(int n, int from, int to, int aux, int *state) {
    if (n == 0) return;
    solve_hanoi_recursive(n - 1, from, aux, to, state);
    hanoi_move(n - 1, from, to, state);
    solve_hanoi_recursive(n - 1, aux, to, from, state);
}

/*
 * solve_hanoi:
 *   Initializes the state for n disks (all starting at peg 0) and calls the
 *   recursive solver. After completion, the entire sequence of moves is printed.
 */
void solve_hanoi(int n) {
    int *state = (int *)malloc(n * sizeof(int));
    if (!state) {
        fprintf(stderr, "Memory allocation failed for Hanoi state.\n");
        exit(1);
    }
    for (int i = 0; i < n; i++) {
        state[i] = 0;
    }
    printf("Initial state (all disks on peg 0):\n");
    print_state(state, n);
    solve_hanoi_recursive(n, 0, 2, 1, state);
    free(state);
}

/*---------------------------------------------------------
  Matrix Serialization and Operations (TMAT_ADD / TMAT_MUL)
  ---------------------------------------------------------*/

/*
 * The TMatrix structure represents a matrix with integer elements.
 * It contains the number of rows, columns, and a pointer to a 2D array of data.
 */
typedef struct {
    int rows;
    int cols;
    int **data;
} TMatrix;

/*
 * create_matrix:
 *   Allocates and initializes a matrix of given dimensions.
 */
TMatrix *create_matrix(int rows, int cols) {
    TMatrix *m = (TMatrix *)malloc(sizeof(TMatrix));
    if (!m) {
        fprintf(stderr, "Memory allocation failed for matrix structure.\n");
        exit(1);
    }
    m->rows = rows;
    m->cols = cols;
    m->data = (int **)malloc(rows * sizeof(int *));
    if (!m->data) {
        fprintf(stderr, "Memory allocation failed for matrix data.\n");
        exit(1);
    }
    for (int i = 0; i < rows; i++) {
        m->data[i] = (int *)calloc(cols, sizeof(int));
        if (!m->data[i]) {
            fprintf(stderr, "Memory allocation failed for matrix row.\n");
            exit(1);
        }
    }
    return m;
}

/*
 * free_matrix:
 *   Frees the memory associated with a matrix.
 */
void free_matrix(TMatrix *m) {
    if (m) {
        for (int i = 0; i < m->rows; i++) {
            free(m->data[i]);
        }
        free(m->data);
        free(m);
    }
}

/*
 * TMAT_ADD:
 *   Adds two matrices (A + B) and returns a new matrix with the result.
 *   Both matrices must have the same dimensions.
 */
TMatrix *TMAT_ADD(TMatrix *A, TMatrix *B) {
    if (A->rows != B->rows || A->cols != B->cols) {
        fprintf(stderr, "Matrix dimensions mismatch for addition.\n");
        exit(1);
    }
    TMatrix *result = create_matrix(A->rows, A->cols);
    for (int i = 0; i < A->rows; i++) {
        for (int j = 0; j < A->cols; j++) {
            result->data[i][j] = A->data[i][j] + B->data[i][j];
        }
    }
    return result;
}

/*
 * TMAT_MUL:
 *   Multiplies two matrices (A * B) and returns a new matrix with the result.
 *   The number of columns of A must equal the number of rows of B.
 */
TMatrix *TMAT_MUL(TMatrix *A, TMatrix *B) {
    if (A->cols != B->rows) {
        fprintf(stderr, "Matrix dimensions mismatch for multiplication.\n");
        exit(1);
    }
    TMatrix *result = create_matrix(A->rows, B->cols);
    for (int i = 0; i < A->rows; i++) {
        for (int j = 0; j < B->cols; j++) {
            int sum = 0;
            for (int k = 0; k < A->cols; k++) {
                sum += A->data[i][k] * B->data[k][j];
            }
            result->data[i][j] = sum;
        }
    }
    return result;
}

/*
 * serialize_matrix:
 *   Writes a matrix to a file in a text-based format.
 *   The file first contains the dimensions, then each element is written in its
 *   ternary representation.
 */
void serialize_matrix(TMatrix *m, const char *filename) {
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        fprintf(stderr, "Failed to open file for matrix serialization.\n");
        exit(1);
    }
    fprintf(fp, "%d %d\n", m->rows, m->cols);
    char buffer[64];
    for (int i = 0; i < m->rows; i++) {
        for (int j = 0; j < m->cols; j++) {
            int_to_ternary(m->data[i][j], buffer);
            fprintf(fp, "%s ", buffer);
        }
        fprintf(fp, "\n");
    }
    fclose(fp);
}

/*
 * deserialize_matrix:
 *   Reads a matrix from a file (in the format produced by serialize_matrix)
 *   and returns a pointer to the reconstructed TMatrix.
 */
TMatrix *deserialize_matrix(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Failed to open file for matrix deserialization.\n");
        exit(1);
    }
    int rows, cols;
    if (fscanf(fp, "%d %d", &rows, &cols) != 2) {
        fprintf(stderr, "Failed to read matrix dimensions.\n");
        exit(1);
    }
    TMatrix *m = create_matrix(rows, cols);
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            char buf[64];
            if (fscanf(fp, "%63s", buf) != 1) {
                fprintf(stderr, "Failed to read matrix element.\n");
                exit(1);
            }
            int value = 0;
            char *p = buf;
            int is_negative = 0;
            if (*p == '-') { is_negative = 1; p++; }
            while (*p) {
                if (*p < '0' || *p > '2') {
                    fprintf(stderr, "Invalid digit in ternary number.\n");
                    exit(1);
                }
                value = value * 3 + (*p - '0');
                p++;
            }
            if (is_negative) value = -value;
            m->data[i][j] = value;
        }
    }
    fclose(fp);
    return m;
}

/*---------------------------------------------------------
  Documentation and Help Information
  ---------------------------------------------------------*/

/*
 * print_help:
 *   Displays a help message detailing the available functionalities and usage.
 */
void print_help() {
    printf("Ternary System Enhanced Program Help\n");
    printf("======================================\n");
    printf("Available functionalities:\n");
    printf("1. Expression Parser (tritjs_eval_expression):\n");
    printf("   Evaluate a ternary arithmetic expression.\n");
    printf("   Usage: Provide an expression string containing digits 0,1,2 and operators +, -, *, /\n");
    printf("   Example: \"12+21*(2-1)\" (numbers are in ternary)\n\n");

    printf("2. Recursive Tower of Hanoi Solver:\n");
    printf("   Solve the Tower of Hanoi puzzle with ternary state encoding.\n");
    printf("   Usage: Call solve_hanoi(n) where n is the number of disks.\n\n");

    printf("3. Matrix Operations and Serialization:\n");
    printf("   - TMAT_ADD: Matrix addition.\n");
    printf("   - TMAT_MUL: Matrix multiplication.\n");
    printf("   - Matrix Serialization/Deserialization: Save or load matrices to/from a file in ternary representation.\n\n");

    printf("Compilation:\n");
    printf("   Compile with a C compiler. Example: gcc ternary_system_A01.cweb -o ternary_system\n");
    printf("   Run the executable with appropriate switches to access functionalities.\n");
    printf("======================================\n");
}

/*---------------------------------------------------------
  Main Program
  ---------------------------------------------------------*/

/*
 * main:
 *   Parses command-line arguments to select the desired functionality:
 *
 *   - -expr "expression" : Evaluate a ternary expression.
 *   - -hanoi n           : Solve Tower of Hanoi with n disks.
 *   - -ser filename      : Create a sample matrix and serialize it to a file.
 *   - -des filename      : Deserialize a matrix from a file and demonstrate matrix
 *                           addition and (if square) multiplication.
 */
int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_help();
        return 0;
    }
    if (strcmp(argv[1], "-expr") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s -expr \"expression\"\n", argv[0]);
            return 1;
        }
        int result = tritjs_eval_expression(argv[2]);
        char buffer[64];
        int_to_ternary(result, buffer);
        printf("Result (ternary): %s\n", buffer);
    } else if (strcmp(argv[1], "-hanoi") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s -hanoi n\n", argv[0]);
            return 1;
        }
        int n = atoi(argv[2]);
        solve_hanoi(n);
    } else if (strcmp(argv[1], "-ser") == 0) {
        /* Create a sample 3x3 matrix and serialize it to a file. */
        TMatrix *m = create_matrix(3, 3);
        for (int i = 0; i < m->rows; i++) {
            for (int j = 0; j < m->cols; j++) {
                m->data[i][j] = (i + j) % 3;
            }
        }
        serialize_matrix(m, argv[2]);
        printf("Matrix serialized to %s\n", argv[2]);
        free_matrix(m);
    } else if (strcmp(argv[1], "-des") == 0) {
        /* Deserialize a matrix from a file and demonstrate operations. */
        TMatrix *m = deserialize_matrix(argv[2]);
        printf("Deserialized matrix:\n");
        for (int i = 0; i < m->rows; i++) {
            for (int j = 0; j < m->cols; j++) {
                printf("%d ", m->data[i][j]);
            }
            printf("\n");
        }
        TMatrix *add_result = TMAT_ADD(m, m);
        printf("Matrix after addition (m + m):\n");
        for (int i = 0; i < add_result->rows; i++) {
            for (int j = 0; j < add_result->cols; j++) {
                printf("%d ", add_result->data[i][j]);
            }
            printf("\n");
        }
        if (m->rows == m->cols) {
            TMatrix *mul_result = TMAT_MUL(m, m);
            printf("Matrix after multiplication (m * m):\n");
            for (int i = 0; i < mul_result->rows; i++) {
                for (int j = 0; j < mul_result->cols; j++) {
                    printf("%d ", mul_result->data[i][j]);
                }
                printf("\n");
            }
            free_matrix(mul_result);
        }
        free_matrix(add_result);
        free_matrix(m);
    } else {
        print_help();
    }
    return 0;
}
