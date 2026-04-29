/*
 * test_target.c — Minimal C binary for ghidra-mcp-ng integration tests.
 *
 * Functions:   add, multiply, compute, main, call_via_ptr, check_64bit_magic
 * Call graph:  main -> compute -> add
 *              main -> compute -> multiply -> add
 *              call_via_ptr -> add (via function pointer — creates DATA ref to add)
 * String:      GHIDRA_MCP_TEST_SENTINEL  (searchable via search_defined_strings)
 *
 * Compile with: gcc -O0 -o test_target test_target.c
 */
#include <stdlib.h>

/* Sentinel string — must survive optimisation and be findable by Ghidra. */
static const char SENTINEL[] = "GHIDRA_MCP_TEST_SENTINEL";

int add(int a, int b) {
    return a + b;
}

int multiply(int a, int b) {
    int result = 0;
    int i;
    for (i = 0; i < b; i++) {
        result = add(result, a);
    }
    return result;
}

int compute(int x, int y, int mode) {
    if (mode == 0) {
        return add(x, y);
    }
    return multiply(x, y);
}

int main(int argc, char *argv[]) {
    int a = 2, b = 3;
    if (argc > 2) {
        a = atoi(argv[1]);
        b = atoi(argv[2]);
    }
    (void)SENTINEL;
    return compute(a, b, 0);
}

/*
 * Forces a 64-bit immediate with its MSB set into the binary so that
 * search_constant_references can be tested with a negative decimal value.
 *
 * 0xDEADBEEFDEADBEEF = -2401053088876216593 (signed long).
 * gcc -O0 emits: movabs rax, -2401053088876216593 ; cmp rdi, rax
 * Ghidra surfaces the immediate as a 64-bit Scalar whose getUnsignedValue()
 * returns the same Java long value (-2401053088876216593L), so searching by
 * the signed decimal form must find this instruction.
 */
long check_64bit_magic(long x) {
    return x == (long)0xDEADBEEFDEADBEEFL;
}

/*
 * Forces a DATA reference to add() via a function pointer.
 * gcc -O0 emits a mov that loads the address of add into a local variable,
 * which Ghidra records as a DATA cross-reference to add's entry point.
 * Used by get_function_references tests to verify non-CALL references are returned.
 */
typedef int (*add_fn_t)(int, int);
int call_via_ptr(int a, int b) {
    add_fn_t fn = add;
    return fn(a, b);
}
