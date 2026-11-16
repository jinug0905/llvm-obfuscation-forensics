// sub_test.c -- toy input for the instruction-substitution pass.
// Compile with -O0 -Xclang -disable-O0-optnone so add/sub/xor show up as plain IR
// instructions instead of being folded away before the pass ever runs.

int add_them(int a, int b) {
    return a + b;
}

int sub_them(int a, int b) {
    return a - b;
}

int xor_them(int a, int b) {
    return a ^ b;
}

int and_them(int a, int b) {
    return a & b;
}

int or_them(int a, int b) {
    return a | b;
}

int mix(int a, int b, int c) {
    int t = a + b;  // Add
    int u = t - c;  // Sub
    return u ^ a;   // Xor
}
