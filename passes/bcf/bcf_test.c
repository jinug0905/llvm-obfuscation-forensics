// bcf_test.c -- toy input for the bogus-control-flow pass.
// Compile with -O0 -Xclang -disable-O0-optnone so if/while show up as real branches between
// blocks instead of being folded away before the pass ever runs.

int classify(int x) {
    int result;
    if (x > 0) {
        result = 1;
    } else {
        result = -1;
    }
    return result;
}

int loop_sum(int n) {
    int sum = 0;
    int i = 0;
    while (i < n) {
        sum += i;
        i++;
    }
    return sum;
}
