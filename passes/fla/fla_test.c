// fla_test.c -- toy input for the control-flow-flattening pass. Same two functions as
// bcf_test.c on purpose: it makes it easy to compare what each pass does to identical input.
// identity() is here to exercise the "only one block, nothing to flatten" bail-out.

int identity(int x) {
    return x;
}

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
