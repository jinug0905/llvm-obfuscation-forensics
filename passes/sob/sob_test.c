// sob_test.c -- toy input for the string-obfuscation pass. These two literals should appear
// in sob_test.ll but NOT in sob_test_out.ll after the pass runs.

#include <string.h>
#include <stdio.h>

int check_marker(const char *input) {
    return strcmp(input, "SECRET_MARKER_1234") == 0;
}

void print_banner(void) {
    puts("this string should not appear in the compiled output");
}
