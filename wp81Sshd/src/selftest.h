#pragma once

/*
 * selftest.h  -  Known-answer tests for the bundled crypto.
 *
 * Has no dependency on the Win32 / CRT environment so it can also be
 * compiled freestanding on a development PC.
 */

/* Output callback: receives one NUL-terminated line (no newline). */
typedef void (*SelfTestPrintFn)(const char *line);

/* Runs every test, prints one PASS/FAIL line per test.
 * Returns the number of failed tests (0 = all good). */
int crypto_selftest(SelfTestPrintFn print);
