/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017, 2018, 2019 Giuseppe Scrivano <giuseppe@scrivano.org>
 * crun is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * crun is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with crun.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <libcrun/utils.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

typedef int (*test) ();

static int
test_str2sig_common_signals ()
{
  /* Test common signals without SIG prefix */
  if (str2sig ("TERM") != SIGTERM)
    return -1;

  if (str2sig ("KILL") != SIGKILL)
    return -1;

  if (str2sig ("INT") != SIGINT)
    return -1;

  if (str2sig ("HUP") != SIGHUP)
    return -1;

  if (str2sig ("QUIT") != SIGQUIT)
    return -1;

  if (str2sig ("USR1") != SIGUSR1)
    return -1;

  if (str2sig ("USR2") != SIGUSR2)
    return -1;

  if (str2sig ("PIPE") != SIGPIPE)
    return -1;

  if (str2sig ("ALRM") != SIGALRM)
    return -1;

  if (str2sig ("CHLD") != SIGCHLD)
    return -1;

  if (str2sig ("CONT") != SIGCONT)
    return -1;

  if (str2sig ("STOP") != SIGSTOP)
    return -1;

  return 0;
}

static int
test_str2sig_with_sig_prefix ()
{
  /* Test signals with SIG prefix - should return same values as without */
  if (str2sig ("SIGTERM") != SIGTERM)
    return -1;

  if (str2sig ("SIGKILL") != SIGKILL)
    return -1;

  if (str2sig ("SIGINT") != SIGINT)
    return -1;

  if (str2sig ("SIGHUP") != SIGHUP)
    return -1;

  if (str2sig ("SIGQUIT") != SIGQUIT)
    return -1;

  if (str2sig ("SIGUSR1") != SIGUSR1)
    return -1;

  if (str2sig ("SIGUSR2") != SIGUSR2)
    return -1;

  if (str2sig ("SIGPIPE") != SIGPIPE)
    return -1;

  if (str2sig ("SIGALRM") != SIGALRM)
    return -1;

  if (str2sig ("SIGCHLD") != SIGCHLD)
    return -1;

  if (str2sig ("SIGCONT") != SIGCONT)
    return -1;

  if (str2sig ("SIGSTOP") != SIGSTOP)
    return -1;

  return 0;
}

static int
test_str2sig_numeric_strings ()
{
  /* Test numeric signal values as strings */
  if (str2sig ("9") != 9)
    return -1;

  if (str2sig ("15") != 15)
    return -1;

  if (str2sig ("1") != 1)
    return -1;

  if (str2sig ("2") != 2)
    return -1;

  if (str2sig ("13") != 13)
    return -1;

  if (str2sig ("17") != 17)
    return -1;

  /* Test edge cases */
  if (str2sig ("0") != 0)
    return -1;

  if (str2sig ("64") != 64)
    return -1;

  return 0;
}

static int
test_str2sig_invalid_names ()
{
  /* Test invalid signal names */
  errno = 0;
  if (str2sig ("INVALID") != -1)
    return -1;
  if (errno != EINVAL)
    return -1;

  errno = 0;
  if (str2sig ("NOTASIGNAL") != -1)
    return -1;
  if (errno != EINVAL)
    return -1;

  errno = 0;
  if (str2sig ("") != -1)
    return -1;
  if (errno != EINVAL)
    return -1;

  /* Test with invalid prefix */
  errno = 0;
  if (str2sig ("SIG") != -1)
    return -1;
  if (errno != EINVAL)
    return -1;

  /* Test signal name that doesn't exist */
  errno = 0;
  if (str2sig ("SIGFAKE") != -1)
    return -1;
  if (errno != EINVAL)
    return -1;

  return 0;
}

static int
test_str2sig_realtime_signals ()
{
  /* Test real-time signals.  These are compared against the fixed values
     from signals.perf, as the first usable real time signal depends on
     how many of them the C library reserves for itself.  */
  if (str2sig ("RTMIN") != 34)
    return -1;

  if (str2sig ("RTMAX") != 64)
    return -1;

  if (str2sig ("RTMIN+1") != 35)
    return -1;

  if (str2sig ("RTMIN+2") != 36)
    return -1;

  if (str2sig ("RTMIN+5") != 39)
    return -1;

  if (str2sig ("RTMIN+10") != 44)
    return -1;

  if (str2sig ("RTMIN+15") != 49)
    return -1;

  if (str2sig ("RTMAX-1") != 63)
    return -1;

  if (str2sig ("RTMAX-2") != 62)
    return -1;

  if (str2sig ("RTMAX-5") != 59)
    return -1;

  if (str2sig ("RTMAX-10") != 54)
    return -1;

  if (str2sig ("RTMAX-14") != 50)
    return -1;

  return 0;
}

static int
test_str2sig_realtime_signals_with_prefix ()
{
  /* Test real-time signals with SIG prefix */
  if (str2sig ("SIGRTMIN") != 34)
    return -1;

  if (str2sig ("SIGRTMAX") != 64)
    return -1;

  if (str2sig ("SIGRTMIN+1") != 35)
    return -1;

  if (str2sig ("SIGRTMIN+10") != 44)
    return -1;

  if (str2sig ("SIGRTMAX-1") != 63)
    return -1;

  if (str2sig ("SIGRTMAX-10") != 54)
    return -1;

  return 0;
}

static int
test_str2sig_all_standard_signals ()
{
  /* Test all standard signals defined in the hash table */
  if (str2sig ("ILL") != SIGILL)
    return -1;

  if (str2sig ("TRAP") != SIGTRAP)
    return -1;

  if (str2sig ("ABRT") != SIGABRT)
    return -1;

  if (str2sig ("BUS") != SIGBUS)
    return -1;

  if (str2sig ("FPE") != SIGFPE)
    return -1;

  if (str2sig ("SEGV") != SIGSEGV)
    return -1;

#ifdef SIGSTKFLT
  if (str2sig ("STKFLT") != SIGSTKFLT)
    return -1;
#endif

  if (str2sig ("TSTP") != SIGTSTP)
    return -1;

  if (str2sig ("TTIN") != SIGTTIN)
    return -1;

  if (str2sig ("TTOU") != SIGTTOU)
    return -1;

  if (str2sig ("URG") != SIGURG)
    return -1;

  if (str2sig ("XCPU") != SIGXCPU)
    return -1;

  if (str2sig ("XFSZ") != SIGXFSZ)
    return -1;

  if (str2sig ("VTALRM") != SIGVTALRM)
    return -1;

  if (str2sig ("PROF") != SIGPROF)
    return -1;

  if (str2sig ("WINCH") != SIGWINCH)
    return -1;

  if (str2sig ("IO") != SIGIO)
    return -1;

  if (str2sig ("PWR") != SIGPWR)
    return -1;

  if (str2sig ("SYS") != SIGSYS)
    return -1;

  return 0;
}

static int
test_str2sig_all_standard_signals_with_prefix ()
{
  /* Test all standard signals with SIG prefix */
  if (str2sig ("SIGILL") != SIGILL)
    return -1;

  if (str2sig ("SIGTRAP") != SIGTRAP)
    return -1;

  if (str2sig ("SIGABRT") != SIGABRT)
    return -1;

  if (str2sig ("SIGBUS") != SIGBUS)
    return -1;

  if (str2sig ("SIGFPE") != SIGFPE)
    return -1;

  if (str2sig ("SIGSEGV") != SIGSEGV)
    return -1;

#ifdef SIGSTKFLT
  if (str2sig ("SIGSTKFLT") != SIGSTKFLT)
    return -1;
#endif

  if (str2sig ("SIGTSTP") != SIGTSTP)
    return -1;

  if (str2sig ("SIGTTIN") != SIGTTIN)
    return -1;

  if (str2sig ("SIGTTOU") != SIGTTOU)
    return -1;

  if (str2sig ("SIGURG") != SIGURG)
    return -1;

  if (str2sig ("SIGXCPU") != SIGXCPU)
    return -1;

  if (str2sig ("SIGXFSZ") != SIGXFSZ)
    return -1;

  if (str2sig ("SIGVTALRM") != SIGVTALRM)
    return -1;

  if (str2sig ("SIGPROF") != SIGPROF)
    return -1;

  if (str2sig ("SIGWINCH") != SIGWINCH)
    return -1;

  if (str2sig ("SIGIO") != SIGIO)
    return -1;

  if (str2sig ("SIGPWR") != SIGPWR)
    return -1;

  if (str2sig ("SIGSYS") != SIGSYS)
    return -1;

  return 0;
}

static int
test_str2sig_case_sensitivity ()
{
  /* Test that signal names are case-sensitive (uppercase only) */
  errno = 0;
  if (str2sig ("term") != -1)
    return -1;
  if (errno != EINVAL)
    return -1;

  errno = 0;
  if (str2sig ("Term") != -1)
    return -1;
  if (errno != EINVAL)
    return -1;

  errno = 0;
  if (str2sig ("sigterm") != -1)
    return -1;
  if (errno != EINVAL)
    return -1;

  errno = 0;
  if (str2sig ("SigTerm") != -1)
    return -1;
  if (errno != EINVAL)
    return -1;

  return 0;
}

static int
test_str2sig_all_rtmin_signals ()
{
  /* Test all RTMIN+ signals from the hash table */
  if (str2sig ("RTMIN+3") != 37)
    return -1;

  if (str2sig ("RTMIN+4") != 38)
    return -1;

  if (str2sig ("RTMIN+6") != 40)
    return -1;

  if (str2sig ("RTMIN+7") != 41)
    return -1;

  if (str2sig ("RTMIN+8") != 42)
    return -1;

  if (str2sig ("RTMIN+9") != 43)
    return -1;

  if (str2sig ("RTMIN+11") != 45)
    return -1;

  if (str2sig ("RTMIN+12") != 46)
    return -1;

  if (str2sig ("RTMIN+13") != 47)
    return -1;

  if (str2sig ("RTMIN+14") != 48)
    return -1;

  return 0;
}

static int
test_str2sig_all_rtmax_signals ()
{
  /* Test all RTMAX- signals from the hash table */
  if (str2sig ("RTMAX-3") != 61)
    return -1;

  if (str2sig ("RTMAX-4") != 60)
    return -1;

  if (str2sig ("RTMAX-6") != 58)
    return -1;

  if (str2sig ("RTMAX-7") != 57)
    return -1;

  if (str2sig ("RTMAX-8") != 56)
    return -1;

  if (str2sig ("RTMAX-9") != 55)
    return -1;

  if (str2sig ("RTMAX-11") != 53)
    return -1;

  if (str2sig ("RTMAX-12") != 52)
    return -1;

  if (str2sig ("RTMAX-13") != 51)
    return -1;

  return 0;
}

static int
test_str2sig_numeric_edge_cases ()
{
  /* Test large numeric values */
  if (str2sig ("100") != 100)
    return -1;

  if (str2sig ("255") != 255)
    return -1;

  /* Test that numeric strings starting with a digit are handled by strtol */
  /* strtol will convert "1ABC" to 1 and stop at 'A', which is valid behavior */
  if (str2sig ("1ABC") != 1)
    return -1;

  return 0;
}

static void
run_and_print_test_result (const char *name, int id, test t)
{
  int ret = t ();
  if (ret == 0)
    printf ("ok %d - %s\n", id, name);
  else if (ret == 77)
    printf ("ok %d - %s #SKIP\n", id, name);
  else
    printf ("not ok %d - %s\n", id, name);
}

#define RUN_TEST(T)                            \
  do                                           \
    {                                          \
      run_and_print_test_result (#T, id++, T); \
  } while (0)

int
main ()
{
  int id = 1;
  printf ("1..12\n");
  RUN_TEST (test_str2sig_common_signals);
  RUN_TEST (test_str2sig_with_sig_prefix);
  RUN_TEST (test_str2sig_numeric_strings);
  RUN_TEST (test_str2sig_invalid_names);
  RUN_TEST (test_str2sig_realtime_signals);
  RUN_TEST (test_str2sig_realtime_signals_with_prefix);
  RUN_TEST (test_str2sig_all_standard_signals);
  RUN_TEST (test_str2sig_all_standard_signals_with_prefix);
  RUN_TEST (test_str2sig_case_sensitivity);
  RUN_TEST (test_str2sig_all_rtmin_signals);
  RUN_TEST (test_str2sig_all_rtmax_signals);
  RUN_TEST (test_str2sig_numeric_edge_cases);
  return 0;
}
