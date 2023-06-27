/* ANSI-C code produced by gperf version 3.1 */
/* Command-line: gperf --lookup-function-name libcrun_mount_flag_in_word_set -m 100 -tCEG -S1 src/libcrun/mount_flags.perf  */
/* Computed positions: -k'1-4' */

#if ! ((' ' == 32) && ('!' == 33) && ('"' == 34) && ('#' == 35)        \
       && ('%' == 37) && ('&' == 38) && ('\'' == 39) && ('(' == 40)    \
       && (')' == 41) && ('*' == 42) && ('+' == 43) && (',' == 44)     \
       && ('-' == 45) && ('.' == 46) && ('/' == 47) && ('0' == 48)     \
       && ('1' == 49) && ('2' == 50) && ('3' == 51) && ('4' == 52)     \
       && ('5' == 53) && ('6' == 54) && ('7' == 55) && ('8' == 56)     \
       && ('9' == 57) && (':' == 58) && (';' == 59) && ('<' == 60)     \
       && ('=' == 61) && ('>' == 62) && ('?' == 63) && ('A' == 65)     \
       && ('B' == 66) && ('C' == 67) && ('D' == 68) && ('E' == 69)     \
       && ('F' == 70) && ('G' == 71) && ('H' == 72) && ('I' == 73)     \
       && ('J' == 74) && ('K' == 75) && ('L' == 76) && ('M' == 77)     \
       && ('N' == 78) && ('O' == 79) && ('P' == 80) && ('Q' == 81)     \
       && ('R' == 82) && ('S' == 83) && ('T' == 84) && ('U' == 85)     \
       && ('V' == 86) && ('W' == 87) && ('X' == 88) && ('Y' == 89)     \
       && ('Z' == 90) && ('[' == 91) && ('\\' == 92) && (']' == 93)    \
       && ('^' == 94) && ('_' == 95) && ('a' == 97) && ('b' == 98)     \
       && ('c' == 99) && ('d' == 100) && ('e' == 101) && ('f' == 102)  \
       && ('g' == 103) && ('h' == 104) && ('i' == 105) && ('j' == 106) \
       && ('k' == 107) && ('l' == 108) && ('m' == 109) && ('n' == 110) \
       && ('o' == 111) && ('p' == 112) && ('q' == 113) && ('r' == 114) \
       && ('s' == 115) && ('t' == 116) && ('u' == 117) && ('v' == 118) \
       && ('w' == 119) && ('x' == 120) && ('y' == 121) && ('z' == 122) \
       && ('{' == 123) && ('|' == 124) && ('}' == 125) && ('~' == 126))
/* The character set is not based on ISO-646.  */
#  error "gperf generated tables don't work with this execution character set. Please report a bug to <bug-gperf@gnu.org>."
#endif

#line 19 "src/libcrun/mount_flags.perf"

#define _GNU_SOURCE

#include <config.h>
#include <stddef.h>
#include <stdlib.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>

#include "utils.h"
#include "mount_flags.h"

#line 34 "src/libcrun/mount_flags.perf"
struct propagation_flags_s;
enum
{
  TOTAL_KEYWORDS = 56,
  MIN_WORD_LENGTH = 2,
  MAX_WORD_LENGTH = 14,
  MIN_HASH_VALUE = 2,
  MAX_HASH_VALUE = 69
};

/* maximum key range = 68, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#  ifdef __cplusplus
inline
#  endif
#endif
    static unsigned int
    hash (register const char *str, register size_t len)
{
  static const unsigned char asso_values[] = {
    70, 70, 70, 70, 70, 70, 70, 70, 70, 70,
    70, 70, 70, 70, 70, 70, 70, 70, 70, 70,
    70, 70, 70, 70, 70, 70, 70, 70, 70, 70,
    70, 70, 70, 70, 70, 70, 70, 70, 70, 70,
    70, 70, 70, 70, 70, 70, 70, 70, 70, 70,
    70, 70, 70, 70, 70, 70, 70, 70, 70, 70,
    70, 70, 70, 70, 70, 70, 70, 70, 70, 70,
    70, 70, 70, 70, 70, 70, 70, 70, 70, 70,
    70, 70, 70, 70, 70, 70, 70, 70, 70, 70,
    70, 70, 70, 70, 70, 70, 70, 8, 29, 3,
    3, 21, 18, 70, 21, 0, 70, 70, 15, 10,
    0, 4, 32, 70, 0, 19, 8, 17, 22, 0,
    16, 27, 70, 70, 70, 70, 70, 70, 70, 70,
    70, 70, 70, 70, 70, 70, 70, 70, 70, 70,
    70, 70, 70, 70, 70, 70, 70, 70, 70, 70,
    70, 70, 70, 70, 70, 70, 70, 70, 70, 70,
    70, 70, 70, 70, 70, 70, 70, 70, 70, 70,
    70, 70, 70, 70, 70, 70, 70, 70, 70, 70,
    70, 70, 70, 70, 70, 70, 70, 70, 70, 70,
    70, 70, 70, 70, 70, 70, 70, 70, 70, 70,
    70, 70, 70, 70, 70, 70, 70, 70, 70, 70,
    70, 70, 70, 70, 70, 70, 70, 70, 70, 70,
    70, 70, 70, 70, 70, 70, 70, 70, 70, 70,
    70, 70, 70, 70, 70, 70, 70, 70, 70, 70,
    70, 70, 70, 70, 70, 70, 70, 70, 70, 70,
    70, 70, 70, 70, 70, 70
  };
  register unsigned int hval = len;

  switch (hval)
    {
    default:
      hval += asso_values[(unsigned char) str[3]];
    /*FALLTHROUGH*/
    case 3:
      hval += asso_values[(unsigned char) str[2]];
    /*FALLTHROUGH*/
    case 2:
      hval += asso_values[(unsigned char) str[1]];
    /*FALLTHROUGH*/
    case 1:
      hval += asso_values[(unsigned char) str[0]];
      break;
    }
  return hval;
}

static const struct propagation_flags_s wordlist[] = {
#line 40 "src/libcrun/mount_flags.perf"
  { "rw", 1, MS_RDONLY, 0 },
#line 70 "src/libcrun/mount_flags.perf"
  { "rrw", 1, MS_RDONLY, OPTION_RECURSIVE },
#line 39 "src/libcrun/mount_flags.perf"
  { "ro", 0, MS_RDONLY, 0 },
#line 69 "src/libcrun/mount_flags.perf"
  { "rro", 0, MS_RDONLY, OPTION_RECURSIVE },
#line 79 "src/libcrun/mount_flags.perf"
  { "rdirsync", 0, MS_DIRSYNC, OPTION_RECURSIVE },
#line 84 "src/libcrun/mount_flags.perf"
  { "rdiratime", 1, MS_NODIRATIME, OPTION_RECURSIVE },
#line 74 "src/libcrun/mount_flags.perf"
  { "rnodev", 0, MS_NODEV, OPTION_RECURSIVE },
#line 87 "src/libcrun/mount_flags.perf"
  { "rnorelatime", 1, MS_RELATIME, OPTION_RECURSIVE },
#line 56 "src/libcrun/mount_flags.perf"
  { "nodiratime", 0, MS_NODIRATIME, 0 },
#line 85 "src/libcrun/mount_flags.perf"
  { "rnodiratime", 0, MS_NODIRATIME, OPTION_RECURSIVE },
#line 55 "src/libcrun/mount_flags.perf"
  { "diratime", 1, MS_NODIRATIME, 0 },
#line 83 "src/libcrun/mount_flags.perf"
  { "rnoatime", 0, MS_NOATIME, OPTION_RECURSIVE },
#line 81 "src/libcrun/mount_flags.perf"
  { "rnomand", 1, MS_MANDLOCK, OPTION_RECURSIVE },
#line 82 "src/libcrun/mount_flags.perf"
  { "ratime", 1, MS_NOATIME, OPTION_RECURSIVE },
#line 80 "src/libcrun/mount_flags.perf"
  { "rmand", 0, MS_MANDLOCK, OPTION_RECURSIVE },
#line 51 "src/libcrun/mount_flags.perf"
  { "mand", 0, MS_MANDLOCK, 0 },
#line 91 "src/libcrun/mount_flags.perf"
  { "idmap", 0, 0, OPTION_IDMAP },
#line 54 "src/libcrun/mount_flags.perf"
  { "noatime", 0, MS_NOATIME, 0 },
#line 52 "src/libcrun/mount_flags.perf"
  { "nomand", 1, MS_MANDLOCK, 0 },
#line 49 "src/libcrun/mount_flags.perf"
  { "dirsync", 0, MS_DIRSYNC, 0 },
#line 72 "src/libcrun/mount_flags.perf"
  { "rnosuid", 0, MS_NOSUID, OPTION_RECURSIVE },
#line 53 "src/libcrun/mount_flags.perf"
  { "atime", 1, MS_NOATIME, 0 },
#line 76 "src/libcrun/mount_flags.perf"
  { "rnoexec", 0, MS_NOEXEC, OPTION_RECURSIVE },
#line 44 "src/libcrun/mount_flags.perf"
  { "nodev", 0, MS_NODEV, 0 },
#line 38 "src/libcrun/mount_flags.perf"
  { "rbind", 0, MS_REC | MS_BIND, 0 },
#line 58 "src/libcrun/mount_flags.perf"
  { "norelatime", 1, MS_RELATIME, 0 },
#line 37 "src/libcrun/mount_flags.perf"
  { "bind", 0, MS_BIND, 0 },
#line 89 "src/libcrun/mount_flags.perf"
  { "rnostrictatime", 1, MS_STRICTATIME, OPTION_RECURSIVE },
#line 59 "src/libcrun/mount_flags.perf"
  { "strictatime", 0, MS_STRICTATIME, 0 },
#line 88 "src/libcrun/mount_flags.perf"
  { "rstrictatime", 0, MS_STRICTATIME, OPTION_RECURSIVE },
#line 66 "src/libcrun/mount_flags.perf"
  { "rprivate", 0, MS_REC | MS_PRIVATE, 0 },
#line 71 "src/libcrun/mount_flags.perf"
  { "rsuid", 1, MS_NOSUID, OPTION_RECURSIVE },
#line 50 "src/libcrun/mount_flags.perf"
  { "remount", 0, MS_REMOUNT, 0 },
#line 41 "src/libcrun/mount_flags.perf"
  { "suid", 1, MS_NOSUID, 0 },
#line 60 "src/libcrun/mount_flags.perf"
  { "nostrictatime", 1, MS_STRICTATIME, 0 },
#line 86 "src/libcrun/mount_flags.perf"
  { "rrelatime", 0, MS_RELATIME, OPTION_RECURSIVE },
#line 42 "src/libcrun/mount_flags.perf"
  { "nosuid", 0, MS_NOSUID, 0 },
#line 46 "src/libcrun/mount_flags.perf"
  { "noexec", 0, MS_NOEXEC, 0 },
#line 64 "src/libcrun/mount_flags.perf"
  { "rslave", 0, MS_REC | MS_SLAVE, 0 },
#line 43 "src/libcrun/mount_flags.perf"
  { "dev", 1, MS_NODEV, 0 },
#line 73 "src/libcrun/mount_flags.perf"
  { "rdev", 1, MS_NODEV, OPTION_RECURSIVE },
#line 77 "src/libcrun/mount_flags.perf"
  { "rsync", 0, MS_SYNCHRONOUS, OPTION_RECURSIVE },
#line 57 "src/libcrun/mount_flags.perf"
  { "relatime", 0, MS_RELATIME, 0 },
#line 47 "src/libcrun/mount_flags.perf"
  { "sync", 0, MS_SYNCHRONOUS, 0 },
#line 61 "src/libcrun/mount_flags.perf"
  { "shared", 0, MS_SHARED, 0 },
#line 62 "src/libcrun/mount_flags.perf"
  { "rshared", 0, MS_REC | MS_SHARED, 0 },
#line 67 "src/libcrun/mount_flags.perf"
  { "unbindable", 0, MS_UNBINDABLE, 0 },
#line 68 "src/libcrun/mount_flags.perf"
  { "runbindable", 0, MS_REC | MS_UNBINDABLE, 0 },
#line 36 "src/libcrun/mount_flags.perf"
  { "defaults", 0, 0, 0 },
#line 48 "src/libcrun/mount_flags.perf"
  { "async", 1, MS_SYNCHRONOUS, 0 },
#line 78 "src/libcrun/mount_flags.perf"
  { "rasync", 1, MS_SYNCHRONOUS, OPTION_RECURSIVE },
#line 65 "src/libcrun/mount_flags.perf"
  { "private", 0, MS_PRIVATE, 0 },
#line 90 "src/libcrun/mount_flags.perf"
  { "tmpcopyup", 0, 0, OPTION_TMPCOPYUP },
#line 75 "src/libcrun/mount_flags.perf"
  { "rexec", 1, MS_NOEXEC, OPTION_RECURSIVE },
#line 45 "src/libcrun/mount_flags.perf"
  { "exec", 1, MS_NOEXEC, 0 },
#line 63 "src/libcrun/mount_flags.perf"
  { "slave", 0, MS_SLAVE, 0 }
};

const struct propagation_flags_s *
libcrun_mount_flag_in_word_set (register const char *str, register size_t len)
{
  if (len <= MAX_WORD_LENGTH && len >= MIN_WORD_LENGTH)
    {
      register unsigned int key = hash (str, len);

      if (key <= MAX_HASH_VALUE && key >= MIN_HASH_VALUE)
        {
          register const struct propagation_flags_s *resword;

          switch (key - 2)
            {
            case 0:
              resword = &wordlist[0];
              goto compare;
            case 1:
              resword = &wordlist[1];
              goto compare;
            case 4:
              resword = &wordlist[2];
              goto compare;
            case 5:
              resword = &wordlist[3];
              goto compare;
            case 9:
              resword = &wordlist[4];
              goto compare;
            case 10:
              resword = &wordlist[5];
              goto compare;
            case 11:
              resword = &wordlist[6];
              goto compare;
            case 13:
              resword = &wordlist[7];
              goto compare;
            case 15:
              resword = &wordlist[8];
              goto compare;
            case 16:
              resword = &wordlist[9];
              goto compare;
            case 17:
              resword = &wordlist[10];
              goto compare;
            case 18:
              resword = &wordlist[11];
              goto compare;
            case 19:
              resword = &wordlist[12];
              goto compare;
            case 20:
              resword = &wordlist[13];
              goto compare;
            case 21:
              resword = &wordlist[14];
              goto compare;
            case 23:
              resword = &wordlist[15];
              goto compare;
            case 24:
              resword = &wordlist[16];
              goto compare;
            case 25:
              resword = &wordlist[17];
              goto compare;
            case 26:
              resword = &wordlist[18];
              goto compare;
            case 27:
              resword = &wordlist[19];
              goto compare;
            case 28:
              resword = &wordlist[20];
              goto compare;
            case 29:
              resword = &wordlist[21];
              goto compare;
            case 30:
              resword = &wordlist[22];
              goto compare;
            case 31:
              resword = &wordlist[23];
              goto compare;
            case 32:
              resword = &wordlist[24];
              goto compare;
            case 33:
              resword = &wordlist[25];
              goto compare;
            case 34:
              resword = &wordlist[26];
              goto compare;
            case 35:
              resword = &wordlist[27];
              goto compare;
            case 36:
              resword = &wordlist[28];
              goto compare;
            case 37:
              resword = &wordlist[29];
              goto compare;
            case 38:
              resword = &wordlist[30];
              goto compare;
            case 39:
              resword = &wordlist[31];
              goto compare;
            case 40:
              resword = &wordlist[32];
              goto compare;
            case 41:
              resword = &wordlist[33];
              goto compare;
            case 42:
              resword = &wordlist[34];
              goto compare;
            case 43:
              resword = &wordlist[35];
              goto compare;
            case 44:
              resword = &wordlist[36];
              goto compare;
            case 45:
              resword = &wordlist[37];
              goto compare;
            case 46:
              resword = &wordlist[38];
              goto compare;
            case 47:
              resword = &wordlist[39];
              goto compare;
            case 48:
              resword = &wordlist[40];
              goto compare;
            case 49:
              resword = &wordlist[41];
              goto compare;
            case 50:
              resword = &wordlist[42];
              goto compare;
            case 51:
              resword = &wordlist[43];
              goto compare;
            case 52:
              resword = &wordlist[44];
              goto compare;
            case 53:
              resword = &wordlist[45];
              goto compare;
            case 54:
              resword = &wordlist[46];
              goto compare;
            case 55:
              resword = &wordlist[47];
              goto compare;
            case 56:
              resword = &wordlist[48];
              goto compare;
            case 57:
              resword = &wordlist[49];
              goto compare;
            case 58:
              resword = &wordlist[50];
              goto compare;
            case 59:
              resword = &wordlist[51];
              goto compare;
            case 60:
              resword = &wordlist[52];
              goto compare;
            case 61:
              resword = &wordlist[53];
              goto compare;
            case 63:
              resword = &wordlist[54];
              goto compare;
            case 67:
              resword = &wordlist[55];
              goto compare;
            }
          return 0;
        compare:
          {
            register const char *s = resword->name;

            if (*str == *s && ! strcmp (str + 1, s + 1))
              return resword;
          }
        }
    }
  return 0;
}
#line 92 "src/libcrun/mount_flags.perf"

const struct propagation_flags_s *
libcrun_str2mount_flags (const char *name)
{
  return libcrun_mount_flag_in_word_set (name, strlen (name));
}

const struct propagation_flags_s *
get_mount_flags_from_wordlist(void) {
  struct propagation_flags_s *flags;
  size_t i;
  size_t num_wordlist_flags = sizeof(wordlist) / sizeof(wordlist[0]);

  flags = xmalloc0 ((sizeof(struct propagation_flags_s) + 1) * num_wordlist_flags);

  for (i = 0; i < num_wordlist_flags; i++) {
    flags[i].name = wordlist[i].name;
  }

  return flags;
}
