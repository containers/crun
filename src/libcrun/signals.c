/* ANSI-C code produced by gperf version 3.1 */
/* Command-line: gperf --lookup-function-name libcrun_signal_in_word_set -m 100 --null-strings --pic -tCEG -S1 src/libcrun/signals.perf  */
/* Computed positions: -k'2,4,$' */

#if !((' ' == 32) && ('!' == 33) && ('"' == 34) && ('#' == 35) \
      && ('%' == 37) && ('&' == 38) && ('\'' == 39) && ('(' == 40) \
      && (')' == 41) && ('*' == 42) && ('+' == 43) && (',' == 44) \
      && ('-' == 45) && ('.' == 46) && ('/' == 47) && ('0' == 48) \
      && ('1' == 49) && ('2' == 50) && ('3' == 51) && ('4' == 52) \
      && ('5' == 53) && ('6' == 54) && ('7' == 55) && ('8' == 56) \
      && ('9' == 57) && (':' == 58) && (';' == 59) && ('<' == 60) \
      && ('=' == 61) && ('>' == 62) && ('?' == 63) && ('A' == 65) \
      && ('B' == 66) && ('C' == 67) && ('D' == 68) && ('E' == 69) \
      && ('F' == 70) && ('G' == 71) && ('H' == 72) && ('I' == 73) \
      && ('J' == 74) && ('K' == 75) && ('L' == 76) && ('M' == 77) \
      && ('N' == 78) && ('O' == 79) && ('P' == 80) && ('Q' == 81) \
      && ('R' == 82) && ('S' == 83) && ('T' == 84) && ('U' == 85) \
      && ('V' == 86) && ('W' == 87) && ('X' == 88) && ('Y' == 89) \
      && ('Z' == 90) && ('[' == 91) && ('\\' == 92) && (']' == 93) \
      && ('^' == 94) && ('_' == 95) && ('a' == 97) && ('b' == 98) \
      && ('c' == 99) && ('d' == 100) && ('e' == 101) && ('f' == 102) \
      && ('g' == 103) && ('h' == 104) && ('i' == 105) && ('j' == 106) \
      && ('k' == 107) && ('l' == 108) && ('m' == 109) && ('n' == 110) \
      && ('o' == 111) && ('p' == 112) && ('q' == 113) && ('r' == 114) \
      && ('s' == 115) && ('t' == 116) && ('u' == 117) && ('v' == 118) \
      && ('w' == 119) && ('x' == 120) && ('y' == 121) && ('z' == 122) \
      && ('{' == 123) && ('|' == 124) && ('}' == 125) && ('~' == 126))
/* The character set is not based on ISO-646.  */
#error "gperf generated tables don't work with this execution character set. Please report a bug to <bug-gperf@gnu.org>."
#endif

#line 19 "src/libcrun/signals.perf"

#define _GNU_SOURCE

#include <config.h>
#include <stddef.h>
#include <stdlib.h>
#include "utils.h"
#line 27 "src/libcrun/signals.perf"
struct signal_s
{
  int name;
  int value;
};
enum
  {
    TOTAL_KEYWORDS = 62,
    MIN_WORD_LENGTH = 2,
    MAX_WORD_LENGTH = 8,
    MIN_HASH_VALUE = 13,
    MAX_HASH_VALUE = 86
  };

/* maximum key range = 74, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
static unsigned int
hash (register const char *str, register size_t len)
{
  static const unsigned char asso_values[] =
    {
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 43,  9,
       5, 17, 13, 31, 43, 40, 39, 34, 87, 87,
      87, 87, 87, 87, 87,  7, 60, 56, 32, 33,
      26, 39,  5,  5, 87, 87,  5, 23, 32, 27,
       6, 87, 30, 31,  6,  5, 16, 35, 49, 31,
      18, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87, 87, 87, 87, 87,
      87, 87, 87, 87, 87, 87
    };
  register unsigned int hval = len;

  switch (hval)
    {
      default:
        hval += asso_values[(unsigned char)str[3]];
      /*FALLTHROUGH*/
      case 3:
      case 2:
        hval += asso_values[(unsigned char)str[1]];
        break;
    }
  return hval + asso_values[(unsigned char)str[len - 1]];
}

struct stringpool_t
  {
    char stringpool_str0[sizeof("ILL")];
    char stringpool_str1[sizeof("HUP")];
    char stringpool_str2[sizeof("KILL")];
    char stringpool_str3[sizeof("TTOU")];
    char stringpool_str4[sizeof("QUIT")];
    char stringpool_str5[sizeof("STOP")];
    char stringpool_str6[sizeof("RTMIN+2")];
    char stringpool_str7[sizeof("RTMIN+12")];
    char stringpool_str8[sizeof("RTMAX-2")];
    char stringpool_str9[sizeof("RTMAX-12")];
    char stringpool_str10[sizeof("RTMIN+1")];
    char stringpool_str11[sizeof("RTMIN+11")];
    char stringpool_str12[sizeof("RTMAX-1")];
    char stringpool_str13[sizeof("RTMAX-11")];
    char stringpool_str14[sizeof("RTMIN+4")];
    char stringpool_str15[sizeof("RTMIN+14")];
    char stringpool_str16[sizeof("RTMAX-4")];
    char stringpool_str17[sizeof("RTMAX-14")];
    char stringpool_str18[sizeof("RTMIN+3")];
    char stringpool_str19[sizeof("RTMIN+13")];
    char stringpool_str20[sizeof("RTMAX-3")];
    char stringpool_str21[sizeof("RTMAX-13")];
    char stringpool_str22[sizeof("BUS")];
    char stringpool_str23[sizeof("VTALRM")];
    char stringpool_str24[sizeof("INT")];
    char stringpool_str25[sizeof("FPE")];
    char stringpool_str26[sizeof("CONT")];
    char stringpool_str27[sizeof("STKFLT")];
    char stringpool_str28[sizeof("USR2")];
    char stringpool_str29[sizeof("TRAP")];
    char stringpool_str30[sizeof("TSTP")];
    char stringpool_str31[sizeof("RTMIN")];
    char stringpool_str32[sizeof("RTMIN+5")];
    char stringpool_str33[sizeof("RTMIN+15")];
    char stringpool_str34[sizeof("RTMAX-5")];
    char stringpool_str35[sizeof("RTMIN+9")];
    char stringpool_str36[sizeof("USR1")];
    char stringpool_str37[sizeof("RTMAX-9")];
    char stringpool_str38[sizeof("ALRM")];
    char stringpool_str39[sizeof("IO")];
    char stringpool_str40[sizeof("RTMIN+8")];
    char stringpool_str41[sizeof("RTMIN+7")];
    char stringpool_str42[sizeof("RTMAX-8")];
    char stringpool_str43[sizeof("RTMAX-7")];
    char stringpool_str44[sizeof("RTMIN+6")];
    char stringpool_str45[sizeof("RTMIN+10")];
    char stringpool_str46[sizeof("RTMAX-6")];
    char stringpool_str47[sizeof("RTMAX-10")];
    char stringpool_str48[sizeof("SYS")];
    char stringpool_str49[sizeof("XFSZ")];
    char stringpool_str50[sizeof("RTMAX")];
    char stringpool_str51[sizeof("PWR")];
    char stringpool_str52[sizeof("SEGV")];
    char stringpool_str53[sizeof("XCPU")];
    char stringpool_str54[sizeof("WINCH")];
    char stringpool_str55[sizeof("URG")];
    char stringpool_str56[sizeof("CHLD")];
    char stringpool_str57[sizeof("TTIN")];
    char stringpool_str58[sizeof("PIPE")];
    char stringpool_str59[sizeof("ABRT")];
    char stringpool_str60[sizeof("TERM")];
    char stringpool_str61[sizeof("PROF")];
  };
static const struct stringpool_t stringpool_contents =
  {
    "ILL",
    "HUP",
    "KILL",
    "TTOU",
    "QUIT",
    "STOP",
    "RTMIN+2",
    "RTMIN+12",
    "RTMAX-2",
    "RTMAX-12",
    "RTMIN+1",
    "RTMIN+11",
    "RTMAX-1",
    "RTMAX-11",
    "RTMIN+4",
    "RTMIN+14",
    "RTMAX-4",
    "RTMAX-14",
    "RTMIN+3",
    "RTMIN+13",
    "RTMAX-3",
    "RTMAX-13",
    "BUS",
    "VTALRM",
    "INT",
    "FPE",
    "CONT",
    "STKFLT",
    "USR2",
    "TRAP",
    "TSTP",
    "RTMIN",
    "RTMIN+5",
    "RTMIN+15",
    "RTMAX-5",
    "RTMIN+9",
    "USR1",
    "RTMAX-9",
    "ALRM",
    "IO",
    "RTMIN+8",
    "RTMIN+7",
    "RTMAX-8",
    "RTMAX-7",
    "RTMIN+6",
    "RTMIN+10",
    "RTMAX-6",
    "RTMAX-10",
    "SYS",
    "XFSZ",
    "RTMAX",
    "PWR",
    "SEGV",
    "XCPU",
    "WINCH",
    "URG",
    "CHLD",
    "TTIN",
    "PIPE",
    "ABRT",
    "TERM",
    "PROF"
  };
#define stringpool ((const char *) &stringpool_contents)

static const struct signal_s wordlist[] =
  {
#line 36 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str0, 4},
#line 33 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str1, 1},
#line 41 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str2, 9},
#line 54 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str3, 22},
#line 35 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str4, 3},
#line 51 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str5, 19},
#line 66 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str6, 36},
#line 76 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str7, 46},
#line 92 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str8, 62},
#line 82 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str9, 52},
#line 65 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str10, 35},
#line 75 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str11, 45},
#line 93 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str12, 63},
#line 83 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str13, 53},
#line 68 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str14, 38},
#line 78 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str15, 48},
#line 90 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str16, 60},
#line 80 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str17, 50},
#line 67 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str18, 37},
#line 77 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str19, 47},
#line 91 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str20, 61},
#line 81 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str21, 51},
#line 39 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str22, 7},
#line 58 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str23, 26},
#line 34 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str24, 2},
#line 40 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str25, 8},
#line 50 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str26, 18},
#line 48 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str27, 16},
#line 44 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str28, 12},
#line 37 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str29, 5},
#line 52 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str30, 20},
#line 64 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str31, 34},
#line 69 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str32, 39},
#line 79 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str33, 49},
#line 89 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str34, 59},
#line 73 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str35, 43},
#line 42 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str36, 10},
#line 85 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str37, 55},
#line 46 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str38, 14},
#line 61 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str39, 29},
#line 72 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str40, 42},
#line 71 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str41, 41},
#line 86 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str42, 56},
#line 87 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str43, 57},
#line 70 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str44, 40},
#line 74 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str45, 44},
#line 88 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str46, 58},
#line 84 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str47, 54},
#line 63 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str48, 31},
#line 57 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str49, 25},
#line 94 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str50, 64},
#line 62 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str51, 30},
#line 43 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str52, 11},
#line 56 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str53, 24},
#line 60 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str54, 28},
#line 55 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str55, 23},
#line 49 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str56, 17},
#line 53 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str57, 21},
#line 45 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str58, 13},
#line 38 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str59, 6},
#line 47 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str60, 15},
#line 59 "src/libcrun/signals.perf"
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str61, 27}
  };

const struct signal_s *
libcrun_signal_in_word_set (register const char *str, register size_t len)
{
  if (len <= MAX_WORD_LENGTH && len >= MIN_WORD_LENGTH)
    {
      register unsigned int key = hash (str, len);

      if (key <= MAX_HASH_VALUE && key >= MIN_HASH_VALUE)
        {
          register const struct signal_s *resword;

          switch (key - 13)
            {
              case 0:
                resword = &wordlist[0];
                goto compare;
              case 1:
                resword = &wordlist[1];
                goto compare;
              case 6:
                resword = &wordlist[2];
                goto compare;
              case 7:
                resword = &wordlist[3];
                goto compare;
              case 8:
                resword = &wordlist[4];
                goto compare;
              case 9:
                resword = &wordlist[5];
                goto compare;
              case 10:
                resword = &wordlist[6];
                goto compare;
              case 11:
                resword = &wordlist[7];
                goto compare;
              case 12:
                resword = &wordlist[8];
                goto compare;
              case 13:
                resword = &wordlist[9];
                goto compare;
              case 14:
                resword = &wordlist[10];
                goto compare;
              case 15:
                resword = &wordlist[11];
                goto compare;
              case 16:
                resword = &wordlist[12];
                goto compare;
              case 17:
                resword = &wordlist[13];
                goto compare;
              case 18:
                resword = &wordlist[14];
                goto compare;
              case 19:
                resword = &wordlist[15];
                goto compare;
              case 20:
                resword = &wordlist[16];
                goto compare;
              case 21:
                resword = &wordlist[17];
                goto compare;
              case 22:
                resword = &wordlist[18];
                goto compare;
              case 23:
                resword = &wordlist[19];
                goto compare;
              case 24:
                resword = &wordlist[20];
                goto compare;
              case 25:
                resword = &wordlist[21];
                goto compare;
              case 26:
                resword = &wordlist[22];
                goto compare;
              case 27:
                resword = &wordlist[23];
                goto compare;
              case 28:
                resword = &wordlist[24];
                goto compare;
              case 29:
                resword = &wordlist[25];
                goto compare;
              case 30:
                resword = &wordlist[26];
                goto compare;
              case 31:
                resword = &wordlist[27];
                goto compare;
              case 32:
                resword = &wordlist[28];
                goto compare;
              case 33:
                resword = &wordlist[29];
                goto compare;
              case 34:
                resword = &wordlist[30];
                goto compare;
              case 35:
                resword = &wordlist[31];
                goto compare;
              case 36:
                resword = &wordlist[32];
                goto compare;
              case 37:
                resword = &wordlist[33];
                goto compare;
              case 38:
                resword = &wordlist[34];
                goto compare;
              case 39:
                resword = &wordlist[35];
                goto compare;
              case 40:
                resword = &wordlist[36];
                goto compare;
              case 41:
                resword = &wordlist[37];
                goto compare;
              case 42:
                resword = &wordlist[38];
                goto compare;
              case 43:
                resword = &wordlist[39];
                goto compare;
              case 44:
                resword = &wordlist[40];
                goto compare;
              case 45:
                resword = &wordlist[41];
                goto compare;
              case 46:
                resword = &wordlist[42];
                goto compare;
              case 47:
                resword = &wordlist[43];
                goto compare;
              case 48:
                resword = &wordlist[44];
                goto compare;
              case 49:
                resword = &wordlist[45];
                goto compare;
              case 50:
                resword = &wordlist[46];
                goto compare;
              case 51:
                resword = &wordlist[47];
                goto compare;
              case 52:
                resword = &wordlist[48];
                goto compare;
              case 53:
                resword = &wordlist[49];
                goto compare;
              case 54:
                resword = &wordlist[50];
                goto compare;
              case 55:
                resword = &wordlist[51];
                goto compare;
              case 56:
                resword = &wordlist[52];
                goto compare;
              case 57:
                resword = &wordlist[53];
                goto compare;
              case 58:
                resword = &wordlist[54];
                goto compare;
              case 59:
                resword = &wordlist[55];
                goto compare;
              case 60:
                resword = &wordlist[56];
                goto compare;
              case 61:
                resword = &wordlist[57];
                goto compare;
              case 62:
                resword = &wordlist[58];
                goto compare;
              case 63:
                resword = &wordlist[59];
                goto compare;
              case 70:
                resword = &wordlist[60];
                goto compare;
              case 73:
                resword = &wordlist[61];
                goto compare;
            }
          return 0;
        compare:
          {
            register const char *s = resword->name + stringpool;

            if (*str == *s && !strcmp (str + 1, s + 1))
              return resword;
          }
        }
    }
  return 0;
}
#line 95 "src/libcrun/signals.perf"

int
str2sig (const char *name)
{
  const struct signal_s *s;

  if (has_prefix (name, "SIG"))
    name += 3;

  s = libcrun_signal_in_word_set (name, strlen (name));
  if (s == NULL)
    {
      long int value;

      errno = 0;
      value = strtol (name, NULL, 10);
      if (errno == 0)
        return value;

      errno = ENOENT;
      return -1;
    }

  return s->value;
}
