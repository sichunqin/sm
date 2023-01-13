#ifndef __COMMON_H__
#define __COMMON_H__

#include <sbi/sbi_string.h>
#ifdef DEBUG
#define debug(format, ...) \
  sbi_printf ("[debug] " format " (%s:%d)\r\n", ## __VA_ARGS__, __FILE__, __LINE__)
#else
#define debug(format, ...) \
  ;
#endif

#define warn(format, ...) \
  sbi_printf ("[warn] " format " (%s:%d)\r\n", ## __VA_ARGS__, __FILE__, __LINE__)
#endif