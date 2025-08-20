dnl Check to find the PolarSSL headers/libraries

AC_DEFUN([ss_POLARSSL],
[

  AC_ARG_WITH(polarssl,
    AS_HELP_STRING([--with-polarssl=DIR], [PolarSSL base directory, or:]),
    [polarssl="$withval"
     CFLAGS="$CFLAGS -I$withval/include"
     LDFLAGS="$LDFLAGS -L$withval/lib"]
  )

  AC_ARG_WITH(polarssl-include,
    AS_HELP_STRING([--with-polarssl-include=DIR], [PolarSSL headers directory (without trailing /polarssl)]),
    [polarssl_include="$withval"
     CFLAGS="$CFLAGS -I$withval"]
  )

  AC_ARG_WITH(polarssl-lib,
    AS_HELP_STRING([--with-polarssl-lib=DIR], [PolarSSL library directory]),
    [polarssl_lib="$withval"
     LDFLAGS="$LDFLAGS -L$withval"]
  )

  AC_CHECK_LIB(polarssl, cipher_init_ctx,
    [LIBS="-lpolarssl $LIBS"],
    [AC_MSG_ERROR([PolarSSL libraries not found.])]
  )

  AC_MSG_CHECKING([polarssl version])
  AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM(
      [[
#include <polarssl/version.h>
      ]],
      [[
#if POLARSSL_VERSION_NUMBER < 0x01020500
#error invalid version
#endif
      ]]
    )],
    [AC_MSG_RESULT([ok])],
    [AC_MSG_ERROR([PolarSSL 1.2.5 or newer required])]
  )
])
