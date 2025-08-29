# boost-version.mk
BOOST_MAKEFILE := $(firstword $(shell find -L $(TOPDIR) -type f -path "*/boost/Makefile"))

BOOST_PKG_VERSION := $(shell grep '^PKG_VERSION:=' $(BOOST_MAKEFILE) | head -n1 | cut -d= -f2)

BOOST_VER_MAJOR := $(word 1,$(subst ., ,$(BOOST_PKG_VERSION)))
BOOST_VER_MINOR := $(word 2,$(subst ., ,$(BOOST_PKG_VERSION)))
BOOST_VER_PATCH := $(word 3,$(subst ., ,$(BOOST_PKG_VERSION)))

BOOST_VERSION_CODE := $(shell echo $$(($(BOOST_VER_MAJOR)*100000 + $(BOOST_VER_MINOR)*100 + $(BOOST_VER_PATCH))))

NEED_BOOST_SYSTEM := $(if $(shell [ $(BOOST_VERSION_CODE) -ge 108900 ] && echo y),y,n)
