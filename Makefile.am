AUTOMAKE_OPTIONS = -Wall -Werror foreign

EXTRA_DIST= \
			Authors.md \
			ChangeLog.md \
			proxifier.conf \
			README.md

distclean-local:
	rm -rf  *.m4
	rm -rf *.in~
	rm -rf autom4te.cache

re-install: uninstall install

include src/Makefile.am

include service/Makefile.am

sysconf_DATA = proxifier.conf 