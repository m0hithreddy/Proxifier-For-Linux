AUTOMAKE_OPTIONS = -Wall -Werror foreign

EXTRA_DIST= \
			Authors.md \
			ChangeLog.md \
			proxifier.conf \
			README.md

clean-local:
	rm -f service/*.service
	rm -f doc/*.1
	
distclean-local:
	rm -rf  *.m4
	rm -rf *.in~
	rm -rf autom4te.cache

re-install: uninstall install

include src/Makefile.am

include service/Makefile.am

sysconf_DATA = proxifier.conf 

if TXT2MAN
include doc/Makefile.am
endif