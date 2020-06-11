
systemdsysdir = $(libdir)/systemd/system

systemdsys_DATA = service/proxifier.service
	
._service.service:
	$(SED) "s|BINDIR|$(DESTDIR)$(bindir)|g" $< > $@

