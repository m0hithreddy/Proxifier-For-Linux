
systemdsysdir = $(libdir)/systemd/system

systemdsys_DATA = service/proxifier.service

clean-local:
	rm service/*.service
	
._service.service:
	$(SED) "s|BINDIR|$(DESTDIR)$(bindir)|g" $< > $@

