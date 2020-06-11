dist_man_MANS = doc/proxifier.1

PACKAGE_DESC = Proxifier-For-Linux

.txt.1:
	$$(txt2man \
		   -t $$(echo $$(echo $< | sed 's/.txt.*//').1) \
		   -v ${PACKAGE_NAME}-${PACKAGE_VERSION} \
		   -s 1 \
		   -P ${PACKAGE_NAME} \
		   -v ${PACKAGE_DESC} \
		   $< > $$(echo $$(echo $< | sed 's/.txt.*//').1))
