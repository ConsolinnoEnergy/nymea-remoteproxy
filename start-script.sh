#!/bin/bash

# nymea-remoteproxy does not import complete certificate chains.
if [ "$WORKAROUND_MISSING_LEAF_CERTIFICATE" == "yes" ]; then
	mkdir /workaround_missing_leaf_certificate
	csplit --elide-empty-files \
		--silent \
		--prefix /workaround_missing_leaf_certificate/tls \
		--suffix-format '_%01d.crt' \
		/ssl/tls.crt \
		'/-----BEGIN CERTIFICATE-----/' \
		'{*}'
fi

# disable debug logging for qt 5
export QT_LOGGING_RULES="*.debug=false"

nymea-remoteproxy -c /config/nymea-remoteproxy.conf -m
