#!/bin/bash
[ "$DKSIGN" ] || DKSIGN="/etc/domainkeys/%/default"
[ "$DKREMOTE" ] || DKREMOTE="/var/qmail/bin/qmail-remote.orig" 
if [[ $DKSIGN == *%* ]] ; then
	DOMAIN=${2##*@}
	DKSIGN="${DKSIGN%%%*}${DOMAIN}${DKSIGN#*%}"
fi
if [ -f "$DKSIGN" ] ; then
        tmp=`mktemp -t dkim.sign.XXXXXXXXXXXXXXX`
	tmp2=`mktemp -t dkim.sign.XXXXXXXXXXXXXXX`
        cat - >"$tmp"
        /usr/local/bin/libdkimtest -ydefault -s "$tmp" "$DKSIGN" "$tmp2" 2>/dev/null
        (cat "$tmp.signed" | /bin/sed 's/; d=.*;/; d='"$DOMAIN"';/';) | \
            "$DKREMOTE" "$@"
        retval=$?
        rm "$tmp" "$tmp2"
        exit $retval
else
        exec "$DKREMOTE" "$@"
fi
