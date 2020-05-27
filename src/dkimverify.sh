#!/bin/sh
    [ "$DKIMQUEUE" ] || DKQUEUE="/var/qmail/bin/qmail-queue"
    if printenv | grep -q '^DKIMVERIFY=' ; then
        tmp=`mktemp -t dkim.verify.XXXXXXXXXXXXXXX`
        cat - >"$tmp"
        ( [ "$(/usr/local/bin/libdkimtest -v <"$tmp" 2>/dev/null | grep "Success")" != "" ] && echo -e -n "DKIM-Status: good\r\n" ) |
         /bin/cat - "$tmp" | \
            $DKQUEUE
        retval=$?
        rm "$tmp"
        exit $retval
    else
        exec $DKQUEUE
    fi 
