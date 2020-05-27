# libdkim_for_openssl1.1
libdkim library for OpenSSL 1.1

The branch of the libdkim library written by Alt-N DKIM Open Source Project 
with the patches required to run OpenSSL 1.1 
in FreeBSD operating system.

-------------------
1.0.0 May 27, 2020
-------------------
  o initial release


This library implements DKIM (DomainKeys Identified Mail).  The
internet drafts are available here:

http://www.ietf.org/internet-drafts/draft-allman-dkim-base-01.txt
http://www.ietf.org/internet-drafts/draft-allman-dkim-ssp-01.txt
http://www.ietf.org/internet-drafts/draft-fenton-dkim-threats-01.txt


Build Instructions
------------------

You must have OpenSSL and gmake installed and built.

For FreeBSD,
  - cd ~/libdkim-patched/src
  - Run "gmake"


Usage
-------

See https://www.syslogs.org/qmail-giden-postalar-icin-dkim-implementasyonu/
for libdkim library usage on FreeBSD+Qmail, Author Cagri Ersen.
