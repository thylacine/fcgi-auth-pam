# fcgi auth pam

## why
This was originally created as a workaround to the generally-unlikely case of
needing [Nginx](http://nginx.org/) to perform authentication via PAM as a
separate process, possibly as a different user, similar to how
[Apache](http://httpd.apache.org/)'s
[mod_authnz_external](https://code.google.com/p/mod-auth-external/) might be
used with [pwauth](https://code.google.com/p/pwauth/).

## what
This is a simple PAM authentication interface (harvested from a variety of
mod_pam-style sources), wrapped up behind [libfcgi](http://www.fastcgi.com/).
The primary intent is for it to get invoked as an internal location via an
auth_request during the course of handling a query.

## how
Have libfcgi installed, tweak Makefile, build, invoke as fastcgi (perhaps
with [spawn-fcgi](http://redmine.lighttpd.net/projects/spawn-fcgi/wiki)).
