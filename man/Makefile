PREFIX ?= /usr/local
MANDIR ?= $(PREFIX)/share/man
PYTHON ?= python3

.PHONY: check install
check:
	$(PYTHON) check.py

install:
	install -d "$(DESTDIR)$(MANDIR)/man3" "$(DESTDIR)$(MANDIR)/man7"
	install -m 644 man3/*.3 "$(DESTDIR)$(MANDIR)/man3/"
	install -m 644 man7/*.7 "$(DESTDIR)$(MANDIR)/man7/"
