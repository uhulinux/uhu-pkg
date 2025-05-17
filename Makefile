uhu-stat: uhu-stat.c
	gcc -Wall -o uhu-stat uhu-stat.c

install: uhu-stat
	install -m 755 uhu-stat $(DESTDIR)/usr/bin/
	install -m 755 uhu-pkg* $(DESTDIR)/usr/sbin/

clean:
	rm -rf uhu-pkg

