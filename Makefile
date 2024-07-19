all:
	apxs -c -i -a src/mod_dp.c

install: all
	mkdir -p /usr/local/share/mod_dp/config
	cp config/mod_dp.conf /usr/local/share/mod_dp/config/
	mkdir -p debian
	cp postinst debian/
	chmod +x debian/postinst
	cp control debian/
	chmod +x debian/control
	cp copyright debian/
	chmod +x debian/copyright
	cp rules debian/
	chmod +x debian/rules
	cp changelog debian/
	chmod +x debian/changelog
	cp prerm debian/
	chmod +x debian/prerm


clean:
	rm -f *.so *.o