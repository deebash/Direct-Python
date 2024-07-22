# Command to build, install and activate the module
# apxs -c -i -a src/mod_dp.c but for current deb package
# we're using apxs -c src/mod_dp.c
all:
	apxs -c src/mod_dp.c

#clean:
#	rm -f *.so *.o