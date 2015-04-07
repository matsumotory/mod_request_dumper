##
##  Makefile -- Build procedure for sample mod_request_dumper Apache module
##	  MATSUMOTO, Ryosuke
##

# target module source
TARGET=mod_request_dumper.c

#   the used tools
APXS=apxs
APACHECTL=/etc/init.d/httpd
#APXS=/usr/local/apache2.4/bin/apxs
#APACHECTL=/usr/local/apache2.4/bin/apachectl

#   additional user defines, includes and libraries
#DEF=-DSYSLOG_NAMES
INC=-I /usr/include/json
LIB=-lm /usr/lib/libjson.la
WC=-Wc,-std=c99

#   the default target
all: mod_request_dumper.so

#   compile the DSO file
mod_request_dumper.so: $(TARGET)
	$(APXS) -c $(DEF) $(INC) $(LIB) $(WC) $(TARGET)

#   install the DSO file into the Apache installation
#   and activate it in the Apache configuration
install: all
	$(APXS) -i -a -n 'request_dumper' .libs/mod_request_dumper.so

#   cleanup
clean:
	-rm -rf .libs *.o *.so *.lo *.la *.slo *.loT

#   reload the module by installing and restarting Apache
reload: install restart

#   the general Apache start/restart/stop procedures
start:
	$(APACHECTL) start
restart:
	$(APACHECTL) restart
stop:
	$(APACHECTL) stop

