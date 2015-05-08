#CPPFLAGS += -I/opt/local/include
#LDFLAGS += -L/opt/local/lib
CFLAGS ?= -g -Wall -Wextra
LIBS = -lpthread -lpam -lfcgi
TARGET = fcgi_auth_pam

.PHONY: clean

$(TARGET): fcgi_auth_pam.o base64.o
	$(CC) -o $@ $(LDFLAGS) $^ $(LIBS)

clean:	
	rm -f *.o $(TARGET)
