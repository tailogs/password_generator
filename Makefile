CC       = gcc
CFLAGS   = -Wall -Wextra -O2 -Wno-cast-function-type
LDFLAGS  = -mwindows
LDLIBS   = -lbcrypt -luser32 -lgdi32 -lshell32

TARGET   = password_generator.exe
OBJS     = main.o resource.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

main.o: main.c resource.h
	$(CC) $(CFLAGS) -c main.c -o $@

resource.o: resource.rc resource.h
	windres resource.rc -O coff -o resource.o

clean:
	del /Q $(OBJS) $(TARGET) 2>nul || rm -f $(OBJS) $(TARGET)

.PHONY: all clean