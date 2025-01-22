CC = gcc
CFLAGS = -Wall -Wextra -g -I./include
SRCS = src/sqwatch.c src/sqwatch_utils.c src/diff.c src/cache.c
OBJS = $(SRCS:.c=.o)
TARGET = sqwatch

all: $(TARGET)
	
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET)
	
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
	
clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
