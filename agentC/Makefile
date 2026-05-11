CC = gcc
CFLAGS = -Wall -Wextra -std=c11
LDFLAGS = -lm -lcrypto

OBJS = main.o processAgent.o funtions.o
TARGET = anomaly_detection_agent

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean