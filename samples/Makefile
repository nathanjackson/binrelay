SAMPLES := $(basename $(wildcard *.c))

all: $(SAMPLES)

%: %.c
	gcc $@.c -o $@ -pthread

clean:
	rm -f $(SAMPLES)