TARGET := rc4
BINDIR := bin
CWARNS := -Wall
CFLAGS := -std=gnu99 -Ofast
SOURCE := rc4.c main.c

all: $(BINDIR)/$(TARGET)

$(BINDIR)/$(TARGET): $(BINDIR) main.c rc4.c rc4.h
	@$(CC) $(CFLAGS) $(CWARNS) -o $@ main.c rc4.c
	@echo [$(CC)] $(CFLAGS) $@ main.c rc4.c

$(BINDIR):
	@mkdir $(BINDIR)

clean:
	@echo [rm] $(BINDIR)
	@rm -rf $(BINDIR) 2> /dev/null || true

.PHONY: clean
