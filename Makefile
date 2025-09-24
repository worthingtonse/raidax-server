BINARY_NAME := raidax_server
CC = gcc
BUILD_DIR = ./build
DST_FOLDER = /opt/raidax
LIBS = -lpthread -lmysqlclient -lm -lcrypto 
CFLAGS = -g

BUILD_TIME = $(shell date -u +"%Y-%m-%d-%H:%M:%S")

.PHONY: clean install

SRCS := $(wildcard *.c)
SRCS += $(wildcard legacycc/*.c)
SRCS += $(wildcard cc2/*.c)
ASMSRCS := $(wildcard asm/*.s)

OBJS := $(SRCS:%.c=$(BUILD_DIR)/%.o)
ASMOBJS := $(ASMSRCS:asm/%.s=$(BUILD_DIR)/%.o)
DEPS := $(OBJS:%.o=%.d)



all: clean prep $(BUILD_DIR)/$(BINARY_NAME)
	echo "Compiled"

prep:
	@mkdir -p $(BUILD_DIR)/cc2
	@mkdir -p $(BUILD_DIR)/legacycc

clean:
	rm -f $(OBJS) $(BINARY_NAME)
	echo "Clean Done"

install:
	@mkdir -p $(DST_FOLDER)/bin
	install $(BUILD_DIR)/$(BINARY_NAME) $(DST_FOLDER)
	install config.toml $(DST_FOLDER)

update:
	systemctl stop raidax_server
	install $(BUILD_DIR)/$(BINARY_NAME) $(DST_FOLDER)
	systemctl start raidax_server


-include $(DEPS)

$(BUILD_DIR)/$(BINARY_NAME): $(OBJS) $(ASMOBJS)
	$(CC) -D__BUILD_TIME=\"$(BUILD_TIME)\" $(CFLAGS) -O2 $^ $(LIBS) -o $@


$(BUILD_DIR)/%.o: asm/%.s
	yasm -D__linux__ -f elf64 $< -o $@

$(BUILD_DIR)/%.o: %.c
	echo $(OBJS)
	$(CC) -D__BUILD_TIME=\"$(BUILD_TIME)\" $(CFLAGS) -MMD -c $< -o $@

deploy2:
	rsync -e 'ssh -p 8022' -avz . root@dev2:/root/g/raidax
	ssh -p 8022 root@dev2 'cd /root/g/raidax && make clean && make && for i in 13 17 21; do systemctl stop raidax@$$i; cp build/raidax_server /opt/raidax/raida$$i/; done'
	ssh -p 8022 root@dev2 'for i in 13 17 21; do systemctl start raidax@$$i; done'
#	ssh -p 8022 root@dev2 'for i in 13 17 21 22; do systemctl start raidax@$$i; done'

#	ssh -p 8022 root@dev2 'for i in 13 17 21 22; do systemctl stop raidax@$$i; done'
#	ssh -p 8022 root@dev2 'for i in 13 17 21 22; do cp /root/raidax_server /opt/raidax/raida$$i/; done'

deploy:
	scp -P 88 build/raidax_server root@dev:~
	ssh -p 88 root@dev 'for i in `seq 0 24`; do systemctl stop raidax@$$i; done'
	ssh -p 88 root@dev 'for i in `seq 0 24`; do cp /root/raidax_server /opt/raidax/raida$$i/; done'
	ssh -p 88 root@dev 'for i in `seq 0 24`; do systemctl start raidax@$$i; done'



