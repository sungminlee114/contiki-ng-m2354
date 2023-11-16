
# ifndef APP
# $(error APP is not set. Use 'make APP=value')
# endif

APP=client
# ifeq ($(APP), client)
CFLAGS += -DAPP_CLIENT
CONTIKI_PROJECT = xbee-client

DEPS = project-conf.h
SOURCEFILES = slip-net.c
# CFLAGS += -DUSE_FDTLS

# else ifeq ($(APP),server)
# CFLAGS += -DAPP_SERVER
# CONTIKI_PROJECT = xbee-server
# else
# $(error Invalid APP value. Use 'make APP=client' or 'make APP=server')
# endif

ifndef TARGET
$(warning "No TARGET. Using TARGET=native!!")
TARGET=native
endif

ifeq ($(TARGET),m2354)
BOARD=ASM2
NS=1
CFLAGS += -DTARGET_M2354=1
DEPS += meterif_data.h adc_data.h
SOURCEFILES += meterif_data.c adc_data.c
else ifeq ($(TARGET),native)
DEPS += xbee-driver.h
SOURCEFILES += xbee-driver.c
CFLAGS += -DTARGET_NATIVE=1
else
$(error Invalid TARGET value. Use 'make TARGET=m2354' or 'make TARGET=native')
endif

all: $(CONTIKI_PROJECT) $(DEPS)


CONTIKI=../..

ifeq ($(FDTLS),1)
$(info "Using FDTLS")
MODULES += os/net/security/tinydtls
MODULES += os/net/security/tinydtls/sha2
MODULES += os/net/security/tinydtls/aes
MODULES += os/net/security/tinydtls/ecc
MODULES += os/net/security/tinydtls/contiki-support
else
$(info "Not using FDTLS")
endif

PROJECT_SOURCEFILES += $(SOURCEFILES)

MAKE_NET = MAKE_NET_IPV6
MAKE_MAC = MAKE_MAC_NULLMAC

include $(CONTIKI)/Makefile.include