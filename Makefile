#one_src_files=$(shell echo ${wildcard *.c}|sed 's/selftest.c//g')
one_src_files=avl_local.c Poly1305.c Utils.c SHA512.c salsa20.c C25519.c  \
	Address.c Identity.c Path.c Peer.c Packet.c Topology.c background.c \
	IncomingPacket.c \
	one.c
objects=$(patsubst %.c,%.o,$(one_src_files))

ifeq ($(ZT_DEBUG),1)
    CFLAGS = -g
endif

all:$(objects)
	cc $(CFLAGS) -o one  $(objects)
Poly1305.o:Poly1305.c Poly1305.h Constants.h
	cc $(CFLAGS) -c $^
Utils.o:Utils.c Utils.h salsa20.h
	cc $(CFLAGS) -c $^
avl_local.o:avl_local.c avl_local.h
	cc $(CFLAGS) -c $^
SHA512.o:SHA512.c SHA512.h Utils.h
	cc $(CFLAGS) -c $^
salsa20.o:salsa20.c salsa20.h Utils.h Constants.h
	cc $(CFLAGS) -c $^
C25519.o: C25519.c Constants.h C25519.h SHA512.h Utils.h
	cc $(CFLAGS) -c $^
Address.o:Address.c Address.h Buffer.h Utils.h
	cc $(CFLAGS) -c $^
Identity.o:Identity.c Constants.h Utils.h Address.h C25519.h SHA512.h Buffer.h Identity.h
	cc $(CFLAGS) -c $^
Path.o:Path.c InetAddress.h Peer.h Buffer.h Packet.h Path.h
	cc $(CFLAGS) -c $^
Peer.o:Peer.c avl_local.h C25519.h RuntimeEnvironment.h Packet.h Peer.h Identity.h
	cc $(CFLAGS) -c $^
Packet.o:Packet.c Constants.h Buffer.h InetAddress.h Address.h Peer.h Version.h salsa20.h RuntimeEnvironment.h Poly1305.h Packet.h
	cc $(CFLAGS) -c $^
IncomingPacket.o:IncomingPacket.c IncomingPacket.h Version.h Path.h
	cc $(CFLAGS) -c $^
Topology.o:Topology.c list.h Buffer.h InetAddress.h Peer.h World.h Address.h Identity.h Topology.h 	
	cc $(CFLAGS) -c $^
background.o:background.c list.h RuntimeEnvironment.h Utils.h InetAddress.h Identity.h World.h Topology.h Packet.h background.h
	cc $(CFLAGS) -c $^
one.o:one.c avl_local.h Utils.h Address.h Identity.h RuntimeEnvironment.h Topology.h IncomingPacket.h Path.h
	cc $(CFLAGS) -c $^

.PHONY: clean
clean:
	rm -rf *.o *.gch one selftest

selftest:C25519.c  Poly1305.c  salsa20.c  selftest.c  SHA512.c  Utils.c
	gcc $^ -o $@
