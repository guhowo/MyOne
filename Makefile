#one_src_files=$(shell echo ${wildcard *.c}|sed 's/selftest.c//g')
one_src_files=avl_local.c Poly1305.c Utils.c SHA512.c salsa20.c C25519.c  \
	InetAddress.c Address.c Identity.c Path.c Peer.c Packet.c Topology.c background.c \
	IncomingPacket.c jsondb.c NetworkController.c Dictionary.c Revocation.c\
	CertificateOfMembership.c  CertificateOfOwnership.c Capability.c Switch.c \
	Network.c Multicaster.c NetworkConfig.c Tag.c one.c
objects=$(patsubst %.c,%.o,$(one_src_files))
json_c_files=$(shell ls json/*.c)
json_h_files=$(shell ls json/*.h)
json_objects=$(patsubst %.c,%.o,$(json_c_files))
SUBDIRS=json

ifeq ($(ZT_DEBUG),1)
    CFLAGS = -g
endif

all:$(SUBDIRS) $(objects)
	cc $(CFLAGS) -o one  $(objects) $(json_objects)
$(SUBDIRS):ECHO
	make -C $@
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
InetAddress.o:InetAddress.c Buffer.h
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
Topology.o:Topology.c list.h Buffer.h InetAddress.h Peer.h World.h Address.h Identity.h Topology.h 	
	cc $(CFLAGS) -c $^
Switch.o:Switch.c
	cc $(CFLAGS) -c $^
jsondb.o:jsondb.c list.h avl_local.h InetAddress.h Address.h ./json/json.h
	cc $(CFLAGS) -c $^ -I./json
CertificateOfMembership.o:CertificateOfMembership.c Buffer.h Utils.h Address.h  Identity.h CertificateOfMembership.h
	cc $(CFLAGS) -c $^
CertificateOfOwnership.o:CertificateOfOwnership.c Constants.h C25519.h Buffer.h Address.h  Identity.h CertificateOfOwnership.h
	cc $(CFLAGS) -c $^
Revocation.o:Revocation.c Constants.h ZeroTierOne.h C25519.h Buffer.h Address.h Revocation.h
	cc $(CFLAGS) -c $^
Capability.o:Capability.c Constants.h ZeroTierOne.h C25519.h Buffer.h Address.h Identity.h Capability.h
	cc $(CFLAGS) -c $^
Tag.o:Tag.c Constants.h ZeroTierOne.h C25519.h Buffer.h Address.h Tag.h
	cc $(CFLAGS) -c $^
Dictionary.o:Dictionary.c
	cc $(CFLAGS) -c $^ -I./json
NetworkConfig.o:NetworkConfig.c NetworkConfig.h
	cc $(CFLAGS) -c $^
Network.o:Network.c
	cc $(CFLAGS) -c $^
Multicaster.o:Multicaster.c Multicaster.h Network.h
	cc $(CFLAGS) -c $^
NetworkController.o:NetworkController.c list.h ./json/json.h NetworkController.h NetworkConfig.h
	cc $(CFLAGS) -c $^ -I./json
IncomingPacket.o:IncomingPacket.c IncomingPacket.h Version.h Path.h Network.h
	cc $(CFLAGS) -c $^
background.o:background.c list.h RuntimeEnvironment.h Utils.h InetAddress.h Identity.h World.h Topology.h Packet.h background.h
	cc $(CFLAGS) -c $^
one.o:one.c avl_local.h Utils.h Address.h Identity.h RuntimeEnvironment.h Topology.h IncomingPacket.h Path.h
	cc $(CFLAGS) -c $^

ECHO:
	@echo $(SUBDIRS)

.PHONY: clean
clean:
	@rm -rf *.o *.gch one selftest
	@rm -rf $(SUBDIRS)/*.o $(SUBDIRS)/*.gch

selftest:C25519.c  Poly1305.c  salsa20.c  selftest.c  SHA512.c  Utils.c
	gcc $^ -o $@
