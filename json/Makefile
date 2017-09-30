CUR_SOURCE=${wildcard *.c}
CUR_OBJS=${patsubst %.c, %.o, $(CUR_SOURCE)}
all:$(SUBDIRS) $(CUR_OBJS)

#ifeq ($(ZT_DEBUG),1)
    CFLAGS = -g -O0
#endif

$(CUR_OBJS):%.o:%.c
	$(CC) $(CFLAGS) -c $^ -o $@
