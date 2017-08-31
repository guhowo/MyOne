CUR_SOURCE=${wildcard *.c}
CUR_OBJS=${patsubst %.c, %.o, $(CUR_SOURCE)}
all:$(SUBDIRS) $(CUR_OBJS)
$(CUR_OBJS):%.o:%.c
	$(CC) $(CFLAGS) -c $^ -o $@
