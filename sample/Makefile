# capstone library name (without prefix 'lib' and suffix '.so')
LIBNAME = capstone

captest: captest.o elftool.o

	#這樣就解掉了...
	#我猜-L就是指向library的所在位址
	#-Ldir
        # Add directory dir to the list of directories to be searched for -l.
	#${CC} $< -O3 -lelf -Wall -L../../../capstone/capstone -l$(LIBNAME) -o $@
	${CC} captest.o elftool.o -O3 -lelf -Wall -L../../../capstone/capstone -l$(LIBNAME) -o $@
	#${CC} $< -O3 -Wall  -l$(LIBNAME) -o $@

%.o: %.c
	${CC} -c $< -o $@
