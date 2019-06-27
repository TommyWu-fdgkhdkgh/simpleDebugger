CC = gcc


all:	sdb

sdb:	main.o elftool.o elftool.h
	cc  main.o elftool.o -lelf -L../../capstone/capstone -lcapstone  -o sdb
	@#cc  main.o elftool.o  -lcapstone -lelf  -o sdb
	@#cc  -lelf -L../../capstone/capstone -lcapstone main.o elftool.o 不知道為什麼，.o檔放後面就是不行


%.o: %.c
	cc -c $< -o $@

clean:	
	rm -f sdb main.o elftool.o 


