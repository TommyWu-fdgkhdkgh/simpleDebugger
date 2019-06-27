#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <assert.h>
#include <capstone/capstone.h>
#include <capstone/platform.h>
#include <signal.h>

#include "elftool.h"

#define MAXARGS 10
#define PEEKSIZE 8
#define MAXBPS 100

char *help_str = "- break {instruction-address}: add a break point\n" \
		"- cont: continue execution\n" \
		"- delete {break-point-id}: remove a break point\n" \
		"- disasm addr: disassemble instructions in a file or a memory region\n" \
		"- dump addr [length]: dump memory content" \
		"- exit: terminate the debugger\n" \
		"- get reg: get a single value from a register\n" \
		"- getregs: show registers\n" \
		"- help: show this message\n" \
		"- list: list break points\n" \
		"- load {path/to/a/program}: load a program\n" \
		"- run: run the program\n" \
		"- vmmap: show memory layout\n" \
		"- set reg val: get a single value to a register\n" \
		"- si: step into instruction\n" \
		"- start: start the program and stop at the first instruction\n";


typedef struct BreakPoint{
	int valid;
	unsigned long long addr;
	unsigned long long base_addr;
	unsigned long long original_code;
}BP;

void user_input(char buf[]);
void parse_argv(char *buf_ptr, char *argv[], int *argc);
int  load_program(char *program_name, elf_handle_t **eh_ptr, elf_strtab_t **tab);
void handle_after_brkp(int* brk_index, pid_t child_pid, BP[]);
void handle_after_brkp_si(int* brk_index, pid_t child_pid, BP[]);
int program_is_load(char *program_name);
int program_is_run(pid_t child_pid);
void patch_brkp(pid_t child_pid, BP bps[]);
void fix_bps(BP bps[], pid_t child_pid);

void f_exit(elf_handle_t *eh);
void f_help();
void f_break(char **argv, int argc, BP bps[], pid_t child_pid, char *program_name, int *bps_index, elf_handle_t *eh, elf_strtab_t *tab);
int f_cont(char **program_name, pid_t *child_pid, int *brk_index, BP bps[], elf_handle_t *eh, csh *cshandle_ptr, unsigned long long *addr_offset_ptr);
void f_delete(char **argv, int argc, BP bps[], pid_t child_pid);
void f_disasm(char **argv, int argc, pid_t child_pid,char *program_name, elf_handle_t *eh, elf_strtab_t *tab, unsigned long long *last_dis_addr_ptr, csh *cshandle_ptr, int *dis_flag_ptr, BP bps[]);
void f_dump(char **argv, int argc, char *program_name, pid_t child_pid, int *dump_flag_ptr, unsigned long long *last_addr_ptr);
void f_get(char **argv, int argc, char *program_name, pid_t child_pid);
void f_getregs(char **argv, int argc, char *program_name, pid_t child_pid);
void f_list(BP bps[]); 
void f_load(char **argv, int argc, elf_handle_t **eh_ptr, elf_strtab_t **tab_ptr, char **program_name_ptr);
void f_run(char **program_name_ptr, pid_t *child_pid_ptr, int *brk_index_ptr, BP bps[], elf_handle_t *eh, csh *cshandle_ptr, unsigned long long *addr_offset_ptr);
void f_vmmap(char *program_name, pid_t child_pid, elf_handle_t *eh, elf_strtab_t *tab);
void f_set(char **argv, int argc, pid_t child_pid, char *program_name, int *brk_index_ptr);
void f_si(pid_t *child_pid_ptr, char **program_name_ptr, int *brk_index_ptr, BP bps[], elf_handle_t *eh, csh *cshandle_pt);
void f_start(char *program_name, pid_t *child_pid_ptr, BP bps[], unsigned long long *addr_offset_ptr);

int main(int main_argc, char *main_argv[]){

	//row input
	char buf[1000];

	//輸入後的字串parse成argv & argc
	char *argv[MAXARGS];
	int argc;

	char *program_name;
	pid_t child_pid = 0;
	int status;
	struct user_regs_struct regs;

	//for dump
	//沒有dump過，就是0
	//有dump 且給位址過，就更新last addr
	int dump_flag = 0;
	unsigned long long last_addr = 0;	

	//for disasm
	int dis_flag = 0;
	unsigned long long last_dis_addr = 0;
	static csh cshandle = 0;
	cs_insn *insn;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &cshandle) != CS_ERR_OK)
		return -1;

	//for breakpoint
	BP bps[MAXBPS];
	memset(bps, 0, sizeof(BP)*MAXBPS);
	int bps_index=0;
	int brk_index=-1;

	//不知道為什麼signal接不到
	//誇張QQ
	//signal(SIGTRAP, brkhandler);

	//for elftool
	elf_handle_t *eh = NULL;
	elf_strtab_t *tab = NULL;

	//for load
	unsigned long long addr_offset;

	if(main_argc > 1){
		//load program
		program_name = (char *)malloc(sizeof(char)*100);
		strcpy(program_name, main_argv[1]);
		if(load_program(program_name, &eh, &tab) == 0){
			int i;
			for(i=0;i<eh->shnum;i++){
				if(strcmp(&tab->data[eh->shdr[i].name], ".text")==0){
					break;
				}
			}
        		printf("** program \'%s\' loaded. entry point 0x%llx, vaddr 0x%llx, offset 0x%llx, size 0x%llx\n", program_name, eh->entrypoint, eh->shdr[i].addr, eh->shdr[i].offset, eh->shdr[i].size);
		}

	}else{
		program_name = NULL;
	}

	//main loop
	while(1){

		argc = 0;

		printf("sdb>");
		
		//get userinput and tokenlize
		user_input(buf);
		//處理直接enter的情況
		if(buf[0]==0){
			continue;
		}
		parse_argv(buf, argv, &argc);	

		//
		if(strcmp(argv[0], "exit")==0 || strcmp(argv[0], "q")==0){
			f_exit(eh);
			return 0;
		}else if(strcmp(argv[0], "help")==0 || strcmp(argv[0], "h")==0){
			f_help();
		}else if(strcmp(argv[0], "break")==0 || strcmp(argv[0], "b")==0){
			f_break(argv, argc, bps, child_pid, program_name, &bps_index, eh, tab);
		}else if(strcmp(argv[0], "cont")==0 || strcmp(argv[0], "c")==0){
			f_cont(&program_name, &child_pid, &brk_index, bps, eh, &cshandle, &addr_offset);
                }else if(strcmp(argv[0], "delete")==0){
			f_delete(argv, argc, bps, child_pid);
                }else if(strcmp(argv[0], "disasm")==0 || strcmp(argv[0], "d")==0){
			f_disasm(argv, argc, child_pid, program_name, eh, tab, &last_dis_addr, &cshandle, &dis_flag, bps);
                }else if(strcmp(argv[0], "dump")==0 || strcmp(argv[0], "x")==0){
			f_dump(argv, argc, program_name, child_pid, &dump_flag, &last_addr);
                }else if(strcmp(argv[0], "get")==0 || strcmp(argv[0], "g")==0){
			f_get(argv, argc, program_name, child_pid);
                }else if(strcmp(argv[0], "getregs")==0){
			f_getregs(argv, argc, program_name, child_pid);
		}else if(strcmp(argv[0], "list")==0 || strcmp(argv[0], "l")==0){
			f_list(bps);
                }else if(strcmp(argv[0], "load")==0){
			f_load(argv, argc, &eh, &tab, &program_name);
                }else if(strcmp(argv[0], "run")==0 || strcmp(argv[0], "r")==0){
			f_run(&program_name, &child_pid, &brk_index, bps, eh, &cshandle, &addr_offset);
                }else if(strcmp(argv[0], "vmmap")==0 || strcmp(argv[0], "m")==0){
			f_vmmap(program_name, child_pid, eh, tab);
                }else if(strcmp(argv[0], "set")==0 || strcmp(argv[0], "s")==0){
			f_set(argv, argc, child_pid, program_name, &brk_index);
                }else if(strcmp(argv[0], "si")==0){
			f_si(&child_pid, &program_name, &brk_index, bps, eh, &cshandle);
                }else if(strcmp(argv[0], "start")==0){
			f_start(program_name, &child_pid, bps, &addr_offset);
                }else{
			printf("unknown command!\n");
		}
	}

	cs_close(&cshandle);

	return 0;
}


void user_input(char buf[]){
	int buf_i = 0; 
	char c;
	while(1){
		c = getchar();
		buf[buf_i] = c;
		if(buf_i==800 || buf[buf_i]=='\n'){
			if(buf_i==800){
				buf[buf_i]='\n';
			}
			break;
		}
		buf_i++;
	}
	while(1){
		if(buf[buf_i]=='\n'){
			buf[buf_i] = 0;
			break;
		}
		buf_i++;
	}
}

void parse_argv(char *buf_ptr, char *argv[], int *argc){

	char *tail_ptr = buf_ptr;
	char *head_ptr = buf_ptr;

	int state = 0;
	while(1){

		//處理連續很多空白的情況
		if(tail_ptr!=buf_ptr && (*(tail_ptr-1))==0 && (*tail_ptr)==' '){
			*tail_ptr=0;
			head_ptr=tail_ptr+1;
			tail_ptr++;
			continue;
		}

		//把一個個參數丟進argv
		if((*tail_ptr)=='\n' || (*tail_ptr)==' '){
			argv[(*argc)] = head_ptr;
			*argc = (*argc)+1;
			head_ptr = tail_ptr+1;
		}else if((*tail_ptr)==0){
			if((*(tail_ptr-1))==0){
				break;	
			}

			argv[(*argc)] = head_ptr;
			*argc = (*argc)+1;
			break;
		}

		//把一個個token中間的'\n'用0x00切斷
		if((*tail_ptr)=='\n' || (*tail_ptr)==' '){
			*tail_ptr = 0;
		}else if((*tail_ptr)==0){
			break;
		}
		tail_ptr++;
	}
	//let the last argv is NULL
	argv[(*argc)] = NULL;
}

void f_exit(elf_handle_t *eh){
	if(eh){
		elf_close(eh);
		eh=NULL;
	}
}

void f_help(){
	printf("%s", help_str);
}

void f_break(char **argv, int argc, BP bps[], pid_t child_pid, char *program_name, int *bps_index, elf_handle_t *eh, elf_strtab_t *tab){
	if(argc < 2){
		printf("parameter is not enough\n");
		return;
	}

	if(program_is_load(program_name)!=0){
		printf("program is not loaded!\n");
		return;
	}


	unsigned long long input_addr = strtol(argv[1], NULL, 0);
	bps[*bps_index].valid = 1;
	bps[*bps_index].addr  = input_addr;

	if(program_is_run(child_pid)!=0){
		int i;
		for(i=0;i<eh->shnum;i++){
			if(strcmp(&tab->data[eh->shdr[i].name], ".text")==0){
				break;
			}
		}
		unsigned long long text_head_addr = eh->shdr[i].addr;
		unsigned long long text_tail_addr = text_head_addr + eh->shdr[i].size;
		
		//超出範圍就踢掉
		if(input_addr < text_head_addr || input_addr > text_tail_addr){
			printf("addr out of range!\n");
			return;
		}

		bps[*bps_index].base_addr = eh->shdr[i].addr - eh->shdr[i].offset;

	}else {

		//get offset from /proc/%d/maps
		FILE *pFile;
		char file_buf[100];
		char map_path[100];
		sprintf(map_path, "/proc/%d/maps", (int)(child_pid));
		pFile = fopen(map_path,"r");
		if(pFile==NULL){
			printf("read error!\n");
			return;
		}
		fread(file_buf, 99, 1,pFile);
		file_buf[99] = 0;
		sscanf(file_buf, "%llx", &(bps[*bps_index].base_addr));


		//1. get code
		bps[*bps_index].original_code = ptrace(PTRACE_PEEKTEXT, child_pid, bps[*bps_index].addr, 0);	
				
		//2. patch code
		//set break point
		if(ptrace(PTRACE_POKETEXT, child_pid, bps[*bps_index].addr, (bps[*bps_index].original_code & 0xffffffffffffff00) | 0xcc) != 0){
			printf("PTRACE_POKETEXT ERROR!\n");
			exit(-1);
		}

	}

	(*bps_index)++;
	if(*bps_index==MAXBPS){
		*bps_index=0;
	}
}

int f_cont(char **program_name_ptr, pid_t *child_pid_ptr, int *brk_index_ptr, BP bps[], elf_handle_t *eh, csh *cshandle_ptr, unsigned long long *addr_offset_ptr){
	
	cs_insn *insn;
	struct user_regs_struct regs;
	int status;

	if(program_is_load(*program_name_ptr) != 0){
		printf("program is not loaded!\n");
		return -1;
	}
	if(program_is_run(*child_pid_ptr) != 0){
		printf("program is not running!\n");
		return -1;
	}

	//看看是不是在break point之後
	handle_after_brkp(brk_index_ptr, *child_pid_ptr, bps);
	ptrace(PTRACE_CONT, *child_pid_ptr, 0, 0);
	waitpid(*child_pid_ptr, &status, 0);

	if(WIFEXITED(status)){
		//if the child exit
		printf("** child process %d terminiated normally (code 0)\n", *child_pid_ptr);
		*child_pid_ptr = 0;
		//*program_name_ptr = NULL;
	}else if(WIFSTOPPED(status)){
		//if the child stop because of breakpoint
		if(ptrace(PTRACE_GETREGS, *child_pid_ptr, 0, &regs) != 0){
			printf("PTRACE_GETREGS ERROR!\n");
			exit(-1);
		}

		unsigned long long look_addr = regs.rip-1;
		unsigned char *peek_code_ptr;
		size_t count;

		int i;
		for(i=0;i<MAXBPS;i++){
			if(bps[i].addr == look_addr){
				break;		
			}
		}		
		*brk_index_ptr = i;

		peek_code_ptr = (unsigned char *)&(bps[i].original_code);
		printf("** breakpoint @\t");
		if((count = cs_disasm(*cshandle_ptr, (uint8_t *)peek_code_ptr, 8, look_addr, 0, &insn)) > 0){
			char display[100] = {0};


			//print address value insn
			printf("0x%llx:", insn[0].address);
			int loop_times = (int)(insn[0+1].address - insn[0].address);
			int now_index = insn[0].address - insn[0].address;
			int gap = 30;

			for(int g=0;g<loop_times;g++){
				printf(" %2.2x", (uint8_t)peek_code_ptr[now_index+g]);
				gap-=3;
			}
			for(int g=0;g<gap;g++){
				printf(" ");
			}

			memset(display, 0, sizeof(display));	
			sprintf(display, "%s %s", insn[0].mnemonic, insn[0].op_str);

			printf("\t%s\n", display);	
		}

	}else if(WEXITSTATUS(status)){
		printf("** child process %d terminated code is %d\n", *child_pid_ptr, WEXITSTATUS(status));
		*child_pid_ptr = 0;
		//*program_name_ptr = NULL;
	}

	return 0;
}

void f_delete(char **argv, int argc, BP bps[], pid_t child_pid){
	if(argc<2){
		printf("give me more parameters!\n");
	}else{
		int index = atoi(argv[1]);

		// 把原本的code patch 回去 
		if(ptrace(PTRACE_POKETEXT, child_pid, bps[index].addr, bps[index].original_code) != 0){
			printf("PTRACE_POKETEXT\n");
			exit(-1);
		}

		bps[index].valid = 0;	
	}
}


void f_disasm(char **argv, int argc, pid_t child_pid,char *program_name, elf_handle_t *eh, elf_strtab_t *tab, unsigned long long *last_dis_addr_ptr, csh *cshandle_ptr, int *dis_flag_ptr, BP bps[]){
	cs_insn *insn;
	char buf[512]={0};
	size_t count;

	int state_load = 0;
	//我們的輸入相對於base_addr
	unsigned long long get_offset;
	unsigned long long base_addr;
	unsigned long long ptr;
	unsigned long long input_addr;

	unsigned long long text_head_addr;
	unsigned long long text_tail_addr;


	if(program_is_load(program_name)!=0){
		printf("program is not loaded!\n");
		return;
	}

	if(argc == 1){
		if(*dis_flag_ptr == 0){
			printf("** no addr is given.\n");
			return;
		}else {
			input_addr = *last_dis_addr_ptr;	
			ptr = input_addr;				
		}
	}else if(argc == 2){
		unsigned long long num = strtol(argv[1], NULL, 0);
		input_addr = num;
		ptr = num;
	}

	if(program_is_run(child_pid)!=0){
	
		state_load = 1;

		int fd = eh->fd;
		int i;
		for(i=0;i<eh->shnum;i++){
			if(strcmp(&tab->data[eh->shdr[i].name], ".text")==0){
				break;
			}
		}
		text_head_addr = eh->shdr[i].addr;
		text_tail_addr = text_head_addr + eh->shdr[i].size;
		
		//超出範圍就踢掉
		if(input_addr < text_head_addr || input_addr > text_tail_addr){
			printf("addr out of range!\n");
			return;
		}

		base_addr = eh->shdr[i].addr - eh->shdr[i].offset;
		get_offset = input_addr - base_addr;

		
		lseek(fd, get_offset, SEEK_SET);	
		read(fd, buf, 496);
		ptr = input_addr + 496;
	

	}else {
		//get base_addr from /proc/%d/maps
		FILE *pFile;
		char file_buf[100];
		char map_path[100];
		sprintf(map_path, "/proc/%d/maps", (int)(child_pid));
		pFile = fopen(map_path,"r");
		if(pFile==NULL){
			printf("read error!\n");
			return;
		}
		fread(file_buf, 99, 1,pFile);
		file_buf[99] = 0;
		sscanf(file_buf, "%llx", &base_addr);

		get_offset = input_addr - base_addr;

		for(ptr = input_addr;ptr<input_addr+496;ptr+=PEEKSIZE){
			long long peek;
			peek = ptrace(PTRACE_PEEKTEXT, child_pid, ptr, NULL);
			memcpy(&buf[ptr-input_addr], &peek, PEEKSIZE);
		}

		//TODO 
		//patch buf back (recover change because of break point)
		//input_addr~input_addr+496 , 是這次需要patch的範圍
		for(int i=0;i<MAXBPS;i++){
			if(bps[i].valid == 1){
				if(bps[i].addr>=input_addr && bps[i].addr<=(input_addr+496)){
					unsigned char *cptr;
					cptr = (unsigned char *)&(bps[i].original_code);		
					buf[bps[i].addr - input_addr] = *cptr;

				}
			}
		}		


	}

	if((count = cs_disasm(*cshandle_ptr, (uint8_t *)buf, ptr-input_addr, input_addr, 0, &insn)) > 0){
		size_t j;
		char display[100]={0};
		for(j=0;j<count;j++){

			//若程式還沒跑起來，就要進行範圍檢查
			if(state_load == 1){
				//printf("text_tail_addr:0x%llx\n", text_tail_addr);
				if(insn[j].address >= text_tail_addr){
					break;
				}
			}

			//print address value insn
			printf("0x%llx:", insn[j].address);
			int loop_times = (int)(insn[j+1].address - insn[j].address);
			int now_index = insn[j].address - insn[0].address;
			int gap = 30;

			for(int g=0;g<loop_times;g++){
				printf(" %2.2x", (uint8_t)buf[now_index+g]);
				gap-=3;
			}
			for(int g=0;g<gap;g++){
				printf(" ");
			}

			memset(display, 0, sizeof(display));	
			sprintf(display, "%s %s", insn[j].mnemonic, insn[j].op_str);

			printf("\t%s\n", display);	
			//最多一次10個instruction
			if(j==9){
				j++;
				break;
			}
		}
		*dis_flag_ptr = 1;	
		*last_dis_addr_ptr = insn[j].address;

	}else{
		printf("disasm error!\n");
	}
	cs_free(insn, count);

}

void f_dump(char **argv, int argc, char *program_name, pid_t child_pid, int *dump_flag_ptr, unsigned long long *last_addr_ptr){
	unsigned long long addr;
	long dump_ret;
	unsigned char *dump_ptr = (unsigned char *) &dump_ret;

	if(argc == 1){
		if(*dump_flag_ptr == 0){
			printf("no last address!\n");
			return;
		}else {
			addr = *last_addr_ptr;
		}
	}else if(argc == 2){
		addr = strtol(argv[1], NULL, 0);
	}else{
		printf("number of the parameter is wrong!\n");
	}

	if(program_name==NULL){
		printf("program is not loaded!\n");
		return;
	}
	if(child_pid==0){
		printf("program is not running!\n");
		return;
	}

	for(int j=0;j<5;j++){
		int dump_char_index=0;
		char dump_char[17];

		dump_ret = ptrace(PTRACE_PEEKTEXT, child_pid, addr, 0);

		printf("%llx: %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x", addr, dump_ptr[0], dump_ptr[1], dump_ptr[2], dump_ptr[3], dump_ptr[4], dump_ptr[5], dump_ptr[6], dump_ptr[7]);	

		for(int i=0;i<8;i++){
			dump_char[dump_char_index++]=dump_ptr[i];
		}

		dump_ret = ptrace(PTRACE_PEEKTEXT, child_pid, addr+8, 0);

		printf(" %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x", dump_ptr[0], dump_ptr[1], dump_ptr[2], dump_ptr[3], dump_ptr[4], dump_ptr[5], dump_ptr[6], dump_ptr[7]);	

		for(int i=0;i<8;i++){
			dump_char[dump_char_index++]=dump_ptr[i];
		}

		dump_char[dump_char_index] = 0;	

		for(int i=0;i<16;i++){
			if(dump_char[i]>=0x20 && dump_char[i]<=0x7e){
		
			}else{
				dump_char[i]='.';
			}
		}
		
		printf(" |%s|\n", dump_char);

		addr+=0x10;

	}
	*dump_flag_ptr = 1;
	*last_addr_ptr = addr;

}

void f_get(char **argv, int argc, char *program_name, pid_t child_pid){

	struct user_regs_struct regs;

	if(argc<2){
		printf("give me more parameter! you ass\n");
		return;
	}

	if(program_name==NULL){
		printf("program is not loaded!\n");
		return;
	}
	if(child_pid==0){
		printf("program is not running!\n");
		return;
	}
	if(ptrace(PTRACE_GETREGS, child_pid, 0, &regs)!=0){
		printf("ptrace failed to get regs!\n");
		return;
	}

	if(strcmp(argv[1], "rip")==0){
		printf("rip = %llu (0x%llx)\n", regs.rip, regs.rip);
	}else if(strcmp(argv[1], "rax")==0){
		printf("rax = %llu (0x%llx)\n", regs.rax, regs.rax);
	}else if(strcmp(argv[1], "rbx")==0){
		printf("rbx = %llu (0x%llx)\n", regs.rbx, regs.rbx);
	}else if(strcmp(argv[1], "rcx")==0){
		printf("rcx = %llu (0x%llx)\n", regs.rcx, regs.rcx);
	}else if(strcmp(argv[1], "rdx")==0){
		printf("rdx = %llu (0x%llx)\n", regs.rdx, regs.rdx);
	}else if(strcmp(argv[1], "r8")==0){
		printf("r8 = %llu (0x%llx)\n", regs.r8, regs.r8);
	}else if(strcmp(argv[1], "r9")==0){
		printf("r9 = %llu (0x%llx)\n", regs.r9, regs.r9);
	}else if(strcmp(argv[1], "r10")==0){
		printf("r10 = %llu (0x%llx)\n", regs.r10, regs.r10);
	}else if(strcmp(argv[1], "r11")==0){
		printf("r11 = %llu (0x%llx)\n", regs.r11, regs.r11);
	}else if(strcmp(argv[1], "r12")==0){
		printf("r12 = %llu (0x%llx)\n", regs.r12, regs.r12);
	}else if(strcmp(argv[1], "r13")==0){
		printf("r13 = %llu (0x%llx)\n", regs.r13, regs.r13);
	}else if(strcmp(argv[1], "r14")==0){
		printf("r14 = %llu (0x%llx)\n", regs.r14, regs.r14);
	}else if(strcmp(argv[1], "r15")==0){
		printf("r15 = %llu (0x%llx)\n", regs.r15, regs.r15);
	}else if(strcmp(argv[1], "rdi")==0){
		printf("rdi = %llu (0x%llx)\n", regs.rdi, regs.rdi);
	}else if(strcmp(argv[1], "rsi")==0){
		printf("rsi = %llu (0x%llx)\n", regs.rsi, regs.rsi);
	}else if(strcmp(argv[1], "rbp")==0){
		printf("rbp = %llu (0x%llx)\n", regs.rbp, regs.rbp);
	}else if(strcmp(argv[1], "rsp")==0){
		printf("rsp = %llu (0x%llx)\n", regs.rsp, regs.rsp);
	}else if(strcmp(argv[1], "flags")==0){
		printf("flags = %llu (0x%llx)\n", regs.eflags, regs.eflags);
	}
}

void f_getregs(char **argv, int argc, char *program_name, pid_t child_pid){

	struct user_regs_struct regs;

	if(program_is_load(program_name)!=0){
		printf("program is not loaded!\n");
		return;
	}
	if(program_is_run(child_pid)!=0){
		printf("program is not running!\n");
		return;
	}
	if(ptrace(PTRACE_GETREGS, child_pid, 0, &regs)!=0){
		printf("ptrace failed to get regs!\n");
		return;
	}		


	printf("RAX 0x%llx\tRBX 0x%llx\tRCX 0x%llx\tRDX 0x%llx\n" \
		"R8 0x%llx\tR9 0x%llx\tR10 0x%llx\tR11 0x%llx\n" \
		"R12 0x%llx\tR13 0x%llx\tR14 0x%llx\tR15 0x%llx\n" \
		"RDI 0x%llx\tRSI 0x%llx\tRBP 0x%llx\tRSP 0x%llx\n" \
		"RIP 0x%llx\tFLAGS 0x%llx\n", regs.rax, regs.rbx, regs.rcx, regs.rdx, regs.r8, regs.r9, regs.r10, regs.r11, regs.r12, regs.r13, regs.r14, regs.r15, regs.rdi, regs.rsi, regs.rbp, regs.rsp, regs.rip, regs.eflags);
 
}

void f_list(BP bps[]){
	for(int i=0;i<MAXBPS;i++){
		if(bps[i].valid==1){
			printf("%d:\t0x%llx\n", i, bps[i].addr);
		}
	}
}

void f_load(char **argv, int argc, elf_handle_t **eh_ptr, elf_strtab_t **tab_ptr, char **program_name_ptr){
	if(*eh_ptr){
		int i;
		for(i=0;i<(*eh_ptr)->shnum;i++){
			if(strcmp(&(*tab_ptr)->data[(*eh_ptr)->shdr[i].name], ".text")==0){
				break;
			}
		}
		printf("** program \'%s\' loaded. entry point 0x%llx, vaddr 0x%llx, offset 0x%llx, size 0x%llx\n", *program_name_ptr, (*eh_ptr)->entrypoint, (*eh_ptr)->shdr[i].addr, (*eh_ptr)->shdr[i].offset, (*eh_ptr)->shdr[i].size);
		return;
	}

	if(argc<2){
		printf("number of parameter is not correct!\n");
		return;
	}
	printf("try to load %s\n", argv[1]);

	*program_name_ptr = (char *)malloc(sizeof(char)*100);
	strcpy(*program_name_ptr, argv[1]);


	if(load_program(*program_name_ptr, eh_ptr, tab_ptr) == 0){	
		int i;
		for(i=0;i<(*eh_ptr)->shnum;i++){
			if(strcmp(&(*tab_ptr)->data[(*eh_ptr)->shdr[i].name], ".text")==0){
				break;
			}
		}
		printf("** program \'%s\' loaded. entry point 0x%llx, vaddr 0x%llx, offset 0x%llx, size 0x%llx\n", *program_name_ptr, (*eh_ptr)->entrypoint, (*eh_ptr)->shdr[i].addr, (*eh_ptr)->shdr[i].offset, (*eh_ptr)->shdr[i].size);
	}



}

void f_run(char **program_name_ptr, pid_t *child_pid_ptr, int *brk_index_ptr, BP bps[], elf_handle_t *eh, csh *cshandle_ptr, unsigned long long *addr_offset_ptr){

	int status;
	struct user_regs_struct regs;
	cs_insn *insn;

	//看看是不是在break point之後
	//handle_after_brkp(brk_index_ptr, *child_pid_ptr, bps);
	//好像不用，因為每次都是重頭開始跑

	if(*child_pid_ptr!=0){
		printf("** process %s is already running.\n", *program_name_ptr);
		f_cont(program_name_ptr, child_pid_ptr, brk_index_ptr, bps,  eh, cshandle_ptr, addr_offset_ptr);
		return;
	}

	if(*program_name_ptr==NULL){
		printf("** program has not been loaded!\n");
		return;
	}


	if(((*child_pid_ptr)=fork())<0){
		printf("fork error!\n");
		return;
	}

	if(*child_pid_ptr==0){
		if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0){
			printf("ptrace error\n");
			exit(-1);
		}

		//目前還不需要給參數
		char *run_argv[2];
		run_argv[0] = *program_name_ptr;
		run_argv[1] = NULL;				
				
		execvp(run_argv[0], run_argv);
		printf("execve error!\n");
		exit(-1);			
	}else{
		if(waitpid(*child_pid_ptr, &status, 0) < 0){
			printf("waitpid error\n");
			exit(-1);
		}
		assert(WIFSTOPPED(status));

		printf("** pid %d\n", *child_pid_ptr);

		//在執行程式之前，把break point patch上去
		fix_bps(bps, *child_pid_ptr);
		patch_brkp(*child_pid_ptr, bps);

		ptrace(PTRACE_SETOPTIONS, *child_pid_ptr, 0, PTRACE_O_EXITKILL);
		ptrace(PTRACE_CONT, *child_pid_ptr, 0, 0);
		waitpid(*child_pid_ptr, &status, 0);

		//if the child exit
		if(WIFEXITED(status)){
			printf("** child process %d terminiated normally (code 0)\n", *child_pid_ptr);
			*child_pid_ptr = 0;
			//*program_name_ptr = NULL;
		}else if(WIFSTOPPED(status)){
			//if the child stop because of breakpoint
			if(ptrace(PTRACE_GETREGS, *child_pid_ptr, 0, &regs) != 0){
				printf("PTRACE_GETREGS ERROR!\n");
				exit(-1);
			}

			unsigned long long look_addr = regs.rip-1;
			unsigned char *peek_code_ptr;
			size_t count;

			int i;
			for(i=0;i<MAXBPS;i++){
				if(bps[i].addr == look_addr){
					break;		
				}
			}		
			*brk_index_ptr = i;

			peek_code_ptr = (unsigned char *)&(bps[i].original_code);
			printf("** breakpoint @\t");
			if((count = cs_disasm(*cshandle_ptr, (uint8_t *)peek_code_ptr, 8, look_addr, 0, &insn)) > 0){
				char display[100] = {0};


				//print address value insn
				printf("0x%llx:", insn[0].address);
				int loop_times = (int)(insn[0+1].address - insn[0].address);
				int now_index = insn[0].address - insn[0].address;
				int gap = 30;

				for(int g=0;g<loop_times;g++){
					printf(" %2.2x", (uint8_t)peek_code_ptr[now_index+g]);
					gap-=3;
				}
				for(int g=0;g<gap;g++){
					printf(" ");
				}

				memset(display, 0, sizeof(display));	
				sprintf(display, "%s %s", insn[0].mnemonic, insn[0].op_str);

				printf("\t%s\n", display);	
			}


		}else if(WEXITSTATUS(status)){
			printf("** child process %d terminated code is %d\n", *child_pid_ptr, WEXITSTATUS(status));
			*child_pid_ptr = 0;
			//*program_name_ptr = NULL;
		}
	}
}

void f_vmmap(char *program_name, pid_t child_pid, elf_handle_t *eh, elf_strtab_t *tab){

	char file_buf[5000];

	if(program_name==NULL){
		printf("there is no loaded program!\n");
		return;
	}
	if(child_pid==0){
		//loaded but not running
		int i;
		for(i=0;i<eh->shnum;i++){
			if(strcmp(&tab->data[eh->shdr[i].name], ".text")==0){
				break;
			}
		}
		printf("%016llx-%016llx\tr-x\t%llx\t%s\n", eh->shdr[i].addr, eh->shdr[i].addr + eh->shdr[i].size, eh->shdr[i].offset, program_name);
	}else{
		//loaded & running
		FILE *pFile;
		char map_path[100];
		sprintf(map_path, "/proc/%d/maps", (int)child_pid);

		pFile = fopen(map_path,"r");
		if(pFile==NULL){
			printf("read error!\n");
			return;
		}

		size_t count;
		fread(file_buf, 5000, 1,pFile);

		//解決vmmap會有奇怪殘值的問題
		for(int i=0;i<5000;i++){
			if(file_buf[i]=='\n' && !((file_buf[i+1]>='0' && file_buf[i+1]<='9') || (file_buf[i+1]>='a' && file_buf[i+1]<='f'))){
				file_buf[i+1] = 0;	
			}
		}

		printf("%s", file_buf);
	}
}

void f_set(char **argv, int argc, pid_t child_pid, char *program_name, int *brk_index_ptr){

	struct user_regs_struct regs;
	if(argc<3){
		printf("give me more parameters!\n");
		return;
	}	
	if(program_is_load(program_name)!=0){
		printf("program is not loaded!\n");
		return;
	}
	if(program_is_run(child_pid)!=0){
		printf("program is not running!\n");
		return;
	}
	if(ptrace(PTRACE_GETREGS, child_pid, 0, &regs)!=0){
		printf("ptrace failed to get regs!\n");
		exit(-1);
	}

	char *input_ptr = argv[2];
	long int num;

	if(input_ptr[0]=='0' && input_ptr[1]=='x'){
		num = strtol(argv[2], NULL, 0);
	}else{
		num = strtol(argv[2], NULL, 10);
	}


	if(strcmp(argv[1], "rip")==0){
		if(regs.rip != num){
			//rip 跟原本的不同 => 要跳到不一樣的地方 => 消去brk_index的狀態
			*brk_index_ptr = -1;
		}
		regs.rip = num;
	}else if(strcmp(argv[1], "rax")==0){
		regs.rax = num;
	}else if(strcmp(argv[1], "rbx")==0){
		regs.rbx = num;
	}else if(strcmp(argv[1], "rcx")==0){
		regs.rcx = num;
	}else if(strcmp(argv[1], "rdx")==0){
		regs.rdx = num;
	}else if(strcmp(argv[1], "r8")==0){
		regs.r8 = num;
	}else if(strcmp(argv[1], "r9")==0){
		regs.r9 = num;
	}else if(strcmp(argv[1], "r10")==0){
		regs.r10 = num;
	}else if(strcmp(argv[1], "r11")==0){
		regs.r11 = num;
	}else if(strcmp(argv[1], "r12")==0){
		regs.r12 = num;
	}else if(strcmp(argv[1], "r13")==0){
		regs.r13 = num;
	}else if(strcmp(argv[1], "r14")==0){
		regs.r14 = num;
	}else if(strcmp(argv[1], "r15")==0){
		regs.r15 = num;
	}else if(strcmp(argv[1], "rdi")==0){
		regs.rdi = num;
	}else if(strcmp(argv[1], "rsi")==0){
		regs.rsi = num;
	}else if(strcmp(argv[1], "rbp")==0){
		regs.rbp = num;
	}else if(strcmp(argv[1], "rsp")==0){
		regs.rsp = num;
	}else if(strcmp(argv[1], "flags")==0){
		regs.eflags = num;
	}

	if(ptrace(PTRACE_SETREGS, child_pid, 0, &regs)!=0){
		printf("ptrace failed to set regs!\n");
		exit(-1);
	}
}

void f_si(pid_t *child_pid_ptr, char **program_name_ptr, int *brk_index_ptr, BP bps[], elf_handle_t *eh, csh *cshandle_ptr){
	int status;
	struct user_regs_struct regs;
	cs_insn *insn;
	int brk_index_old = *brk_index_ptr;
	size_t count;


	if(program_is_load(*program_name_ptr)!=0){
		printf("program is not loaded!\n");
		return;
	}	

	if(program_is_run(*child_pid_ptr)!=0){
		printf("program is not running!\n");
		return;
	}

	//1. 走之前先看看是不是break point
	//	是的話，就印出訊息，patch後走一步，再patch回break point
	//	不是的話，就走一步



	//看看是不是在break point之後
	//因為run, cont踩到的那種
	handle_after_brkp(brk_index_ptr, *child_pid_ptr, bps);
	//假如不等於-1 => 處理brkp需要一個single step => si也順便處理完了
	if(brk_index_old == -1){
		//上一步不是break point (因為run, cont踩到的那種)
		ptrace(PTRACE_SINGLESTEP, *child_pid_ptr, 0, 0);
		waitpid(*child_pid_ptr, &status, 0);
	}else {

	}

	//if the child exit
	if(WIFEXITED(status)){
		printf("** child process %d terminiated normally (code 0)\n", *child_pid_ptr);
		*child_pid_ptr = 0;
		//*program_name_ptr = NULL;
		return;
	}

	//沒exit的話，就可以開始觀察上一步做了什麼事情
	//拿rip-1看看執行到什麼指令，假如是0xcc，就找找看那個位址有沒有break point
	//應該是要有啦，有的話就在brk_index_ptr上面計上一筆
	if(ptrace(PTRACE_GETREGS, *child_pid_ptr, 0, &regs) != 0){
		printf("PTRACE_GETREGS ERROR\n");
		exit(-1);
	}
	unsigned long long look_addr = regs.rip-1;	
	unsigned long long peek_code;
	unsigned char *peek_code_ptr = (unsigned char *)&peek_code;
	peek_code = ptrace(PTRACE_PEEKTEXT, *child_pid_ptr, look_addr, NULL);
	if(peek_code_ptr[0]==0xcc){

		printf("** breakpoint @\t");

		int i;
		for(i=0;i<MAXBPS;i++){
			if(bps[i].addr == look_addr){
				break;
			}			
		}
		*brk_index_ptr = i;

		peek_code_ptr = (unsigned char *)&(bps[i].original_code);				
		
		if((count = cs_disasm(*cshandle_ptr, (uint8_t *)peek_code_ptr, 8, look_addr, 0, &insn)) > 0){
			char display[100] = {0};


			//print address value insn
			printf("0x%llx:", insn[0].address);
			int loop_times = (int)(insn[0+1].address - insn[0].address);
			int now_index = insn[0].address - insn[0].address;
			int gap = 30;

			for(int g=0;g<loop_times;g++){
				printf(" %2.2x", (uint8_t)peek_code_ptr[now_index+g]);
				gap-=3;
			}
			for(int g=0;g<gap;g++){
				printf(" ");
			}

			memset(display, 0, sizeof(display));	
			sprintf(display, "%s %s", insn[0].mnemonic, insn[0].op_str);

			printf("\t%s\n", display);	
		}
	}
}

void f_start(char *program_name, pid_t *child_pid_ptr, BP bps[], unsigned long long *addr_offset_ptr){

	int status;

	if(*child_pid_ptr!=0){
		printf("** the process has already run!\n");
		return;
	}

	if(program_name==NULL){
		printf("** program has not been loaded!\n");
		return;
	}


	if(((*child_pid_ptr)=fork())<0){
		printf("fork error!\n");
		return;
	}

	if((*child_pid_ptr)==0){
		if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0){
			printf("ptrace error\n");
			exit(-1);
		}

		//目前還不需要給參數
		char *run_argv[2];
		run_argv[0] = program_name;
		run_argv[1] = NULL;				
				
		execvp(run_argv[0], run_argv);
		printf("execve error!\n");
		exit(-1);			
	}else{
		printf("** pid %d\n", *child_pid_ptr);
		
		if(waitpid(*child_pid_ptr, &status, 0) < 0){
			printf("waitpid error\n");
			exit(-1);
		}
		assert(WIFSTOPPED(status));
		ptrace(PTRACE_SETOPTIONS, *child_pid_ptr, 0, PTRACE_O_EXITKILL);

		//在執行程式之前，把break point patch上去
		fix_bps(bps, *child_pid_ptr);
		patch_brkp(*child_pid_ptr, bps);
	}
}

//看是不是在breakpoint後面
//start, si, run等等rip會往後跑的指令都需要這個
void handle_after_brkp(int* brk_index, pid_t child_pid, BP bps[]){
	
	struct user_regs_struct regs;
	int status;

	if(*brk_index!=-1){
		//從break point往下走

		if(ptrace(PTRACE_GETREGS, child_pid, 0, &regs) != 0) {
			printf("PTRACE_GETREGS ERROR\n");
			exit(-1);
		}
				
		regs.rip = regs.rip-1;
		//這邊沒一樣就不正常了
		//但是f_si的話，就不用regs.rip-1
		assert(regs.rip == bps[*brk_index].addr);

		// 把原本的code patch 回去 
		if(ptrace(PTRACE_POKETEXT, child_pid, bps[*brk_index].addr, bps[*brk_index].original_code) != 0){
			printf("PTRACE_POKETEXT\n");
			exit(-1);
		}

		//把rip退回執行0xcc之前
		if(ptrace(PTRACE_SETREGS, child_pid, 0, &regs) != 0){
			printf("PTRACE_SETREGS ERROR!\n");
			exit(-1);
		}

		//往下走一步
        	ptrace(PTRACE_SINGLESTEP, child_pid, 0, 0);
		waitpid(child_pid, &status, 0);

		//把原本的break point再patch成0xcc
		if(ptrace(PTRACE_POKETEXT, child_pid, bps[*brk_index].addr, (bps[*brk_index].original_code & 0xffffffffffffff00) | 0xcc) != 0){
			printf("PTRACE_POKETEXT ERROR!\n");
			exit(-1);
		}

		//這次的breakpoint平安處理完了
		//把值設回-1，等著碰到下一個break point
		*brk_index = -1;		
	}

}
void handle_after_brkp_si(int* brk_index, pid_t child_pid, BP bps[]){
	
	struct user_regs_struct regs;
	int status;

	if(*brk_index!=-1){
		//從break point往下走

		if(ptrace(PTRACE_GETREGS, child_pid, 0, &regs) != 0) {
			printf("PTRACE_GETREGS ERROR\n");
			exit(-1);
		}
				
		//這邊沒一樣就不正常了
		//但是f_si的話，就不用regs.rip-1
		assert(regs.rip == bps[*brk_index].addr);

		// 把原本的code patch 回去 
		if(ptrace(PTRACE_POKETEXT, child_pid, bps[*brk_index].addr, bps[*brk_index].original_code) != 0){
			printf("PTRACE_POKETEXT\n");
			exit(-1);
		}
	
		//往下走一步
        	ptrace(PTRACE_SINGLESTEP, child_pid, 0, 0);
		waitpid(child_pid, &status, 0);

		//把原本的break point再patch成0xcc
		if(ptrace(PTRACE_POKETEXT, child_pid, bps[*brk_index].addr, (bps[*brk_index].original_code & 0xffffffffffffff00) | 0xcc) != 0){
			printf("PTRACE_POKETEXT ERROR!\n");
			exit(-1);
		}

		//這次的breakpoint平安處理完了
		//把值設回-1，等著碰到下一個break point
		*brk_index = -1;		
	}

}
//shell要開啟這個程式的時候， ./a.out program name可用
//也可用在load指令
int  load_program(char *program_name, elf_handle_t **eh_ptr, elf_strtab_t **tab_ptr){
	
	elf_init();

	if(((*eh_ptr) = elf_open(program_name))==NULL){
		printf("** unable to load %s.\n", program_name);
		return -1;
	}
	if(elf_load_all(*eh_ptr)<0){
		printf("** unable to load %s.\n", program_name);
		return -1;
	}

	for(*tab_ptr = (*eh_ptr)->strtab; *tab_ptr != NULL ; *tab_ptr = (*tab_ptr)->next){
		if((*tab_ptr)->id == (*eh_ptr)->shstrndx) break;
	}

	if(*tab_ptr==NULL){
		printf("** section header string table not found.\n");
		return -1;
	}

	
	return 0;

}

//判斷program有沒有被load進來了
int program_is_load(char *program_name){
	if(program_name == NULL){
		return -1;
	}

	return 0;
}

//判斷program有沒有在跑
int program_is_run(pid_t child_pid){
	if(child_pid==0){
		return -1;
	}
	return 0;
}

//在程式準備run前，修整一下break point
void fix_bps(BP bps[], pid_t child_pid){

	unsigned long long offset;	
	unsigned long long base_addr;

	//get base_addr from /proc/%d/maps
	FILE *pFile;
	char file_buf[100];
	char map_path[100];
	sprintf(map_path, "/proc/%d/maps", (int)(child_pid));
	pFile = fopen(map_path,"r");
	if(pFile==NULL){
		printf("read error!\n");
		return;
	}
	fread(file_buf, 99, 1,pFile);
	file_buf[99] = 0;
	sscanf(file_buf, "%llx", &base_addr);

	for(int i=0;i<MAXBPS;i++){
		offset = bps[i].addr - bps[i].base_addr;
		bps[i].base_addr = base_addr;
		bps[i].addr = base_addr+offset;
	}
}

//在load的時候就下的斷點，在run or start等等fork出process的時候，再patch上去
void patch_brkp(pid_t child_pid, BP bps[]){
	for(int i=0;i<MAXBPS;i++){
		if(bps[i].valid == 1){
			//1. get code
			bps[i].original_code = ptrace(PTRACE_PEEKTEXT, child_pid, bps[i].addr, 0);

			//2. patch code
			//set break point
			if(ptrace(PTRACE_POKETEXT, child_pid, bps[i].addr, (bps[i].original_code & 0xffffffffffffff00) | 0xcc) != 0){
				printf("PTRACE_POKETEXT ERROR!\n");
				exit(-1);
			}		
		}
	}
}


