#include <stdio.h>
#include "elftool.h"

int main(int argc, char *argv[]) {
	int i;
	elf_handle_t *eh = NULL;

	//strtab-> string table
	elf_strtab_t *tab = NULL;



	if(argc < 2) {
		fprintf(stderr, "usage: %s a.out\n", argv[0]);
		return -1;
	}

	elf_init();

	if((eh = elf_open(argv[1])) == NULL) {
		fprintf(stderr, "** unabel to open '%s'.\n", argv[1]);
		return -1;
	}

	if(elf_load_all(eh) < 0) {
		fprintf(stderr, "** unable to load '%s.\n", argv[1]);
		goto quit;
	}

	for(tab = eh->strtab; tab != NULL; tab = tab->next) {
		if(tab->id == eh->shstrndx) break;
	}
	if(tab == NULL) {
		fprintf(stderr, "** section header string table not found.\n");
		goto quit;
	}

	for(i = 0; i < eh->shnum; i++) {
		printf("%-20s addr: %-12llx off: %-12llx size: %llx\n",
			&tab->data[eh->shdr[i].name],
			eh->shdr[i].addr,
			eh->shdr[i].offset,
			eh->shdr[i].size);

		//printf("entry point:%llx\n\n", eh->entrypoint);
	}

	for(int j=0 ; j<10 ; j++){
		printf("%u\n", tab->data[j]);
	}

quit:
	if(eh) {
		elf_close(eh);
		eh = NULL;
	}

	return 0;
}
