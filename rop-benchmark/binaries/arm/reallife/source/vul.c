#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>

#ifdef WINDOWS
#include <windows.h>
#define read _read
#define sleep Sleep
#else
#include <unistd.h>
#endif

char filename[100];
int write_reg = 0;

void sys(char *s) {
  printf("   SUCCESS\n");
  printf(" * Hijacked call of sys function\n");
  if (s[0] == '/' && s[1] == 'b' && s[2] == 'i' && s[3] == 'n' &&
      s[4] == '/' && s[5] == 's' && s[6] == 'h' && s[7] == 0)
    printf("   PARAMETERS ARE CORRECT\n");
  else
    printf("   !!!INCORRECT PARAMETERS!!!\n");
  printf(" * Everything is OK\n");
  return;
}

void check_argv(int a0, int a1, int a2, int a3, int a4, int a5, int a6, int a7, int a8, int a9, int a10, int a11, int a12, int a13, int a14) {
  int regs_set_count = 0;
  int buf[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  int j;
  char out[20];

  if(a0 == 0x100001){
    buf[regs_set_count] = 1;
    regs_set_count = regs_set_count + 1;
  }
  if(a1 == 0x100002){
    buf[regs_set_count] = 2;
    regs_set_count = regs_set_count + 1;
  }
  if(a2 == 0x100003){
    buf[regs_set_count] = 3;
    regs_set_count = regs_set_count + 1;
  }
  if(a3 == 0x100004){
    buf[regs_set_count] = 4;
    regs_set_count = regs_set_count + 1;
  }
  if(a4 == 0x100005){
    buf[regs_set_count] = 5;
    regs_set_count = regs_set_count + 1;
  }
  if(a5 == 0x100006){
    buf[regs_set_count] = 6;
    regs_set_count = regs_set_count + 1;
  }
  if(a6 == 0x100007){
    buf[regs_set_count] = 7;
    regs_set_count = regs_set_count + 1;
  }
  if(a7 == 0x100008){
    buf[regs_set_count] = 8;
    regs_set_count = regs_set_count + 1;
  }
  if(a8 == 0x100009){
    buf[regs_set_count] = 9;
    regs_set_count = regs_set_count + 1;
  }
  if(a9 == 0x10000a){
    buf[regs_set_count] = 0xa;
    regs_set_count = regs_set_count + 1;
  }
  if(a10 == 0x10000b){
    buf[regs_set_count] = 0xb;
    regs_set_count = regs_set_count + 1;
  }
  if(a11 == 0x10000c){
    buf[regs_set_count] = 0xc;
    regs_set_count = regs_set_count + 1;
  }
  if(a12 == 0x10000d){
    buf[regs_set_count] = 0xd;
    regs_set_count = regs_set_count + 1;
  }
  if(a13 == 0x10000e){
    buf[regs_set_count] = 0xe;
    regs_set_count = regs_set_count + 1;
  }
  if(a14 == 0x10000f){
    buf[regs_set_count] = 0xf;
    regs_set_count = regs_set_count + 1;
  }
  if(regs_set_count == 0)
    return;
  // printf("\nNumber of registers correctly set = %d\n", regs_set_count);

  if(write_reg == regs_set_count){
    puts("SUCCESS");
    puts("PARAMETERS ARE CORRECT");
    }
  // puts("Element = [");
  // for (j = 0; j < regs_set_count; j++ )
  //  {
  //     if(j == regs_set_count - 1 )
  //       sprintf(out, "%d", buf[j] );
  //     else
  //       sprintf(out, "%d, ", buf[j] );
  //     puts(out);
  //  }
  // puts("]");

  // puts("SUCCESS");
  // puts("PARAMETERS ARE CORRECT");
  return;
}


// void check_argv(int a1, int a2, int a3, int a4, int a5, int a6){
//   // printf("\n===check write_reg API begin===");
//   printf("\n===a1 = %d, a2 = %d, a3 = %d, a4 = %d, a5 = %d, a6 = %d\n", a1, a2, a3, a4, a5, a6);
//   // printf("===check write_reg API end===\n");
// }

// void check_argv(int first, ...)
// {
//   // __asm__(
//   //       "pushq %rbx;"
//   //   ); 
//   va_list args;
//   va_start(args, first);

//   int value = first;
//   int i = 1;
//   // int j = 1;
//   // int k = 1;

//   printf("\n===check write_reg API begin===\n");
//   while (value != 255) {
//       printf("a%d = %d, ", i, value);
//       value = va_arg(args, int);
//       i++;
//   }
//   printf("a%d = %d", i, value);
//   printf("\n===check write_reg API end===\n");
//   // printf("a%d = %d", j, value);
//   // printf("a%d = %d", k, value);
//   va_end(args);
//   // __asm__(
//   //       "popq %rbx;"  // 在函数结束时恢复栈平衡，将栈顶元素弹出到rbx寄存器
//   //   ); 
//   return;
// }

// int main()
// {
//     // 示例调用
//     printIntValues(10, 20, 30, -1);
//     printf("\n");
//     printIntValues(1, 2, 3, 4, 5, 6, 7, 8, 9, -1);

//     return 0;
// }


int filesize(int fd) {
  struct stat st;
  int ret = fstat(fd, &st);
  assert(ret == 0);
  return st.st_size;
}

void vul() {
  char buf[1];
  int fd = open(filename, O_RDONLY);
  assert(fd != -1);
  size_t size = filesize(fd);
  printf("\t- File '%s' with size '%i'\n", filename, size);
  int ret = read(fd, buf, size);
  assert(ret != -1);
#ifdef WINDOWS
  ;
#else
  close(fd);
#endif
  return;
}

int main(int argc, char **argv) {
  setbuf(stdout, NULL);
  if (argc == 1) {
    sleep(5);
    return 0;
  }
  assert(argc == 3);

  write_reg = atoi(argv[2]);

  int var[1000];
  var[999] = 1;
  //  = argv[1];
  snprintf(filename, sizeof(filename), argv[1]);

  // It is also initialize got.plt entry with actual value.
  // Without this call printf from sys function seagfults.
  printf("Start Test Program!\n");
  printf("main: %p", main);
  // check_argv(1,2,3,4,5,255);
  // check_argv(1,2,3,4,255);
  vul(filename);
  printf("   FAIL\n");
  printf(" * Control flow wasn't be hijacked\n");
  return 0;
}
