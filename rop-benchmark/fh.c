#include <stdio.h>


int main()
{
  setbuf(stdout,0);
  setbuf(stdin,0);
  setbuf(stderr,0);
  puts("SUCCESS");
  puts("PARAMETERS ARE CORRECT");
  return 0;
}
