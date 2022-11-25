#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <fcntl.h>
#include <unistd.h>

#include "../src/enclave.c"
#include "../src/attest.c"

/*
Use the following command to geneerate rt.bin
riscv64-unknown-linux-gnu-objcopy -O binary /home/sichunqin/code/github/sichunqin/keystone/build/overlay/root/eyrie-rt rt.bin
*/
#define public_key_path  "/home/sichunqin/code/github/sichunqin/keystone/keystone-tools/rt_root_key/root_key.pub"
#define binary_path "rt.bin"

void printBytes(unsigned char *address, int size) {
    int count;
    for (count = 0; count < size; count++){
        printf("%.2x", address[count]);
    }
    printf("\n");
}

static void test_verify_rt_sig()
{
  print_message("test is starting...\n");
  const char *uptime_path;

  unsigned char public_key[32] = {0};
  unsigned char buf[32768] = {0};
  ssize_t nread;
  int fd_pub_key = -1;
  int fd_binary = -1;

  fd_pub_key = open(public_key_path, O_RDONLY);
  assert_true(fd_pub_key >= 0 );

  nread = read(fd_pub_key, public_key, sizeof(public_key));
  assert_int_equal(nread,32);

  fd_binary = open(binary_path, O_RDONLY);
  nread = read(fd_binary, buf, sizeof(buf));

 // assert_int_equal(nread,20677);
  close(fd_pub_key);
  close(fd_binary);
  unsigned char * end = buf + nread -1;
  print_message("buf value is %x, buf end value is %x\n, public key value is %x \n ", buf ,end, public_key);

  int r = validate_signature((uintptr_t) buf, (uintptr_t)(end), public_key);

  print_message("nread:  %d\n", nread);
  printBytes(buf,1024);

  assert_true(r==0);
}



int main()
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_verify_rt_sig)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
