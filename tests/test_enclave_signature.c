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
riscv64-unknown-linux-gnu-objcopy -O binary /home/sichunqin/code/github/sichunqin/keystone/build/overlay/root/eyrie-rt.patch ../test_files/rt.bin
riscv64-unknown-linux-gnu-objcopy -O binary /home/sichunqin/code/github/sichunqin/keystone/build/overlay/root/hello-world/hello-world.patch ../test_files/eapp.bin
*/
#define rt_root_public_key_path  "/home/sichunqin/code/github/sichunqin/keystone/keystone-tools/rt_root_key/root_key.pub"
#define eapp_root_public_key_path  "/home/sichunqin/code/github/sichunqin/keystone/keystone-tools/eapp_root_key/root_key.pub"
#define rt_root_enc_key_path  "/home/sichunqin/code/github/sichunqin/keystone/keystone-tools/rt_root_key/root_key.enc"
#define eapp_root_enc_key_path  "/home/sichunqin/code/github/sichunqin/keystone/keystone-tools/eapp_root_key/root_key.enc"

//#define rt_binary_path "../test_files/rt.bin"
#define rt_binary_path "../test_files//eyrie-rt.enc.signed.bin"
#define rt_ori_binary_path "../test_files/eyrie-rt.bin"      // Original unpatched binary, no signature, no encrypted.

#define eapp_binary_path "../test_files/hello-world.signed.bin"

//#define rt_ori_binary_path "../test_files/ori_rt.bin"      // Original unpatched binary, no signature, no encrypted.


#define eapp_ori_binary_path "../test_files/hello-world.bin"



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

  fd_pub_key = open(rt_root_public_key_path, O_RDONLY);
  assert_true(fd_pub_key >= 0 );

  nread = read(fd_pub_key, public_key, sizeof(public_key));
  assert_int_equal(nread,32);

  fd_binary = open(rt_binary_path, O_RDONLY);
  nread = read(fd_binary, buf, sizeof(buf));

 // assert_int_equal(nread,20677);
  close(fd_pub_key);
  close(fd_binary);
  unsigned char * end = buf + nread -1;

  void * embed = find_embed((uintptr_t) buf, (uintptr_t)(end));
  print_message("buf: %x end: %x embed:  %x\n", buf,end,embed);
  int r = validate_enclave_signature((uintptr_t) buf, (uintptr_t)(embed), public_key);

  print_message("nread:  %d\n", nread);
  printBytes(buf,1024);

  assert_true(r==0);
}

static void test_verify_eapp_sig()
{
  print_message("test is starting...\n");

  unsigned char public_key[32] = {0};
  unsigned char buf[32768] = {0};
  ssize_t nread;
  int fd_pub_key = -1;
  int fd_binary = -1;

  fd_pub_key = open(eapp_root_public_key_path, O_RDONLY);
  assert_true(fd_pub_key >= 0 );

  nread = read(fd_pub_key, public_key, sizeof(public_key));
  assert_int_equal(nread,32);

  fd_binary = open(eapp_binary_path, O_RDONLY);
  nread = read(fd_binary, buf, sizeof(buf));

 // assert_int_equal(nread,20677);
  close(fd_pub_key);
  close(fd_binary);
  unsigned char * end = buf + nread -1;
  print_message("buf value is %x, buf end value is %x\n, public key value is %x \n ", buf ,end, public_key);

  void * embed = find_embed((uintptr_t) buf, (uintptr_t)(end));
  int r = validate_enclave_signature((uintptr_t) buf, (uintptr_t)(embed), public_key);

  print_message("nread:  %d\n", nread);
  printBytes(buf,1024);

  assert_true(r==0);
}

static void test_decrypt_rt()
{
  print_message("test is starting...\n");

  unsigned char root_enc_key[32] = {0};
  unsigned char buf[32768] = {0};
  unsigned char ori_buf[20480];
  ssize_t nread, binary_size;
  int fd_root_enc_key = -1;
  int fd_binary = -1;

  fd_root_enc_key = open(rt_root_enc_key_path, O_RDONLY);
  assert_true(fd_root_enc_key >= 0 );

  nread = read(fd_root_enc_key, root_enc_key, sizeof(root_enc_key));
  assert_int_equal(nread,32);

  fd_binary = open(rt_binary_path, O_RDONLY);
  nread = read(fd_binary, buf, sizeof(buf));

 // assert_int_equal(nread,20677);
  close(fd_root_enc_key);
  close(fd_binary);
  unsigned char * end = buf + nread -1;

  int len = 20480;

  printBytes(buf,256);

  void * embed = find_embed((uintptr_t) buf, (uintptr_t)(end));
  decrypt_enclave_binary((uintptr_t) buf, (uintptr_t)(embed), root_enc_key);
  printBytes(buf,256);
  int fd_ori_binary = open(rt_ori_binary_path, O_RDONLY);
  read(fd_ori_binary, ori_buf, 20480);
  printBytes(buf,256);

  printBytes(ori_buf,256);
  assert_int_equal(memcmp(buf,ori_buf, len), 0);
}

static void test_decrypt_eapp()
{
  unsigned char root_enc_key[32] = {0};
  unsigned char buf[32768] = {0};
  unsigned char ori_buf[20480];
  ssize_t nread, binary_size;
  int fd_root_enc_key = -1;
  int fd_binary = -1;

  fd_root_enc_key = open(rt_root_enc_key_path, O_RDONLY);
  assert_true(fd_root_enc_key >= 0 );

  nread = read(fd_root_enc_key, root_enc_key, sizeof(root_enc_key));
  assert_int_equal(nread,32);

  fd_binary = open(eapp_binary_path, O_RDONLY);
  nread = read(fd_binary, buf, sizeof(buf));

 // assert_int_equal(nread,20677);
  close(fd_root_enc_key);
  close(fd_binary);
  unsigned char * end = buf + nread -1;



  printBytes(buf,256);

  void * embed = find_embed((uintptr_t) buf, (uintptr_t)(end));
  decrypt_enclave_binary((uintptr_t) buf, (uintptr_t)(embed), root_enc_key);
  printBytes(buf,256);
  int fd_ori_binary = open(eapp_ori_binary_path, O_RDONLY);
  read(fd_ori_binary, ori_buf, 20480);
  printBytes(buf,256);

  printBytes(ori_buf,256);
  int len = (unsigned char*) embed - buf;
  assert_int_equal(memcmp(buf,ori_buf, len), 0);
}

int main()
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_verify_rt_sig),
    cmocka_unit_test(test_verify_eapp_sig),
    cmocka_unit_test(test_decrypt_rt),
    cmocka_unit_test(test_decrypt_eapp),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
