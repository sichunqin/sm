//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "enclave.h"
#include "crypto.h"
#include "page.h"
#include <sbi/sbi_console.h>
#include <sbi/sbi_string.h>

typedef uintptr_t pte_t;

#define MAGIC_NUMBER_SIZE 4
struct embedded_data {
  byte magic_number[MAGIC_NUMBER_SIZE];             //!emb ASCII code.
  byte protocol_version;                             //Current version is 0.
  byte public_key[PUBLIC_KEY_SIZE];                  //RT or Eapp public key
  byte public_key_signature[SIGNATURE_SIZE];         //The RT or Eapp public key signed by RT or Eapp root private key
  byte image_signature[SIGNATURE_SIZE];              //RT or Eapp image signature.
  byte encrypted_enc_key[ENC_KEY_SIZE];              //RT or Eapp encryption key protected by RT or Eapp root enc key.
};

extern byte _rt_root_public_key[PUBLIC_KEY_SIZE];
extern byte _eapp_root_public_key[PUBLIC_KEY_SIZE];

/* This will walk the entire vaddr space in the enclave, validating
   linear at-most-once paddr mappings, and then hashing valid pages */
int validate_and_hash_epm(hash_ctx* hash_ctx, int level,
                          pte_t* tb, uintptr_t vaddr, int contiguous,
                          struct enclave* encl,
                          uintptr_t* runtime_max_seen,
                          uintptr_t* user_max_seen)
{
  pte_t* walk;
  int i;

  //TODO check for failures
  uintptr_t epm_start, epm_size;
  uintptr_t utm_start, utm_size;
  int idx = get_enclave_region_index(encl->eid, REGION_EPM);
  epm_start = pmp_region_get_addr(encl->regions[idx].pmp_rid);
  epm_size = pmp_region_get_size(encl->regions[idx].pmp_rid);
  idx = get_enclave_region_index(encl->eid, REGION_UTM);
  utm_start = pmp_region_get_addr(encl->regions[idx].pmp_rid);
  utm_size = pmp_region_get_size(encl->regions[idx].pmp_rid);



  /* iterate over PTEs */
  for (walk=tb, i=0; walk < tb + (RISCV_PGSIZE/sizeof(pte_t)); walk += 1,i++)
  {
    if (*walk == 0) {
      contiguous = 0;
      continue;
    }
    uintptr_t vpn;
    uintptr_t phys_addr = (*walk >> PTE_PPN_SHIFT) << RISCV_PGSHIFT;

    /* Check for blatently invalid mappings */
    int map_in_epm = (phys_addr >= epm_start &&
                      phys_addr < epm_start + epm_size);
    int map_in_utm = (phys_addr >= utm_start &&
                      phys_addr < utm_start + utm_size);

    /* EPM may map anything, UTM may not map pgtables */
    if(!map_in_epm && (!map_in_utm || level != 1)){
      goto fatal_bail;
    }


    /* propagate the highest bit of the VA */
    if ( level == RISCV_PGLEVEL_TOP && i & RISCV_PGTABLE_HIGHEST_BIT )
      vpn = ((-1UL << RISCV_PGLEVEL_BITS) | (i & RISCV_PGLEVEL_MASK));
    else
      vpn = ((vaddr << RISCV_PGLEVEL_BITS) | (i & RISCV_PGLEVEL_MASK));

    uintptr_t va_start = vpn << RISCV_PGSHIFT;

    /* include the first virtual address of a contiguous range */
    if (level == 1 && !contiguous)
    {

      hash_extend(hash_ctx, &va_start, sizeof(uintptr_t));
      //printm("VA hashed: 0x%lx\n", va_start);
      contiguous = 1;
    }

    if (level == 1)
    {

      /*
       * This is where we enforce the at-most-one-mapping property.
       * To make our lives easier, we also require a 'linear' mapping
       * (for each of the user and runtime spaces independently).
       *
       * That is: Given V1->P1 and V2->P2:
       *
       * V1 < V2  ==> P1 < P2  (Only for within a given space)
       *
       * V1 != V2 ==> P1 != P2
       *
       * We also validate that all utm vaddrs -> utm paddr`+--+-+s
       */
      int in_runtime = ((phys_addr >= encl->pa_params.runtime_base) &&
                        (phys_addr < encl->pa_params.user_base));
      int in_user = ((phys_addr >= encl->pa_params.user_base) &&
                     (phys_addr < encl->pa_params.free_base));

      /* Validate U bit */
      if(in_user && !(*walk & PTE_U)){
        goto fatal_bail;
      }

      /* If the vaddr is in UTM, the paddr must be in UTM */
      if(va_start >= encl->params.untrusted_ptr &&
         va_start < (encl->params.untrusted_ptr + encl->params.untrusted_size) &&
         !map_in_utm){
        goto fatal_bail;
      }

      /* Do linear mapping validation */
      if(in_runtime){
        if(phys_addr <= *runtime_max_seen){
          goto fatal_bail;
        }
        else{
          *runtime_max_seen = phys_addr;
        }
      }
      else if(in_user){
        if(phys_addr <= *user_max_seen){
          goto fatal_bail;
        }
        else{
          *user_max_seen = phys_addr;
        }
      }
      else if(map_in_utm){
        // we checked this above, its OK
      }
      else{
        //printm("BAD GENERIC MAP %x %x %x\n", in_runtime, in_user, map_in_utm);
        goto fatal_bail;
      }

      /* Page is valid, add it to the hash */

      /* if PTE is leaf, extend hash for the page */
      hash_extend_page(hash_ctx, (void*)phys_addr);



      //printm("PAGE hashed: 0x%lx (pa: 0x%lx)\n", vpn << RISCV_PGSHIFT, phys_addr);
    }
    else
    {
      /* otherwise, recurse on a lower level */
      contiguous = validate_and_hash_epm(hash_ctx,
                                         level - 1,
                                         (pte_t*) phys_addr,
                                         vpn,
                                         contiguous,
                                         encl,
                                         runtime_max_seen,
                                         user_max_seen);
      if(contiguous == -1){
        sbi_printf("BAD MAP: %lx->%lx epm %x %lx uer %x %lx\n",
               va_start,phys_addr,
               //in_runtime,
               0,
               encl->pa_params.runtime_base,
               0,
               //in_user,
               encl->pa_params.user_base);
        goto fatal_bail;
      }
    }
  }

  return contiguous;

 fatal_bail:
  return -1;
}
unsigned long validate_signature(uintptr_t start,uintptr_t end, const unsigned char* root_pub_key){

  unsigned char magic[] = "!emb";
  bool embed_found = false;
  uintptr_t temp = start;

  while(temp < end){

    if(sbi_memcmp((const void*) temp, (const void*)magic,4) == 0){
        embed_found = true;
        int sz = temp - start;
        struct embedded_data * embed = (struct embedded_data *) temp;

        //Need to verify public key first, then image
        if(ed25519_verify((const unsigned char*) embed->public_key_signature,
                          (const unsigned char *)embed->public_key,
                          (size_t)PUBLIC_KEY_SIZE,
                          (const unsigned char *)root_pub_key) == 0)
        {
          sbi_printf("Pub key is wrong!\n");
          return SBI_ERR_SM_ENCLAVE_PUB_KEY_WRONG;
        }
        else{
          sbi_printf("Pub key is correct!\n");
        }
        if(ed25519_verify((const unsigned char*) embed->image_signature,
                          (const unsigned char *)start,
                          (size_t) sz,
                          (const unsigned char *)embed->public_key) == 0)
        {
          sbi_printf("Signature is wrong!\n");
          return SBI_ERR_SM_ENCLAVE_SIG_WRONG;
        }
        else{
          sbi_printf("Signature is correct!\n");
        }
    }
    temp = temp + 4096;
  }
  if(!embed_found){
    return SBI_ERR_SM_ENCLAVE_NO_EMBED_FOUND;
  }
  return 0;
}


unsigned long validate_epm_signanture(struct enclave* enclave){

  uintptr_t runtime_base = enclave->pa_params.runtime_base;
  uintptr_t user_base = enclave->pa_params.user_base;
  uintptr_t free_base = enclave->pa_params.free_base;

  sbi_printf("runtime_base: 0x%lx: user_base: 0x%lx  free_base: 0x%lx \n", runtime_base, user_base,free_base);

  int rt_valid = validate_signature(runtime_base,
                                    user_base-1,
                                    (const unsigned char *)_rt_root_public_key);
  if(rt_valid > 0) return rt_valid;

  int eapp_valid = validate_signature(user_base,
                                      free_base-1,
                                      (const unsigned char *)_eapp_root_public_key);
  if(eapp_valid > 0) return eapp_valid;
  return 0;
}

unsigned long validate_and_hash_enclave(struct enclave* enclave){
#ifdef VALIDATE_EPM_SIG
  unsigned long valid_sig = validate_epm_signanture(enclave);
  if(valid_sig > 0) return valid_sig;
#endif
  hash_ctx hash_ctx;
  int ptlevel = RISCV_PGLEVEL_TOP;

  hash_init(&hash_ctx);

  // hash the runtime parameters
  hash_extend(&hash_ctx, &enclave->params, sizeof(struct runtime_va_params_t));


  uintptr_t runtime_max_seen=0;
  uintptr_t user_max_seen=0;;

  // hash the epm contents including the virtual addresses
  int valid = validate_and_hash_epm(&hash_ctx,
                                    ptlevel,
                                    (pte_t*) (enclave->encl_satp << RISCV_PGSHIFT),
                                    0, 0, enclave, &runtime_max_seen, &user_max_seen);

  if(valid == -1){
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_PTE;
  }

  hash_finalize(enclave->hash, &hash_ctx);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

