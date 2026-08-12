#include "mlkem_decaps_hw.h"
#define REG_CONTROL 0x04u
#define REG_STATUS 0x08u
#define REG_SLOT 0x0cu
#define REG_SESSION 0x10u
#define REG_MEM_REGION 0x20u
#define REG_MEM_ADDR 0x24u
#define REG_MEM_DATA 0x28u
#define REGION_SK 0u
#define REGION_CT 1u
static void wr(const mlkem_decaps_hw_t*d,uint32_t o,uint32_t v){
    *(volatile uint32_t*)(d->base+(uintptr_t)o)=v;}
static uint32_t rd(const mlkem_decaps_hw_t*d,uint32_t o){
    return *(volatile const uint32_t*)(d->base+(uintptr_t)o);}
static uint32_t le32(const uint8_t*p){return (uint32_t)p[0]|(uint32_t)p[1]<<8|
    (uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static int load(mlkem_decaps_hw_t*d,uint32_t region,const uint8_t*p,size_t n){
    size_t i;if(!d||!p||(n&3u))return MLKEM_HW_ARGUMENT;
    wr(d,REG_MEM_REGION,region);wr(d,REG_MEM_ADDR,0);
    for(i=0;i<n;i+=4)
        wr(d,REG_MEM_DATA,le32(p+i));
    return MLKEM_HW_OK;
}
void mlkem_decaps_hw_init(mlkem_decaps_hw_t*d,uintptr_t base,uint32_t limit){
    if(d){d->base=base;d->poll_limit=limit?limit:10000000u;}}
int mlkem_decaps_hw_load_secret_key(mlkem_decaps_hw_t*d,const uint8_t sk[1632]){
    return load(d,REGION_SK,sk,MLKEM512_SECRET_KEY_BYTES);}
int mlkem_decaps_hw_start(mlkem_decaps_hw_t*d,const uint8_t ct[768],uint8_t slot,
                          uint32_t session_id){int r;if(!d||!ct||slot>=4)return MLKEM_HW_ARGUMENT;
    r=load(d,REGION_CT,ct,MLKEM512_CIPHERTEXT_BYTES);if(r)return r;
    wr(d,REG_SLOT,slot);wr(d,REG_SESSION,session_id);wr(d,REG_CONTROL,1u<<8);
    wr(d,REG_CONTROL,1u);return MLKEM_HW_OK;}
int mlkem_decaps_hw_wait(mlkem_decaps_hw_t*d){uint32_t i,s;if(!d)return MLKEM_HW_ARGUMENT;
    for(i=0;i<d->poll_limit;i++){s=rd(d,REG_STATUS);if(s&(1u<<2))
        return (s&(1u<<3))?MLKEM_HW_REJECTED:MLKEM_HW_OK;}return MLKEM_HW_TIMEOUT;}
