#include <stdint.h>

asm(R"(
    .section .text
    .align 2
.word write_sram_patched + 1
.word write_eeprom_patched + 1
.word read_sram_patched + 1
.word read_eeprom_patched + 1
.word verify_sram_patched + 1
.word verify_eeprom_patched + 1
.word write_eeprom_fixed6_patched + 1
.word read_eeprom_fixed6_patched + 1
.word verify_eeprom_fixed6_patched + 1
eeprom_meta:
.word 0)");

struct eeprom_meta
{
    unsigned size;
    unsigned short addrs;
    unsigned short wait;
    unsigned char addr_bits;
};

__attribute__((noinline)) struct eeprom_meta *get_eeprom_meta()
{
    struct eeprom_meta ***eeprom_meta_ptrptr;
    asm volatile (
        ".align 2\n\t"
        "mov %[eeprom_meta_ptrptr], pc\n\t"
        "sub %[eeprom_meta_ptrptr], # . + 2 - eeprom_meta" 
        : [eeprom_meta_ptrptr] "=r" (eeprom_meta_ptrptr)
    );
    return **eeprom_meta_ptrptr;
}

#define SRAM_BASE ((volatile unsigned char*) (0x0E000000))
#define FLASH_MAGIC_0 (0x5555)
#define FLASH_MAGIC_1 (0x2AAA)
#define SCRATCH_BUF_ADDR (0x0203F800)
#define SCRATCH_BUF_SIZE (2048)
#define FLASH_MAX_ATTEMPTS 3

#define PROTO_AMD_JEDEC 0
#define PROTO_INTEL_SHARP 1

#define MFR_INTEL    0x89
#define MFR_SHARP_A  0xB0
#define MFR_SHARP_B  0x05
#define MFR_NUMONYX  0x20

static int detect_flash_type(void)
{
    SRAM_BASE[FLASH_MAGIC_0] = 0xAA;
    SRAM_BASE[FLASH_MAGIC_1] = 0x55;
    SRAM_BASE[FLASH_MAGIC_0] = 0x90;
    __asm("nop");
    unsigned char m_id = SRAM_BASE[0x0000];

    SRAM_BASE[0x0000] = 0xF0;
    __asm("nop");

    if (m_id == MFR_INTEL || m_id == MFR_SHARP_A || m_id == MFR_SHARP_B || m_id == MFR_NUMONYX)
    {
        SRAM_BASE[0x0000] = 0xFF;
        __asm("nop");
        return PROTO_INTEL_SHARP;
    }
    return PROTO_AMD_JEDEC;
}

#define FLASH_PROTO_CACHE (*(volatile unsigned *) (SCRATCH_BUF_ADDR - 8))
#define FLASH_PROTO_MAGIC (0x50524FU)          

static int flash_protocol(void)
{
    unsigned cached = FLASH_PROTO_CACHE;
    if ((cached >> 8) == FLASH_PROTO_MAGIC)
    {
        unsigned p = cached & 0xFF;
        if (p == PROTO_AMD_JEDEC || p == PROTO_INTEL_SHARP)
            return (int) p;
    }
	int p = detect_flash_type();
    FLASH_PROTO_CACHE = (FLASH_PROTO_MAGIC << 8) | (unsigned) p;
    return p;
}

static int flashWaitData(volatile unsigned char *tgt, unsigned char expected, int protocol)
{
    if (protocol == PROTO_INTEL_SHARP) {
        volatile unsigned char sr;
        unsigned char error_mask = (expected == 0xFF) ? 0x20 : 0x10;
        do {
            sr = *tgt;
            if (sr & 0x80) {
                if (sr & error_mask) {
                    *tgt = 0x50;
                    *tgt = 0xFF;
                    return 0;
                }
                *tgt = 0xFF;
                return 1;
            }
        } while (!(sr & error_mask));
        *tgt = 0x50;
        *tgt = 0xFF;
        return 0;
    }

    unsigned char value = expected & 0x80;
    volatile unsigned char a;
    do {
        a = *tgt;
        if ((a & 0x80) == value)
            return 1;            
    } while (!(a & 0x20));
    if ((*tgt & 0x80) == value)
		return 1; 
	*tgt = 0xF0;
	__asm("nop");
	return 0;
}

static void flashEraseSector(volatile unsigned char *tgt, int protocol)
{
    for (int attempt = 0; attempt < FLASH_MAX_ATTEMPTS; ++attempt)
    {
        if (protocol == PROTO_AMD_JEDEC) {
            SRAM_BASE[FLASH_MAGIC_0] = 0xAA;
            SRAM_BASE[FLASH_MAGIC_1] = 0x55;
            SRAM_BASE[FLASH_MAGIC_0] = 0x80;
            SRAM_BASE[FLASH_MAGIC_0] = 0xAA;
            SRAM_BASE[FLASH_MAGIC_1] = 0x55;
            *tgt = 0x30;
        } else {
            *tgt = 0x20;
            *tgt = 0xD0;
        }
        __asm("nop");
        int settled = flashWaitData(tgt, 0xFF, protocol);
		if (settled)
		{
			if (*tgt == 0xFF)
				return;
			*tgt = (protocol == PROTO_AMD_JEDEC) ? 0xF0 : 0xFF;
			__asm("nop");
		}
	}			
}

static void flashProgramByte(volatile unsigned char *tgt, unsigned char data, int protocol)
{
    for (int attempt = 0; attempt < FLASH_MAX_ATTEMPTS; ++attempt)
    {
        if (protocol == PROTO_AMD_JEDEC) {
            SRAM_BASE[FLASH_MAGIC_0] = 0xAA;
            SRAM_BASE[FLASH_MAGIC_1] = 0x55;
            SRAM_BASE[FLASH_MAGIC_0] = 0xA0;
            *tgt = data;
        } else {
            *tgt = 0x40;
            *tgt = data;
        }
        __asm("nop");
        int settled = flashWaitData(tgt, data, protocol);
		if (settled)
		{
			if (*tgt == data)
				return;
			*tgt = (protocol == PROTO_AMD_JEDEC) ? 0xF0 : 0xFF;
			__asm("nop");
		}
	}
}
int my_memcpy(unsigned char *dst, int dstride, unsigned char *src, int sstride, unsigned size)
{
    int hits = 0;
    while (size)
    {
        if (*dst != *src)
            ++hits;
        *dst = *src;
        dst += dstride;
        src += sstride;
        --size;
    }
    return hits;
}

unsigned char *translate(unsigned idx, int loadfactor_log2)
{
    return (unsigned char *) (0x0E000000 | idx << loadfactor_log2);
}

void write_core_patched(unsigned char *src, unsigned idx, unsigned size, int loadfactor_log2)
{
    int protocol = flash_protocol();
    unsigned sector_usage = 0x1000 >> loadfactor_log2;
    unsigned char *sector_buf = (unsigned char *) SCRATCH_BUF_ADDR;
    
    while (size)
    {
        int prefix = (sector_usage - 1) & idx;
        unsigned char *sector = translate(idx - prefix, loadfactor_log2);
        int len = size;
        if (len + prefix > sector_usage)
        {
            len = sector_usage;
            len -= prefix;      
        }              
        int need_erase = 0;
        for (int i = 0; i < len; ++i)
        {
            unsigned char oldb = sector[(prefix + i) << loadfactor_log2];
            unsigned char newb = src[i];
            if (oldb == newb)
                continue;
            if ((unsigned char) (oldb & newb) != newb)
            {
                need_erase = 1;
                break;
            }
        }
        if (need_erase)
        {
            my_memcpy(sector_buf, 1, sector, 1 << loadfactor_log2, sector_usage);
            my_memcpy(sector_buf + prefix, 1, src, 1, len);
            flashEraseSector(sector, protocol);
            for (int i = 0; i < sector_usage; ++i)
            {
                if (sector_buf[i] != 0xFF)
					flashProgramByte(&sector[i << loadfactor_log2], sector_buf[i], protocol);
            }
        }
        else
        {
            for (int i = 0; i < len; ++i)
            {
                unsigned char oldb = sector[(prefix + i) << loadfactor_log2];
                unsigned char newb = src[i];
                if (oldb != newb)
					flashProgramByte(&sector[(prefix + i) << loadfactor_log2], newb, protocol);
            }
        }     
        src += len;
        idx += len;
        size -= len;
    }
}

void read_core_patched(unsigned char *dst, unsigned idx, unsigned size, int loadfactor_log2)
{
    my_memcpy(dst, 1, translate(idx, loadfactor_log2), 1 << loadfactor_log2, size);
}

int verify_core_patched(unsigned char *src, unsigned idx, unsigned size, int loadfactor_log2)
{
    while (size)
    {
        if (*src != *translate(idx, loadfactor_log2))
            return idx;        
        ++src;
        ++idx;
        --size;
    }
    return -1;
}

void write_sram_patched(unsigned char *src, unsigned char *dst, unsigned size)
{
    if (((unsigned) dst & 0xFF000000) == 0x0E000000)
    {
        write_core_patched(src, 0x00007FFF & (unsigned) dst, size, 1);
    }
    else if (((unsigned) src & 0xFF000000) == 0x0E000000)
    {
        read_core_patched(dst, 0x00007FFF & (unsigned) src, size, 1);
    }
    else
    {
        my_memcpy(dst, 1, src, 1, size);
    }
}

void read_sram_patched(unsigned char *src, unsigned char *dst, unsigned size)
{
    write_sram_patched(src, dst, size);
}

unsigned char *verify_sram_patched(unsigned char *src, unsigned char *tgt, unsigned size)
{
    unsigned char *ram;
    unsigned idx;
    if (((unsigned) tgt & 0xFF000000) == 0x0E000000)
    {
        idx = 0x00007FFF & (unsigned) tgt;
        ram = src;
    }
    else if (((unsigned) src & 0xFF000000) == 0x0E000000)
    {
        idx = 0x00007FFF & (unsigned) src;
        ram = tgt;
    }
    else
    {
        while (size)
        {
            if (*src != *tgt)
                return tgt;
            ++src;
            ++tgt;
            --size;
        }
        return 0;
    }
    int error_idx = verify_core_patched(ram, idx, size, 1);
    return error_idx < 0 ? 0 : (unsigned char *) (0x0E000000 | error_idx);
}

unsigned write_eeprom_patched(unsigned short addr, unsigned char *src)
{
    struct eeprom_meta *eeprom_meta = get_eeprom_meta();
    if (!eeprom_meta)
        return 1;
    int loadfactor_log2 = eeprom_meta->addrs == 0x40 ? 7 : 3;
    write_core_patched(src, addr << 3, 1 << 3, loadfactor_log2);
    return 0;
}

unsigned read_eeprom_patched(unsigned short addr, unsigned char *dst)
{
    struct eeprom_meta *eeprom_meta = get_eeprom_meta();
    if (!eeprom_meta)
        return 1;
    int loadfactor_log2 = eeprom_meta->addrs == 0x40 ? 7 : 3;
    read_core_patched(dst, addr << 3, 1 << 3, loadfactor_log2);
    return 0;
}

unsigned verify_eeprom_patched(unsigned short addr, unsigned char *src)
{   
    struct eeprom_meta *eeprom_meta = get_eeprom_meta();
    if (!eeprom_meta)
        return 1;
    int loadfactor_log2 = eeprom_meta->addrs == 0x40 ? 7 : 3;
    return verify_core_patched(src, addr << 3, 1 << 3, loadfactor_log2) >= 0;
}

#define EEPROM_FIXED6_LOADFACTOR_LOG2 7

unsigned write_eeprom_fixed6_patched(unsigned short addr, unsigned char *src)
{
    write_core_patched(src, addr << 3, 1 << 3, EEPROM_FIXED6_LOADFACTOR_LOG2);
    return 0;
}

unsigned read_eeprom_fixed6_patched(unsigned short addr, unsigned char *dst)
{
    read_core_patched(dst, addr << 3, 1 << 3, EEPROM_FIXED6_LOADFACTOR_LOG2);
    return 0;
}

unsigned verify_eeprom_fixed6_patched(unsigned short addr, unsigned char *src)
{
    return verify_core_patched(src, addr << 3, 1 << 3,
                               EEPROM_FIXED6_LOADFACTOR_LOG2) < 0 ? 0 : 0x8000;
}
