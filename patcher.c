#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "payload_bin.h"

FILE *romfile;
FILE *outfile;
uint32_t romsize;
uint8_t rom[0x02000000];

enum payload_offsets {
    WRITE_SRAM_PATCHED,
    WRITE_EEPROM_PATCHED,
    READ_SRAM_PATCHED,
    READ_EEPROM_PATCHED,
    VERIFY_SRAM_PATCHED,
    VERIFY_EEPROM_PATCHED,
    WRITE_EEPROM_FIXED6_PATCHED,
    READ_EEPROM_FIXED6_PATCHED,
    VERIFY_EEPROM_FIXED6_PATCHED,
    EEPROM_META
};

static unsigned char thumb_branch_thunk[] = { 0x00, 0x4b, 0x18, 0x47 };
static unsigned char arm_branch_thunk[] = { 0x00, 0x30, 0x9f, 0xe5, 0x13, 0xff, 0x2f, 0xe1 };

static unsigned char write_sram_generic_sig[] = {
    0x30, 0xB5, 0x05, 0x1C, 0x0C, 0x1C, 0x13, 0x1C, 0x0B, 0x4A, 0x10, 0x88, 0x0B, 0x49, 0x08, 0x40,
    0x03, 0x21, 0x08, 0x43, 0x10, 0x80, 0x01, 0x3B, 0x01, 0x20, 0x40, 0x42, 0x83, 0x42, 0x07, 0xD0,
    0x01, 0x1C, 0x28, 0x78, 0x20, 0x70, 0x01, 0x35 };
static int write_sram_generic_wild[] = {
    0,0,0,0,0,0,0,0, 1,0,0,0, 1,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0,0,0,0,0 };
static unsigned char verify_sram_generic_sig[] = {
    0x30, 0xB5, 0x05, 0x1C, 0x0C, 0x1C, 0x13, 0x1C, 0x0A, 0x4A, 0x10, 0x88, 0x0A, 0x49, 0x08, 0x40,
    0x03, 0x21, 0x08, 0x43, 0x10, 0x80, 0x01, 0x3B, 0x01, 0x20, 0x40, 0x42, 0x83, 0x42, 0x10, 0xD0,
    0x02, 0x1C, 0x21, 0x78, 0x28, 0x78, 0x01, 0x35 };
static int verify_sram_generic_wild[] = {
    0,0,0,0,0,0,0,0, 1,0,0,0, 1,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0,0,0,0,0 };
static unsigned char write_sram2_signature[] = { 0x80, 0xb5, 0x83, 0xb0, 0x6f, 0x46, 0x38, 0x60, 0x79, 0x60, 0xba, 0x60, 0x09, 0x48, 0x09, 0x49 };
static unsigned char write_sram_ram_signature[] = { 0x04, 0xC0, 0x90, 0xE4, 0x01, 0xC0, 0xC1, 0xE4, 0x2C, 0xC4, 0xA0, 0xE1, 0x01, 0xC0, 0xC1, 0xE4 };
static unsigned char read_sram_signature[] = { 0x70, 0xB5, 0xA0, 0xB0, 0x04, 0x1C, 0x0D, 0x1C, 0x16, 0x1C, 0x08, 0x4A, 0x10, 0x88, 0x08, 0x49};
static unsigned char verify_sram_signature[] = { 0x70, 0xB5, 0xB0, 0xB0, 0x04, 0x1C, 0x0D, 0x1C, 0x16, 0x1C, 0x08, 0x4A, 0x10, 0x88, 0x08, 0x49 };
static unsigned char verify_sram_push4_sig[] = {
    0x90, 0xB5, 0x83, 0xB0, 0x6F, 0x46, 0x38, 0x60, 0x79, 0x60, 0xBA, 0x60, 0x09, 0x48, 0x09, 0x49,
    0x0A, 0x88, 0x09, 0x4B, 0x11, 0x1C, 0x19, 0x40, 0x0A, 0x1C, 0x03, 0x23, 0x11, 0x1C, 0x19, 0x43,
    0x0A, 0x1C, 0x02, 0x80, 0xB8, 0x68, 0x41, 0x1E, 0x08, 0x1C, 0xB8, 0x60, 0x01, 0x21, 0xC8, 0x42,
    0x04, 0xD1, 0x13, 0xE0, 0x04, 0x02, 0x00, 0x04, 0xFC, 0xFF, 0x00, 0x00, 0x38, 0x1D, 0x01, 0x68,
    0x3C, 0x68, 0x0A, 0x78, 0x23, 0x78, 0x01, 0x34, 0x3C, 0x60, 0x01, 0x31, 0x01, 0x60, 0x9A, 0x42,
    0x03, 0xD0 };
static unsigned char sram_ramexec_copy_sig[] = {
    0x90, 0xB4, 0x0A, 0x4F, 0x0A, 0x4B, 0xBC, 0x88, 0x1C, 0x40, 0x03, 0x23, 0x23, 0x43, 0xBB, 0x80,
    0x53, 0x1E, 0x00, 0x2A, 0x07, 0xD0, 0x02, 0x78, 0x01, 0x30, 0x0A, 0x70, 0x1A, 0x1C, 0x01, 0x3B,
    0x01, 0x31, 0x00, 0x2A };
static unsigned char sram_ramexec_verify_sig[] = {
    0x90, 0xB4, 0x0C, 0x4F, 0x0C, 0x4B, 0xBC, 0x88, 0x1C, 0x40, 0x03, 0x23, 0x23, 0x43, 0xBB, 0x80,
    0x53, 0x1E, 0x00, 0x2A, 0x0C, 0xD0, 0x0F, 0x78, 0x02, 0x78, 0x01, 0x30, 0x01, 0x31, 0x97, 0x42,
    0x02, 0xD0, 0x48, 0x1E, 0x90, 0xBC, 0x70, 0x47 };
static unsigned char write_sram_push4reg_sig[] = {
    0xF0, 0xB5, 0x04, 0x1C, 0x0E, 0x1C, 0x15, 0x1C, 0x03, 0x4A, 0x10, 0x88, 0x03, 0x49, 0x08, 0x40,
    0x03, 0x21, 0x08, 0x43, 0x10, 0x80, 0x0A, 0xE0, 0x04, 0x02, 0x00, 0x04, 0xFC, 0xFF, 0x00, 0x00,
    0x20, 0x78, 0x30, 0x70, 0x01, 0x34, 0x01, 0x36, 0x01, 0x3D, 0x00, 0x2D };
static unsigned char write_sram_standalone_sig[] = {
    0x10, 0xB5, 0x04, 0x1C, 0x53, 0x1E, 0x00, 0x2A, 0x08, 0xD0, 0x01, 0x22, 0x52, 0x42, 0x20, 0x78,
    0x08, 0x70, 0x01, 0x34, 0x01, 0x31, 0x01, 0x3B, 0x93, 0x42, 0xF8, 0xD1, 0x10, 0xBC };
static unsigned char verify_sram_standalone_sig[] = {
    0x30, 0xB5, 0x05, 0x1C, 0x0B, 0x1C, 0x54, 0x1E, 0x00, 0x2A, 0x0C, 0xD0, 0x01, 0x22, 0x52, 0x42,
    0x19, 0x78, 0x28, 0x78, 0x01, 0x35, 0x01, 0x33, 0x81, 0x42, 0x01, 0xD0, 0x58, 0x1E };
static unsigned char sram_gencopy_sig[] = {
    0x80, 0xB5, 0x83, 0xB0, 0x6F, 0x46, 0x38, 0x60, 0x79, 0x60, 0xBA, 0x60, 0xB8, 0x68, 0x41, 0x1E,
    0x08, 0x1C, 0xB8, 0x60, 0x01, 0x21, 0xC8, 0x42, 0x00, 0xD1, 0x09, 0xE0, 0x38, 0x1D, 0x01, 0x68,
    0x3A, 0x68, 0x13, 0x78, 0x0B, 0x70, 0x01, 0x32 };
static unsigned char sram_genverify_sig[] = {
    0x90, 0xB5, 0x83, 0xB0, 0x6F, 0x46, 0x38, 0x60, 0x79, 0x60, 0xBA, 0x60, 0xB8, 0x68, 0x41, 0x1E,
    0x08, 0x1C, 0xB8, 0x60, 0x01, 0x21, 0xC8, 0x42, 0x00, 0xD1, 0x0F, 0xE0, 0x38, 0x1D, 0x01, 0x68,
    0x3C, 0x68, 0x0A, 0x78, 0x23, 0x78, 0x01, 0x34 };
static unsigned char sram_gencopy_ram_sig[] = {
    0x90, 0xB5, 0xA7, 0xB0, 0x6F, 0x46, 0x38, 0x60, 0x79, 0x60, 0xBA, 0x60, 0x00, 0x48, 0x00, 0x49, 0x0A, 0x88, 0x00, 0x4B };
static int         sram_gencopy_ram_wild[] = { 0,0,0,0,0,0,0,0,0,0,0,0, 1,0, 1,0, 0,0, 1,0 };
static unsigned char sram_genverify_ram_sig[] = {
    0x90, 0xB5, 0xB7, 0xB0, 0x6F, 0x46, 0x38, 0x60, 0x79, 0x60, 0xBA, 0x60, 0x00, 0x48, 0x00, 0x49, 0x0A, 0x88, 0x00, 0x4B };
static int         sram_genverify_ram_wild[] = { 0,0,0,0,0,0,0,0,0,0,0,0, 1,0, 1,0, 0,0, 1,0 };

static unsigned char write_eeprom_sig_a[] = { 0x70, 0xB5, 0x00, 0x04, 0x0A, 0x1C, 0x40, 0x0B, 0xE0, 0x21, 0x09, 0x05, 0x41, 0x18, 0x07, 0x31, 0x00, 0x23, 0x10, 0x78};
static unsigned char write_eeprom_sig_b[] = { 0xF0, 0xB5, 0xAC, 0xB0, 0x0D, 0x1C, 0x00, 0x04, 0x01, 0x0C, 0x12, 0x06, 0x17, 0x0E, 0x00, 0x48, 0x00, 0x68, 0x80, 0x88, 0x81, 0x42, 0x05, 0xD3 };
static int         write_eeprom_sig_b_wild[] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0, 1, 0,0,0,0,0,0,0,0,0 };
static unsigned char write_eeprom_sig_c[] = { 0xF0, 0xB5, 0x47, 0x46, 0x80, 0xB4, 0xAC, 0xB0, 0x0E, 0x1C, 0x00, 0x04, 0x05, 0x0C, 0x12, 0x06, 0x12, 0x0E, 0x90, 0x46, 0x00, 0x48, 0x00, 0x68, 0x80, 0x88, 0x85, 0x42, 0x06, 0xD3 };
static int         write_eeprom_sig_c_wild[] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 1, 0,0,0,0,0,0,0,0,0 };
static unsigned char write_eeprom_sig_d[] = { 0x30, 0xB5, 0xA9, 0xB0, 0x0D, 0x1C, 0x00, 0x04, 0x04, 0x0C, 0x00, 0x48, 0x00, 0x68, 0x80, 0x88, 0x84, 0x42, 0x05, 0xD3 };
static int         write_eeprom_sig_d_wild[] = { 0,0,0,0,0,0,0,0,0,0, 1, 0,0,0,0,0,0,0,0,0 };
static unsigned char write_eeprom_sig_e[] = { 0x30, 0xB5, 0xA9, 0xB0, 0x0D, 0x1C, 0x00, 0x4C, 0x04, 0x19, 0x00, 0x48, 0x00, 0x68, 0x80, 0x88, 0x84, 0x42, 0x05, 0xD3 };
static int         write_eeprom_sig_e_wild[] = { 0,0,0,0,0,0, 1,0, 0,0, 1, 0,0,0,0,0,0,0,0,0 };

static unsigned char read_eeprom_sig_a[] = { 0x70, 0xB5, 0x00, 0x04, 0x0A, 0x1C, 0x40, 0x0B, 0xE0, 0x21, 0x09, 0x05, 0x41, 0x18, 0x07, 0x31 };
static unsigned char read_eeprom_sig_b[] = { 0x70, 0xB5, 0xA2, 0xB0, 0x0D, 0x1C, 0x00, 0x04, 0x03, 0x0C, 0x00, 0x48, 0x00, 0x68, 0x80, 0x88, 0x83, 0x42, 0x05, 0xD3 };
static int         read_eeprom_sig_b_wild[] = { 0,0,0,0,0,0,0,0,0,0, 1, 0,0,0,0,0,0,0,0,0 };
static unsigned char read_eeprom_sig_c[] = { 0x70, 0xB5, 0xA2, 0xB0, 0x0D, 0x1C, 0x04, 0x4B, 0xC3, 0x18, 0x28, 0x48, 0x00, 0x68, 0x80, 0x88, 0x83, 0x42, 0x05, 0xD3 };
static int         read_eeprom_sig_c_wild[] = { 0,0,0,0,0,0, 1,0, 0,0, 1, 0,0,0,0,0,0,0,0,0 };
static unsigned char verify_eeprom_signature[] = { 0x30, 0xB5, 0x82, 0xB0, 0x0C, 0x1C, 0x00, 0x04, 0x01, 0x0C, 0x00, 0x25, 0x03, 0x48, 0x00, 0x68 };

static unsigned char read_eeprom_fixed6_sig_a[] = { 0xB0, 0xB5, 0xAA, 0xB0, 0x6F, 0x46, 0x79, 0x60, 0x39, 0x1C, 0x08, 0x80, 0x38, 0x1C, 0x01, 0x88, 0x3F, 0x29, 0x00, 0xD9, 0x00, 0x48 };
static int         read_eeprom_fixed6_sig_a_wild[] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 1,0, 1,0 };
static unsigned char write_eeprom_fixed6_sig_a[] = { 0x80, 0xB5, 0xAA, 0xB0, 0x6F, 0x46, 0x79, 0x60, 0x39, 0x1C, 0x08, 0x80, 0x38, 0x1C, 0x01, 0x88, 0x3F, 0x29, 0x00, 0xD9, 0x00, 0x48 };
static int         write_eeprom_fixed6_sig_a_wild[] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 1,0, 1,0 };
static unsigned char verify_eeprom_fixed6_sig_a[] = { 0xB0, 0xB5, 0x87, 0xB0, 0x6F, 0x46, 0x79, 0x60, 0x39, 0x1C, 0x08, 0x80, 0x38, 0x1C, 0x18, 0x30, 0x00, 0x21, 0x01, 0x80, 0x38, 0x1C };

static unsigned char identify_eeprom_sig_a[] = { 0x00, 0x04, 0x00, 0x0C, 0x00, 0x22, 0x04, 0x28, 0x08, 0xD1, 0x02, 0x49, 0x02, 0x48, 0x08, 0x60 };
static unsigned char identify_eeprom_sig_b[] = { 0x00, 0x04, 0x00, 0x0C, 0x00, 0x22, 0x04, 0x28, 0x00, 0xD1, 0x00, 0x49, 0x02, 0x48, 0x08, 0x60 };
static int         identify_eeprom_sig_b_wild[] = { 0,0,0,0,0,0,0,0, 1,0, 1,0, 0,0,0,0 };
static unsigned char identify_eeprom_sig_c[] = { 0x00, 0x04, 0x00, 0x0C, 0x00, 0x22, 0x04, 0x28, 0x00, 0xE0, 0x00, 0x49, 0x02, 0x48, 0x08, 0x60 };
static int         identify_eeprom_sig_c_wild[] = { 0,0,0,0,0,0,0,0, 1,0, 1,0, 0,0,0,0 };
static int memcmp_wild(const uint8_t *data, const unsigned char *sig, const int *wild, size_t len)
{
    for (size_t i = 0; i < len; ++i)
    {
        if (!wild[i] && data[i] != sig[i])
            return 1;
    }
    return 0;
}

/* La coda di IdentifyEeprom e' sempre questa:
 *
 *   +10  02 49   ldr r1,[pc,#8]   <- indirizzo della VARIABILE del gioco
 *   +12  02 48   ldr r0,[pc,#8]   <- indirizzo della STRUTTURA di configurazione
 *   +14  08 60   str r0,[r1]      <- variabile = &struttura
 *
 * Al payload serve l'indirizzo della VARIABILE, non della struttura: legge
 * quella parola e la dereferenzia ancora una volta per arrivare alla
 * configurazione (get_eeprom_meta fa due dereferenziazioni). Bisogna quindi
 * risolvere il letterale della PRIMA delle due ldr, quella a +10.
 *
 * Con il match allineato a 4 i due letterali finiscono in parole diverse,
 * +20 e +24, quindi partire dall'istruzione sbagliata restituisce
 * l'indirizzo della struttura: il payload lo dereferenzia una volta di
 * troppo, legge il campo 'size' come se fosse un puntatore e ricava
 * loadfactor_log2 da una lettura fuori memoria. */
static uint32_t resolve_eeprom_meta_ptr(uint8_t *rom, long rom_offset)
{
    uint8_t imm = rom[rom_offset + 10];
    uint32_t instr_addr = 0x08000000 + rom_offset + 10;
    uint32_t target = ((instr_addr + 4) & ~3u) + imm * 4;
    uint32_t rom_target_offset = target - 0x08000000;
    return *(uint32_t *) &rom[rom_target_offset];
}

typedef struct {
    const unsigned char *sig;
    const int *wild;
    size_t len;
} sig_variant;

static int match_any_variant(const uint8_t *data, const sig_variant *variants, int count)
{
    for (int v = 0; v < count; ++v)
    {
        const sig_variant *sv = &variants[v];
        int matched = sv->wild
            ? !memcmp_wild(data, sv->sig, sv->wild, sv->len)
            : !memcmp(data, sv->sig, sv->len);
        if (matched)
            return v;
    }
    return -1;
}

static int rom_contains(uint8_t *rom, size_t romsize, const char *needle)
{
    size_t needle_len = strlen(needle);
    for (size_t i = 0; i + needle_len <= romsize; ++i)
    {
        if (!memcmp(rom + i, needle, needle_len))
            return 1;
    }
    return 0;
}

static const sig_variant v_write_sram_generic[]   = { { write_sram_generic_sig,  write_sram_generic_wild,  sizeof write_sram_generic_sig } };
static const sig_variant v_verify_sram_generic[]  = { { verify_sram_generic_sig, verify_sram_generic_wild, sizeof verify_sram_generic_sig } };
static const sig_variant v_write_sram2[]          = { { write_sram2_signature,   NULL, sizeof write_sram2_signature } };
static const sig_variant v_write_sram_fast[]      = { { write_sram_ram_signature,NULL, sizeof write_sram_ram_signature } };
static const sig_variant v_read_sram[]            = { { read_sram_signature,     NULL, sizeof read_sram_signature } };
static const sig_variant v_verify_sram[]          = { { verify_sram_signature,   NULL, sizeof verify_sram_signature } };
static const sig_variant v_verify_sram_push4[]    = { { verify_sram_push4_sig,   NULL, sizeof verify_sram_push4_sig } };
static const sig_variant v_ramexec_copy[]         = { { sram_ramexec_copy_sig,   NULL, sizeof sram_ramexec_copy_sig } };
static const sig_variant v_ramexec_verify[]       = { { sram_ramexec_verify_sig, NULL, sizeof sram_ramexec_verify_sig } };
static const sig_variant v_write_push4reg[]       = { { write_sram_push4reg_sig, NULL, sizeof write_sram_push4reg_sig } };
static const sig_variant v_write_standalone[]     = { { write_sram_standalone_sig,  NULL, sizeof write_sram_standalone_sig } };
static const sig_variant v_verify_standalone[]    = { { verify_sram_standalone_sig, NULL, sizeof verify_sram_standalone_sig } };
static const sig_variant v_gencopy[]              = { { sram_gencopy_sig,        NULL, sizeof sram_gencopy_sig } };
static const sig_variant v_gencopy_ram[]          = { { sram_gencopy_ram_sig,    sram_gencopy_ram_wild,   sizeof sram_gencopy_ram_sig } };
static const sig_variant v_genverify[]            = { { sram_genverify_sig,      NULL, sizeof sram_genverify_sig } };
static const sig_variant v_genverify_ram[]        = { { sram_genverify_ram_sig,  sram_genverify_ram_wild, sizeof sram_genverify_ram_sig } };
static const sig_variant v_verify_eeprom[]        = { { verify_eeprom_signature, NULL, sizeof verify_eeprom_signature } };
static const sig_variant identify_eeprom_variants[] = {
    { identify_eeprom_sig_a, NULL, sizeof identify_eeprom_sig_a },
    { identify_eeprom_sig_b, identify_eeprom_sig_b_wild, sizeof identify_eeprom_sig_b },
    { identify_eeprom_sig_c, identify_eeprom_sig_c_wild, sizeof identify_eeprom_sig_c },
};
static const sig_variant read_eeprom_variants[] = {
    { read_eeprom_sig_a, NULL, sizeof read_eeprom_sig_a },
    { read_eeprom_sig_b, read_eeprom_sig_b_wild, sizeof read_eeprom_sig_b },
    { read_eeprom_sig_c, read_eeprom_sig_c_wild, sizeof read_eeprom_sig_c },
};
static const sig_variant write_eeprom_variants[] = {
    { write_eeprom_sig_a, NULL, sizeof write_eeprom_sig_a },
    { write_eeprom_sig_b, write_eeprom_sig_b_wild, sizeof write_eeprom_sig_b },
    { write_eeprom_sig_c, write_eeprom_sig_c_wild, sizeof write_eeprom_sig_c },
    { write_eeprom_sig_d, write_eeprom_sig_d_wild, sizeof write_eeprom_sig_d },
    { write_eeprom_sig_e, write_eeprom_sig_e_wild, sizeof write_eeprom_sig_e },
};
static const sig_variant verify_eeprom_fixed6_variants[] = {
    { verify_eeprom_fixed6_sig_a, NULL, sizeof verify_eeprom_fixed6_sig_a },
};
static const sig_variant write_eeprom_fixed6_variants[] = {
    { write_eeprom_fixed6_sig_a, write_eeprom_fixed6_sig_a_wild, sizeof write_eeprom_fixed6_sig_a },
};
static const sig_variant read_eeprom_fixed6_variants[] = {
    { read_eeprom_fixed6_sig_a, read_eeprom_fixed6_sig_a_wild, sizeof read_eeprom_fixed6_sig_a },
};

enum { G_SRAM, G_SRAM_HDR, G_EEPROM };

typedef struct {
    const char        *label;        
    const char        *label_gbata;  
    const sig_variant *vars;
    int                nvars;
    int                slot;         
    int                gate;
    int                arm;          
} hook_desc;

#define N1(a) ((int)(sizeof(a)/sizeof((a)[0])))

static const hook_desc hooks[] = {
 { "WriteSram identified at offset %lx, patching\n", NULL, v_write_sram_generic, N1(v_write_sram_generic), WRITE_SRAM_PATCHED, G_SRAM, 0 },
 { "VerifySram (generic variant) identified at offset %lx, patching\n", NULL, v_verify_sram_generic, N1(v_verify_sram_generic), VERIFY_SRAM_PATCHED, G_SRAM, 0 },
 { "WriteSram 2 identified at offset %lx, patching\n", NULL, v_write_sram2, N1(v_write_sram2), WRITE_SRAM_PATCHED, G_SRAM, 0 },
 { "WriteSramFast identified at offset %lx, patching\n", NULL, v_write_sram_fast, N1(v_write_sram_fast), WRITE_SRAM_PATCHED, G_SRAM, 1 },
 { "ReadSram identified at offset %lx, patching\n", NULL, v_read_sram, N1(v_read_sram), READ_SRAM_PATCHED, G_SRAM, 0 },
 { "VerifySram identified at offset %lx, patching\n", NULL, v_verify_sram, N1(v_verify_sram), VERIFY_SRAM_PATCHED, G_SRAM, 0 },
 { "ProgramEepromDword identified at offset %lx, patching\n", "SRAM-patched ProgramEepromDword identified at offset %lx, patching\n", write_eeprom_variants, N1(write_eeprom_variants), WRITE_EEPROM_PATCHED, G_EEPROM, 0 },
 { "ReadEepromDword identified at offset %lx, patching\n", "SRAM-patched ReadEepromDword identified at offset %lx, patching\n", read_eeprom_variants, N1(read_eeprom_variants), READ_EEPROM_PATCHED, G_EEPROM, 0 },
 { "VerifySram (push r4 variant) identified at offset %lx, patching\n", NULL, v_verify_sram_push4, N1(v_verify_sram_push4), VERIFY_SRAM_PATCHED, G_SRAM, 0 },
 { "WriteSram (RAM-executed driver) identified at offset %lx, patching\n", NULL, v_ramexec_copy, N1(v_ramexec_copy), WRITE_SRAM_PATCHED, G_SRAM, 0 },
 { "VerifySram (RAM-executed driver) identified at offset %lx, patching\n", NULL, v_ramexec_verify, N1(v_ramexec_verify), VERIFY_SRAM_PATCHED, G_SRAM, 0 },
 { "WriteSram (extended push variant) identified at offset %lx, patching\n", NULL, v_write_push4reg, N1(v_write_push4reg), WRITE_SRAM_PATCHED, G_SRAM, 0 },
 { "WriteSram (standalone variant) identified at offset %lx, patching\n", NULL, v_write_standalone, N1(v_write_standalone), WRITE_SRAM_PATCHED, G_SRAM_HDR, 0 },
 { "VerifySram (standalone variant) identified at offset %lx, patching\n", NULL, v_verify_standalone, N1(v_verify_standalone), VERIFY_SRAM_PATCHED, G_SRAM_HDR, 0 },
 { "WriteSram (generic copy driver) identified at offset %lx, patching\n", NULL, v_gencopy, N1(v_gencopy), WRITE_SRAM_PATCHED, G_SRAM_HDR, 0 },
 { "WriteSram (generic copy driver, RAM-executed) identified at offset %lx, patching\n", NULL, v_gencopy_ram, N1(v_gencopy_ram), WRITE_SRAM_PATCHED, G_SRAM, 0 },
 { "VerifySram (generic copy driver) identified at offset %lx, patching\n", NULL, v_genverify, N1(v_genverify), VERIFY_SRAM_PATCHED, G_SRAM_HDR, 0 },
 { "VerifySram (generic copy driver, RAM-executed) identified at offset %lx, patching\n", NULL, v_genverify_ram, N1(v_genverify_ram), VERIFY_SRAM_PATCHED, G_SRAM, 0 },
 { "ReadEepromDword (fixed 6-bit addressing) identified at offset %lx, patching\n", NULL, read_eeprom_fixed6_variants, N1(read_eeprom_fixed6_variants), READ_EEPROM_FIXED6_PATCHED, G_EEPROM, 0 },
 { "ProgramEepromDword (fixed 6-bit addressing) identified at offset %lx, patching\n", NULL, write_eeprom_fixed6_variants, N1(write_eeprom_fixed6_variants), WRITE_EEPROM_FIXED6_PATCHED, G_EEPROM, 0 },
 { "VerifyEepromDword (fixed 6-bit addressing) identified at offset %lx, patching\n", NULL, verify_eeprom_fixed6_variants, N1(verify_eeprom_fixed6_variants), VERIFY_EEPROM_FIXED6_PATCHED, G_EEPROM, 0 },
 { "VerifyEepromDword identified at offset %lx, patching\n", "SRAM-patched VerifyEepromDword identified at offset %lx, patching\n", v_verify_eeprom, N1(v_verify_eeprom), VERIFY_EEPROM_PATCHED, G_EEPROM, 0 },
};
#define NHOOKS N1(hooks)

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        puts("Wrong number of args");
        scanf("%*s");
        return 1;
    }
	
    memset(rom, 0xFF, sizeof rom);
    
    size_t romfilename_len = strlen(argv[1]);
    int ext_ok = 0;
    if (romfilename_len >= 4)
    {
        const char *e = argv[1] + romfilename_len - 4;
        ext_ok = (e[0] == '.')
              && (e[1] == 'g' || e[1] == 'G')
              && (e[2] == 'b' || e[2] == 'B')
              && (e[3] == 'a' || e[3] == 'A');
    }
    if (!ext_ok)
    {
        puts("File does not have .gba extension.");
        scanf("%*s");
        return 1;
    }

    if (!(romfile = fopen(argv[1], "rb")))
    {
        puts("Could not open input file");
        puts(strerror(errno));
        scanf("%*s");
        return 1;
    }

    fseek(romfile, 0, SEEK_END);
    romsize = ftell(romfile);
    long filesize = (long) romsize;        

    if (romsize > sizeof rom)
    {
        puts("ROM too large - not a GBA ROM?");
        scanf("%*s");
        return 1;
    }

    if (romsize & 0x3ffff)
    {
        puts("ROM has been trimmed and is misaligned. Padding to 256KB alignment");
        romsize &= ~0x3ffff;
        romsize += 0x40000;
    }

    fseek(romfile, 0, SEEK_SET);
    if (fread(rom, 1, filesize, romfile) != (size_t) filesize)
    {
        puts("Could not read the whole ROM file.");
        puts(strerror(errno));
        scanf("%*s");
        return 1;
    }
    
    int payload_base;
    for (payload_base = romsize - payload_bin_len; payload_base >= 0; payload_base -= 4)
    {
        int is_all_zeroes = 1;
        int is_all_ones = 1;
        for (unsigned i = 0; i < payload_bin_len; ++i)
        {
            if (rom[payload_base+i] != 0)
            {
                is_all_zeroes = 0;
            }
            if (rom[payload_base+i] != 0xFF)
            {
                is_all_ones = 0;
            }
            /* Posizione gia' esclusa: guardare il resto non cambia l'esito.
             * Senza questa uscita ogni posizione costa tutti i byte del
             * payload, e su una ROM piena fino in fondo - Fire Emblem EUR,
             * 32 MB, primo spazio libero 17 MB prima della fine - la
             * ricerca passava da un istante a una ventina di secondi. */
            if (!is_all_zeroes && !is_all_ones)
                break;
        }
        if (is_all_zeroes || is_all_ones)
        {
           break;
        }
    }
    if (payload_base < 0)
    {
        puts("ROM too small to install payload.");
        if (romsize + payload_bin_len > 0x2000000)
        {
            puts("ROM already max size. Cannot expand. Cannot install payload");
            scanf("%*s");
            return 1;
        }
        else
        {
            puts("Expanding ROM");
            romsize += payload_bin_len;
            payload_base = romsize - payload_bin_len;
        }
    }
	
    printf("Installing payload at offset %x\n", payload_base);
    memcpy(rom + payload_base, payload_bin, payload_bin_len);

    int has_eeprom_id = rom_contains(rom, romsize, "EEPROM_V");
    int has_sram_id = rom_contains(rom, romsize, "SRAM_V") || rom_contains(rom, romsize, "SRAM_F_V");
    int has_flash_id = rom_contains(rom, romsize, "FLASH_V")
                     || rom_contains(rom, romsize, "FLASH512_V")
                     || rom_contains(rom, romsize, "FLASH1M_V");
    int try_eeprom = has_eeprom_id || !has_sram_id;
    int try_sram = !((has_eeprom_id || has_flash_id) && has_sram_id);
    if (has_eeprom_id && has_sram_id)
        puts("Header declares both EEPROM and SRAM - assuming EEPROM is the real save type and skipping SRAM signature scan");
    else if (has_flash_id && has_sram_id)
        puts("Header declares both FLASH and SRAM - assuming FLASH is the real save type and skipping SRAM signature scan");

    int gbata_converted = 0;
    for (uint8_t *scan = rom; scan < rom + romsize - 64 && !gbata_converted; scan += 2)
    {
        if (!memcmp(scan, write_eeprom_sig_a, sizeof write_eeprom_sig_a))
            gbata_converted = 1;
        else if (!memcmp(scan, read_eeprom_sig_a, sizeof read_eeprom_sig_a))
            gbata_converted = 1;
    }

    int found_write_location = 0;
    for (uint8_t *write_location = rom; write_location < rom + romsize - 64; write_location += 2)
    {
        for (int h = 0; h < NHOOKS; ++h)
        {
            const hook_desc *hd = &hooks[h];

            if (hd->gate == G_SRAM     && !try_sram)                 continue;
            if (hd->gate == G_SRAM_HDR && !(try_sram && has_sram_id)) continue;
            if (hd->gate == G_EEPROM   && !try_eeprom)               continue;

            if (match_any_variant(write_location, hd->vars, hd->nvars) < 0) continue;

            found_write_location = 1;
            printf(hd->label_gbata && gbata_converted ? hd->label_gbata : hd->label, write_location - rom);

            uint32_t *target_ptr = (uint32_t*)write_location;
            uint32_t *payload_ptr = (uint32_t*)payload_bin;

            if (hd->arm)
            {
                memcpy(write_location, arm_branch_thunk, sizeof arm_branch_thunk);
                target_ptr[2] = 0x08000000 + payload_base + payload_ptr[hd->slot];
            }
            else
            {
                memcpy(write_location, thumb_branch_thunk, sizeof thumb_branch_thunk);
                target_ptr[1] = 0x08000000 + payload_base + payload_ptr[hd->slot];
            }
        }

        if (try_eeprom && match_any_variant(write_location, identify_eeprom_variants, N1(identify_eeprom_variants)) >= 0)
        {
            found_write_location = 1;
            uint32_t meta_ptr = resolve_eeprom_meta_ptr(rom, write_location - rom);
            uint32_t *rom_payload_ptr = (uint32_t*)&rom[payload_base];
            rom_payload_ptr[EEPROM_META] = meta_ptr;
            printf(gbata_converted
                ? "SRAM-patched IdentifyEeprom identified at offset %lx, RAM address of eeprom info is %x\n"
                : "IdentifyEeprom identified at offset %lx, RAM address of eeprom info is %x\n", write_location - rom, meta_ptr);
        }
    }
    if (!found_write_location)
    {
        if (has_flash_id && !has_eeprom_id)
            puts("Header declares Flash as the real save type, and this ROM doesn't use EEPROM.\n"
                 "Nothing to patch: a Flash cart already supports this game natively, without\n"
                 "any modification. If it still doesn't save on real hardware, that's a separate\n"
                 "problem, not something this tool can fix.");
        else
            puts("Could not find a write function to hook. Are you sure the game has save functionality?");
        scanf("%*s");
        return 1;
    }

    const char *suffix = "_flash512.gba";
    size_t base_len = romfilename_len - 4;              
    char new_filename[FILENAME_MAX];

    if (base_len + strlen(suffix) + 1 > sizeof new_filename)
    {
        puts("Output path would be too long. Move the ROM to a shorter path.");
        scanf("%*s");
        return 1;
    }
    memcpy(new_filename, argv[1], base_len);
    strcpy(new_filename + base_len, suffix);
    
    if (!(outfile = fopen(new_filename, "wb")))
    {
        puts("Could not open output file");
        puts(strerror(errno));
        scanf("%*s");
        return 1;
    }
    
    fwrite(rom, 1, romsize, outfile);
    fflush(outfile);

    printf("Patched successfully. Changes written to %s\n", new_filename);
    scanf("%*s");
    return 0;
}
