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
    EEPROM_META
};

// ldr r3, [pc, # 0]; bx r3
static unsigned char thumb_branch_thunk[] = { 0x00, 0x4b, 0x18, 0x47 };
static unsigned char arm_branch_thunk[] = { 0x00, 0x30, 0x9f, 0xe5, 0x13, 0xff, 0x2f, 0xe1 };

static unsigned char write_sram_signature[] = { 0x30, 0xB5, 0x05, 0x1C, 0x0C, 0x1C, 0x13, 0x1C, 0x0B, 0x4A, 0x10, 0x88, 0x0B, 0x49, 0x08, 0x40};
/* I byte agli indici 8 e 12 sono l'immediato di due "ldr rX, [pc, #imm]"
 * che caricano il registro WAITCNT e la sua maschera da una literal pool
 * adiacente. Quella distanza cambia leggermente a seconda della posizione
 * di ciascuna copia della funzione nel codice compilato, quindi il valore
 * esatto di questi due byte NON e' affidabile per identificare la
 * funzione: li trattiamo come wildcard (1 = ignora). Trovato analizzando
 * manualmente il gioco: la stessa funzione generica di copia compare 3
 * volte nella ROM con offset di literal pool leggermente diversi, e il
 * confronto byte-per-byte originale ne intercettava solo 2 su 3. */
static int write_sram_signature_wild[] = { 0,0,0,0,0,0,0,0, 1,0,0,0, 1,0,0,0 };

/* Byte 34-37 (relativi all'inizio della funzione, quindi oltre le 16
 * della firma sopra) distinguono in modo affidabile la variante
 * "scrittura" (copia: ldrb+strb) dalla variante "verifica" (confronto:
 * ldrb+ldrb+cmp), che condividono lo stesso prologo di impostazione
 * WAITCNT ma hanno un corpo del ciclo diverso. A differenza dei byte 8
 * e 12, questi non dipendono dalla posizione della literal pool: sono
 * istruzioni che usano solo registri, quindi la loro codifica resta
 * identica ovunque si trovi la funzione nella ROM. */
static unsigned char write_body_pattern[] = { 0x28, 0x78, 0x20, 0x70 };
static unsigned char verify_body_pattern[] = { 0x21, 0x78, 0x28, 0x78 };
#define SRAM_BODY_PATTERN_OFFSET 34

static int memcmp_wild(const uint8_t *data, const unsigned char *sig, const int *wild, size_t len)
{
    for (size_t i = 0; i < len; ++i)
    {
        if (!wild[i] && data[i] != sig[i])
            return 1; /* diverso, come memcmp che ritorna non-zero */
    }
    return 0; /* uguale (rispettando le wildcard) */
}

/* Decodifica correttamente la seconda "ldr rX, [pc, #imm8]" (offset
 * relativo 12 dall'inizio del match di identify_eeprom) per risalire al
 * vero valore puntato, invece di assumere un offset fisso che vale solo
 * se l'immediato coincide con quello dell'esempio originale. */
static uint32_t resolve_eeprom_meta_ptr(uint8_t *rom, long rom_offset)
{
    uint8_t imm2 = rom[rom_offset + 12];
    uint32_t instr2_addr = 0x08000000 + rom_offset + 12;
    uint32_t target2 = ((instr2_addr + 4) & ~3u) + imm2 * 4;
    uint32_t rom_target_offset = target2 - 0x08000000;
    return *(uint32_t *) &rom[rom_target_offset];
}

static unsigned char write_sram2_signature[] = { 0x80, 0xb5, 0x83, 0xb0, 0x6f, 0x46, 0x38, 0x60, 0x79, 0x60, 0xba, 0x60, 0x09, 0x48, 0x09, 0x49 };
static unsigned char write_sram_ram_signature[] = { 0x04, 0xC0, 0x90, 0xE4, 0x01, 0xC0, 0xC1, 0xE4, 0x2C, 0xC4, 0xA0, 0xE1, 0x01, 0xC0, 0xC1, 0xE4 };

static unsigned char read_sram_signature[] = { 0x70, 0xB5, 0xA0, 0xB0, 0x04, 0x1C, 0x0D, 0x1C, 0x16, 0x1C, 0x08, 0x4A, 0x10, 0x88, 0x08, 0x49};

static unsigned char verify_sram_signature[] = { 0x70, 0xB5, 0xB0, 0xB0, 0x04, 0x1C, 0x0D, 0x1C, 0x16, 0x1C, 0x08, 0x4A, 0x10, 0x88, 0x08, 0x49 };

/* Ogni "operazione" (scrittura/lettura/identificazione EEPROM) puo' avere
 * piu' varianti byte-per-byte a seconda del compilatore/versione usati dal
 * gioco. Le raggruppiamo qui invece di avere blocchi duplicati sparsi nel
 * loop di scansione. wild puo' essere NULL se la variante e' un confronto
 * esatto, senza byte in wildcard. */
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
            return 1;
    }
    return 0;
}

/* --- ProgramEepromDword (scrittura EEPROM) --- */
static unsigned char write_eeprom_sig_a[] = { 0x70, 0xB5, 0x00, 0x04, 0x0A, 0x1C, 0x40, 0x0B, 0xE0, 0x21, 0x09, 0x05, 0x41, 0x18, 0x07, 0x31, 0x00, 0x23, 0x10, 0x78};
/* Variante trovata analizzando The Legend of Zelda: The Minish Cap (EEPROM
 * nativo): il compilatore usato per questo gioco genera un prologo diverso
 * (due istruzioni extra di setup subito dopo il push), quindi la firma
 * sopra non trova mai un riscontro qui. Il byte in wildcard e' l'immediato
 * di una "ldr rX, [pc, #imm]" che dipende dalla distanza dalla literal
 * pool, quindi cambia in base alla posizione della funzione nel codice
 * compilato. */
static unsigned char write_eeprom_sig_b[] = { 0xF0, 0xB5, 0xAC, 0xB0, 0x0D, 0x1C, 0x00, 0x04, 0x01, 0x0C, 0x12, 0x06, 0x17, 0x0E, 0x00, 0x48, 0x00, 0x68, 0x80, 0x88, 0x81, 0x42, 0x05, 0xD3 };
static int         write_eeprom_sig_b_wild[] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0, 1, 0,0,0,0,0,0,0,0,0 };
/* Terza variante, trovata analizzando Yggdra Union (EEPROM nativo): due
 * istruzioni extra rispetto alla variante B ("mov r7,r8; push {r7}" subito
 * dopo il push iniziale) e un'allocazione di registri diversa. Stesso
 * genere di compilatore/versione diversi da entrambe le varianti sopra. */
static unsigned char write_eeprom_sig_c[] = { 0xF0, 0xB5, 0x47, 0x46, 0x80, 0xB4, 0xAC, 0xB0, 0x0E, 0x1C, 0x00, 0x04, 0x05, 0x0C, 0x12, 0x06, 0x12, 0x0E, 0x90, 0x46, 0x00, 0x48, 0x00, 0x68, 0x80, 0x88, 0x85, 0x42, 0x06, 0xD3 };
static int         write_eeprom_sig_c_wild[] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 1, 0,0,0,0,0,0,0,0,0 };
/* Quarta variante, trovata analizzando Super Mario Advance 2 - Super Mario
 * World: prologo piu' snello (push {r4,r5,lr}, solo 3 registri) rispetto
 * alle altre tre varianti, con un'allocazione di stack diversa (164 byte). */
static unsigned char write_eeprom_sig_d[] = { 0x30, 0xB5, 0xA9, 0xB0, 0x0D, 0x1C, 0x00, 0x04, 0x04, 0x0C, 0x00, 0x48, 0x00, 0x68, 0x80, 0x88, 0x84, 0x42, 0x05, 0xD3 };
static int         write_eeprom_sig_d_wild[] = { 0,0,0,0,0,0,0,0,0,0, 1, 0,0,0,0,0,0,0,0,0 };
static const sig_variant write_eeprom_variants[] = {
    { write_eeprom_sig_a, NULL, sizeof write_eeprom_sig_a },
    { write_eeprom_sig_b, write_eeprom_sig_b_wild, sizeof write_eeprom_sig_b },
    { write_eeprom_sig_c, write_eeprom_sig_c_wild, sizeof write_eeprom_sig_c },
    { write_eeprom_sig_d, write_eeprom_sig_d_wild, sizeof write_eeprom_sig_d },
};

/* --- ReadEepromDword (lettura EEPROM) --- */
static unsigned char read_eeprom_sig_a[] = { 0x70, 0xB5, 0x00, 0x04, 0x0A, 0x1C, 0x40, 0x0B, 0xE0, 0x21, 0x09, 0x05, 0x41, 0x18, 0x07, 0x31 };
/* Variante Minish Cap, stesso motivo della scrittura sopra. */
static unsigned char read_eeprom_sig_b[] = { 0x70, 0xB5, 0xA2, 0xB0, 0x0D, 0x1C, 0x00, 0x04, 0x03, 0x0C, 0x00, 0x48, 0x00, 0x68, 0x80, 0x88, 0x83, 0x42, 0x05, 0xD3 };
static int         read_eeprom_sig_b_wild[] = { 0,0,0,0,0,0,0,0,0,0, 1, 0,0,0,0,0,0,0,0,0 };
static const sig_variant read_eeprom_variants[] = {
    { read_eeprom_sig_a, NULL, sizeof read_eeprom_sig_a },
    { read_eeprom_sig_b, read_eeprom_sig_b_wild, sizeof read_eeprom_sig_b },
};

static unsigned char verify_eeprom_signature[] = { 0x30, 0xB5, 0x82, 0xB0, 0x0C, 0x1C, 0x00, 0x04, 0x01, 0x0C, 0x00, 0x25, 0x03, 0x48, 0x00, 0x68 };

/* --- IdentifyEeprom --- */
static unsigned char identify_eeprom_sig_a[] = { 0x00, 0x04, 0x00, 0x0C, 0x00, 0x22, 0x04, 0x28, 0x08, 0xD1, 0x02, 0x49, 0x02, 0x48, 0x08, 0x60 };
/* Variante Minish Cap: i byte agli indici 8 e 10 sono l'immediato di un
 * salto condizionale e di una "ldr r1, [pc, #imm]", entrambi dipendenti
 * dalla posizione nel codice compilato. Il byte all'indice 12 (secondo
 * "ldr", quello che punta al vero valore che ci interessa) resta invece
 * fisso in entrambe le varianti: e' per questo che resolve_eeprom_meta_ptr
 * funziona identicamente per entrambe, senza bisogno di un offset fisso
 * diverso per ciascuna. */
static unsigned char identify_eeprom_sig_b[] = { 0x00, 0x04, 0x00, 0x0C, 0x00, 0x22, 0x04, 0x28, 0x00, 0xD1, 0x00, 0x49, 0x02, 0x48, 0x08, 0x60 };
static int         identify_eeprom_sig_b_wild[] = { 0,0,0,0,0,0,0,0, 1,0, 1,0, 0,0,0,0 };
static const sig_variant identify_eeprom_variants[] = {
    { identify_eeprom_sig_a, NULL, sizeof identify_eeprom_sig_a },
    { identify_eeprom_sig_b, identify_eeprom_sig_b_wild, sizeof identify_eeprom_sig_b },
};


static uint8_t *memfind(uint8_t *haystack, size_t haystack_size, uint8_t *needle, size_t needle_size, int stride)
{
    for (size_t i = 0; i < haystack_size - needle_size; i += stride)
    {
        if (!memcmp(haystack + i, needle, needle_size))
        {
            return haystack + i;
        }
    }
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        puts("Wrong number of args");
		scanf("%*s");
        return 1;
    }
	
	memset(rom, 0x00ff, sizeof rom);
    
    size_t romfilename_len = strlen(argv[1]);
    if (romfilename_len < 4 || strcmp(argv[1] + romfilename_len - 4, ".gba"))
    {
        puts("File does not have .gba extension.");
		scanf("%*s");
        return 1;
    }

    // Open ROM file
    if (!(romfile = fopen(argv[1], "rb")))
    {
        puts("Could not open input file");
        puts(strerror(errno));
		scanf("%*s");
        return 1;
    }

    // Load ROM into memory
    fseek(romfile, 0, SEEK_END);
    romsize = ftell(romfile);

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
    fread(rom, 1, romsize, romfile);
    
    // Find a location to insert the payload
	int payload_base;
    for (payload_base = romsize - payload_bin_len; payload_base >= 0; payload_base -= 4)
    {
        int is_all_zeroes = 1;
        int is_all_ones = 1;
        for (int i = 0; i < payload_bin_len; ++i)
        {
            if (rom[payload_base+i] != 0)
            {
                is_all_zeroes = 0;
            }
            if (rom[payload_base+i] != 0xFF)
            {
                is_all_ones = 0;
            }
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
			puts("ROM alraedy max size. Cannot expand. Cannot install payload");
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
	
	// Patch any write functions 
    int found_write_location = 0;
    for (uint8_t *write_location = rom; write_location < rom + romsize - 64; write_location += 2)
    {
        int rom_offset = write_location - rom;
		if (!memcmp_wild(write_location, write_sram_signature, write_sram_signature_wild, sizeof write_sram_signature))
		{
            int is_verify = !memcmp(write_location + SRAM_BODY_PATTERN_OFFSET, verify_body_pattern, sizeof verify_body_pattern);
            int is_write = !memcmp(write_location + SRAM_BODY_PATTERN_OFFSET, write_body_pattern, sizeof write_body_pattern);

            if (is_verify)
            {
                found_write_location = 1;
                printf("VerifySram (generic variant) identified at offset %lx, patching\n", write_location - rom);
                memcpy(write_location, thumb_branch_thunk, sizeof thumb_branch_thunk);
                1[(uint32_t*) write_location] = 0x08000000 + payload_base + VERIFY_SRAM_PATCHED[(uint32_t*) payload_bin];
            }
            else if (is_write)
            {
                found_write_location = 1;
                printf("WriteSram identified at offset %lx, patching\n", write_location - rom);
                memcpy(write_location, thumb_branch_thunk, sizeof thumb_branch_thunk);
                1[(uint32_t*) write_location] = 0x08000000 + payload_base + WRITE_SRAM_PATCHED[(uint32_t*) payload_bin];
            }
            /* se non corrisponde a nessuna delle due varianti note, non
             * tocchiamo nulla: meglio lasciare intonsa una funzione che
             * non riconosciamo con certezza piuttosto che patcharla
             * a caso */

		}
        if (!memcmp(write_location, write_sram2_signature, sizeof write_sram2_signature))
		{
            found_write_location = 1;
            printf("WriteSram 2 identified at offset %lx, patching\n", write_location - rom);
            memcpy(write_location, thumb_branch_thunk, sizeof thumb_branch_thunk);
            1[(uint32_t*) write_location] = 0x08000000 + payload_base + WRITE_SRAM_PATCHED[(uint32_t*) payload_bin];

		}
		if (!memcmp(write_location, write_sram_ram_signature, sizeof write_sram_ram_signature))
		{
            found_write_location = 1;
            printf("WriteSramFast identified at offset %lx, patching\n", write_location - rom);
            memcpy(write_location, arm_branch_thunk, sizeof arm_branch_thunk);
            2[(uint32_t*) write_location] = 0x08000000 + payload_base + WRITE_SRAM_PATCHED[(uint32_t*) payload_bin];
		}
        if (!memcmp(write_location, read_sram_signature, sizeof read_sram_signature))
		{
            found_write_location = 1;
            printf("ReadSram identified at offset %lx, patching\n", write_location - rom);
            memcpy(write_location, thumb_branch_thunk, sizeof thumb_branch_thunk);
            1[(uint32_t*) write_location] = 0x08000000 + payload_base + READ_SRAM_PATCHED[(uint32_t*) payload_bin];

		}
        if (!memcmp(write_location, verify_sram_signature, sizeof verify_sram_signature))
		{
            found_write_location = 1;
            printf("VerifySram identified at offset %lx, patching\n", write_location - rom);
            memcpy(write_location, thumb_branch_thunk, sizeof thumb_branch_thunk);
            1[(uint32_t*) write_location] = 0x08000000 + payload_base + VERIFY_SRAM_PATCHED[(uint32_t*) payload_bin];
		}
		if (match_any_variant(write_location, write_eeprom_variants, 4))
		{
            found_write_location = 1;
            printf("ProgramEepromDword identified at offset %lx, patching\n", write_location - rom);
            memcpy(write_location, thumb_branch_thunk, sizeof thumb_branch_thunk);
            1[(uint32_t*) write_location] = 0x08000000 + payload_base + WRITE_EEPROM_PATCHED[(uint32_t*) payload_bin];
		}
        if (match_any_variant(write_location, read_eeprom_variants, 2))
		{
            found_write_location = 1;
            printf("ReadEepromDword identified at offset %lx, patching\n", write_location - rom);
            memcpy(write_location, thumb_branch_thunk, sizeof thumb_branch_thunk);
            1[(uint32_t*) write_location] = 0x08000000 + payload_base + READ_EEPROM_PATCHED[(uint32_t*) payload_bin];
		}
        if (!memcmp(write_location, verify_eeprom_signature, sizeof verify_eeprom_signature))
		{
            found_write_location = 1;
            printf("VerifyEepromDword identified at offset %lx, patching\n", write_location - rom);
            memcpy(write_location, thumb_branch_thunk, sizeof thumb_branch_thunk);
            1[(uint32_t*) write_location] = 0x08000000 + payload_base + VERIFY_EEPROM_PATCHED[(uint32_t*) payload_bin];
		}
        if (match_any_variant(write_location, identify_eeprom_variants, 2))
        {
            found_write_location = 1;
            uint32_t meta_ptr = resolve_eeprom_meta_ptr(rom, write_location - rom);
            EEPROM_META[(uint32_t*) &rom[payload_base]] = meta_ptr;
            printf("IdentifyEeprom identified at offset %lx, RAM address of eeprom info is %x\n", write_location - rom, meta_ptr);
        }
	}
    if (!found_write_location)
    {
        puts("Could not find a write function to hook. Are you sure the game has save functionality and has been SRAM patched with GBATA?");
        scanf("%*s");
        return 1;
    }


	// Flush all changes to new file
    char *suffix = "_flash512.gba";
    size_t suffix_length = strlen(suffix);
    char new_filename[FILENAME_MAX];
    strncpy(new_filename, argv[1], FILENAME_MAX);
    strncpy(new_filename + romfilename_len - 4, suffix, strlen(suffix));
    
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
