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
            return v; /* indice della variante trovata */
    }
    return -1; /* nessuna corrispondenza */
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
/* Quinta variante, trovata in "2 in 1 - Spyro: Season of Ice & Season of
 * Flame": stessa forma della quarta ma con un calcolo di offset in piu'
 * (ldr r4,[pc,#imm]; adds r4,r0,r4) prima del solito controllo — probabile
 * gestione di piu' blocchi di salvataggio in un'unica ROM 2-in-1. */
static unsigned char write_eeprom_sig_e[] = { 0x30, 0xB5, 0xA9, 0xB0, 0x0D, 0x1C, 0x00, 0x4C, 0x04, 0x19, 0x00, 0x48, 0x00, 0x68, 0x80, 0x88, 0x84, 0x42, 0x05, 0xD3 };
static int         write_eeprom_sig_e_wild[] = { 0,0,0,0,0,0, 1,0, 0,0, 1, 0,0,0,0,0,0,0,0,0 };
static const sig_variant write_eeprom_variants[] = {
    { write_eeprom_sig_a, NULL, sizeof write_eeprom_sig_a },
    { write_eeprom_sig_b, write_eeprom_sig_b_wild, sizeof write_eeprom_sig_b },
    { write_eeprom_sig_c, write_eeprom_sig_c_wild, sizeof write_eeprom_sig_c },
    { write_eeprom_sig_d, write_eeprom_sig_d_wild, sizeof write_eeprom_sig_d },
    { write_eeprom_sig_e, write_eeprom_sig_e_wild, sizeof write_eeprom_sig_e },
};

/* --- ReadEepromDword (lettura EEPROM) --- */
static unsigned char read_eeprom_sig_a[] = { 0x70, 0xB5, 0x00, 0x04, 0x0A, 0x1C, 0x40, 0x0B, 0xE0, 0x21, 0x09, 0x05, 0x41, 0x18, 0x07, 0x31 };
/* Variante Minish Cap, stesso motivo della scrittura sopra. */
static unsigned char read_eeprom_sig_b[] = { 0x70, 0xB5, 0xA2, 0xB0, 0x0D, 0x1C, 0x00, 0x04, 0x03, 0x0C, 0x00, 0x48, 0x00, 0x68, 0x80, 0x88, 0x83, 0x42, 0x05, 0xD3 };
static int         read_eeprom_sig_b_wild[] = { 0,0,0,0,0,0,0,0,0,0, 1, 0,0,0,0,0,0,0,0,0 };
/* Terza variante, trovata in "2 in 1 - Spyro: Season of Ice & Season of
 * Flame": stesso calcolo di offset in piu' visto nella scrittura, stesso
 * probabile motivo (piu' blocchi di salvataggio in una ROM 2-in-1). */
static unsigned char read_eeprom_sig_c[] = { 0x70, 0xB5, 0xA2, 0xB0, 0x0D, 0x1C, 0x04, 0x4B, 0xC3, 0x18, 0x28, 0x48, 0x00, 0x68, 0x80, 0x88, 0x83, 0x42, 0x05, 0xD3 };
static int         read_eeprom_sig_c_wild[] = { 0,0,0,0,0,0, 1,0, 0,0, 1, 0,0,0,0,0,0,0,0,0 };
static const sig_variant read_eeprom_variants[] = {
    { read_eeprom_sig_a, NULL, sizeof read_eeprom_sig_a },
    { read_eeprom_sig_b, read_eeprom_sig_b_wild, sizeof read_eeprom_sig_b },
    { read_eeprom_sig_c, read_eeprom_sig_c_wild, sizeof read_eeprom_sig_c },
};

static unsigned char verify_eeprom_signature[] = { 0x30, 0xB5, 0x82, 0xB0, 0x0C, 0x1C, 0x00, 0x04, 0x01, 0x0C, 0x00, 0x25, 0x03, 0x48, 0x00, 0x68 };

/* --- Varianti a indirizzamento FISSO a 6 bit (Rayman Advance) ---
 * Questi giochi non hanno una IdentifyEeprom: l'indirizzamento a 6 bit e'
 * deciso in compilazione, quindi vanno instradati a funzioni del payload
 * che non passano da get_eeprom_meta(). Array separati dagli altri perche'
 * puntano a offset diversi nel payload.
 *
 * ATTENZIONE: lettura e scrittura hanno prologhi quasi identici (l'unica
 * differenza e' il primo byte, cioe' la lista di registri nel push), ed e'
 * facilissimo scambiarle. Il ruolo NON e' stato dedotto dal prologo ma dai
 * conteggi dei trasferimenti DMA verso 0x0D000000:
 *   0x48634 -> dma(buf -> EEPROM, 9) poi dma(EEPROM -> buf, 68)  = LETTURA
 *   0x48788 -> dma(buf -> EEPROM, 73) in un'unica trasmissione   = SCRITTURA
 * (9 = 2 comando + 6 indirizzo + 1 stop; 68 = 4 ignorati + 64 dati;
 *  73 = 2 comando + 6 indirizzo + 64 dati + 1 stop). */
static unsigned char read_eeprom_fixed6_sig_a[] = { 0xB0, 0xB5, 0xAA, 0xB0, 0x6F, 0x46, 0x79, 0x60, 0x39, 0x1C, 0x08, 0x80, 0x38, 0x1C, 0x01, 0x88, 0x3F, 0x29, 0x00, 0xD9, 0x00, 0x48 };
/* Indici 18 e 20 in wildcard: sono l'offset di un salto condizionale e
 * l'immediato di una "ldr r0,[pc,#imm]", entrambi dipendenti da dove
 * cade la funzione nel codice compilato. In Rayman valgono 0x03 e 0x00,
 * ma un altro gioco con lo stesso compilatore potrebbe avere un layout
 * di literal pool leggermente diverso. */
static int         read_eeprom_fixed6_sig_a_wild[] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 1,0, 1,0 };
static const sig_variant read_eeprom_fixed6_variants[] = {
    { read_eeprom_fixed6_sig_a, read_eeprom_fixed6_sig_a_wild, sizeof read_eeprom_fixed6_sig_a },
};
static unsigned char write_eeprom_fixed6_sig_a[] = { 0x80, 0xB5, 0xAA, 0xB0, 0x6F, 0x46, 0x79, 0x60, 0x39, 0x1C, 0x08, 0x80, 0x38, 0x1C, 0x01, 0x88, 0x3F, 0x29, 0x00, 0xD9, 0x00, 0x48 };
static int         write_eeprom_fixed6_sig_a_wild[] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 1,0, 1,0 };
static const sig_variant write_eeprom_fixed6_variants[] = {
    { write_eeprom_fixed6_sig_a, write_eeprom_fixed6_sig_a_wild, sizeof write_eeprom_fixed6_sig_a },
};
/* La verifica rilegge tramite la funzione di lettura sopra e confronta;
 * restituisce 0 se combacia, 0x8000 in caso di discrepanza. */
static unsigned char verify_eeprom_fixed6_sig_a[] = { 0xB0, 0xB5, 0x87, 0xB0, 0x6F, 0x46, 0x79, 0x60, 0x39, 0x1C, 0x08, 0x80, 0x38, 0x1C, 0x18, 0x30, 0x00, 0x21, 0x01, 0x80, 0x38, 0x1C };
static const sig_variant verify_eeprom_fixed6_variants[] = {
    { verify_eeprom_fixed6_sig_a, NULL, sizeof verify_eeprom_fixed6_sig_a },
};

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
/* Terza variante, trovata in "2 in 1 - Spyro: Season of Ice & Season of
 * Flame": qui il compilatore genera un salto incondizionato (b) invece di
 * uno condizionato (bne) in quel punto - un'istruzione diversa, non solo
 * un offset diverso, quindi il byte dell'opcode (indice 9) resta fisso a
 * 0xE0 in questa variante invece di essere in wildcard. */
static unsigned char identify_eeprom_sig_c[] = { 0x00, 0x04, 0x00, 0x0C, 0x00, 0x22, 0x04, 0x28, 0x00, 0xE0, 0x00, 0x49, 0x02, 0x48, 0x08, 0x60 };
static int         identify_eeprom_sig_c_wild[] = { 0,0,0,0,0,0,0,0, 1,0, 1,0, 0,0,0,0 };
static const sig_variant identify_eeprom_variants[] = {
    { identify_eeprom_sig_a, NULL, sizeof identify_eeprom_sig_a },
    { identify_eeprom_sig_b, identify_eeprom_sig_b_wild, sizeof identify_eeprom_sig_b },
    { identify_eeprom_sig_c, identify_eeprom_sig_c_wild, sizeof identify_eeprom_sig_c },
};


/* Cerca una sottostringa ASCII ovunque nella ROM (usata per leggere le
 * stringhe identificative di tipo di salvataggio nell'header, es.
 * "EEPROM_V..." o "SRAM_V..."). */
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

    /* Alcuni giochi (es. "Rocky") contengono nella ROM sia una stringa
     * "EEPROM_V..." sia una "SRAM_V..." nell'header - probabile residuo di
     * un motore/SDK condiviso tra piu' release con tipi di salvataggio
     * diversi, di cui una sola e' realmente usata in questa build.
     * Patchare il lato non pertinente puo' rompere codice non collegato
     * al salvataggio che condivide per coincidenza la stessa forma di
     * funzione generica, causando crash all'avvio (visto esattamente su
     * Rocky, dove ENTRAMBE le stringhe erano presenti). Una cartuccia GBA
     * fisica ha comunque un solo chip di salvataggio, quindi diamo
     * sempre precedenza all'EEPROM quando la sua stringa e' presente,
     * indipendentemente dal fatto che compaia anche quella SRAM. Solo se
     * l'header non dichiara EEPROM proviamo la scansione SRAM; se non
     * dichiara nulla di riconoscibile, proviamo comunque tutto come
     * prima (rete di sicurezza per ROM senza header pulito). */
    int has_eeprom_id = rom_contains(rom, romsize, "EEPROM_V");
    int has_sram_id = rom_contains(rom, romsize, "SRAM_V") || rom_contains(rom, romsize, "SRAM_F_V");
    /* GBATA, quando converte un gioco da EEPROM a SRAM, lascia l'header
     * originale invariato (ancora "EEPROM_V...", solo con un marcatore
     * "(Patched)"): non aggiunge una vera stringa SRAM_V. Quindi la sola
     * presenza di EEPROM_V non basta per escludere la scansione SRAM,
     * altrimenti romperemmo proprio questo caso d'uso legittimo. Saltiamo
     * la scansione SRAM solo quando troviamo ENTRAMBE le stringhe native
     * insieme (il caso ambiguo visto su Rocky, dove SRAM_V e' una vera
     * stringa nativa, non un residuo di conversione). */
    int try_eeprom = has_eeprom_id || !has_sram_id;
    int try_sram = !(has_eeprom_id && has_sram_id);
    if (has_eeprom_id && has_sram_id)
        puts("Header declares both EEPROM and SRAM - assuming EEPROM is the real save type and skipping SRAM signature scan");

    /* Controllo preliminare su tutta la ROM: la variante 0 (sig_a) di
     * ProgramEepromDword/ReadEepromDword corrisponde esattamente al
     * codice che GBATA produce convertendo EEPROM in SRAM. Se la
     * troviamo anche una sola volta, l'intera ROM appartiene con ogni
     * probabilita' a quel contesto - quindi etichettiamo allo stesso
     * modo anche identify e verify, anche se il loro codice specifico
     * non risulta toccato da GBATA (che in pratica lascia identify e
     * verify invariati, convertendo solo read/write). */
    int gbata_converted = 0;
    for (uint8_t *scan = rom; scan < rom + romsize - 64 && !gbata_converted; scan += 2)
    {
        if (!memcmp(scan, write_eeprom_sig_a, sizeof write_eeprom_sig_a))
            gbata_converted = 1;
        else if (!memcmp(scan, read_eeprom_sig_a, sizeof read_eeprom_sig_a))
            gbata_converted = 1;
    }

	// Patch any write functions 
    int found_write_location = 0;
    for (uint8_t *write_location = rom; write_location < rom + romsize - 64; write_location += 2)
    {
        int rom_offset = write_location - rom;
		if (try_sram && !memcmp_wild(write_location, write_sram_signature, write_sram_signature_wild, sizeof write_sram_signature))
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
        if (try_sram && !memcmp(write_location, write_sram2_signature, sizeof write_sram2_signature))
		{
            found_write_location = 1;
            printf("WriteSram 2 identified at offset %lx, patching\n", write_location - rom);
            memcpy(write_location, thumb_branch_thunk, sizeof thumb_branch_thunk);
            1[(uint32_t*) write_location] = 0x08000000 + payload_base + WRITE_SRAM_PATCHED[(uint32_t*) payload_bin];

		}
		if (try_sram && !memcmp(write_location, write_sram_ram_signature, sizeof write_sram_ram_signature))
		{
            found_write_location = 1;
            printf("WriteSramFast identified at offset %lx, patching\n", write_location - rom);
            memcpy(write_location, arm_branch_thunk, sizeof arm_branch_thunk);
            2[(uint32_t*) write_location] = 0x08000000 + payload_base + WRITE_SRAM_PATCHED[(uint32_t*) payload_bin];
		}
        if (try_sram && !memcmp(write_location, read_sram_signature, sizeof read_sram_signature))
		{
            found_write_location = 1;
            printf("ReadSram identified at offset %lx, patching\n", write_location - rom);
            memcpy(write_location, thumb_branch_thunk, sizeof thumb_branch_thunk);
            1[(uint32_t*) write_location] = 0x08000000 + payload_base + READ_SRAM_PATCHED[(uint32_t*) payload_bin];

		}
        if (try_sram && !memcmp(write_location, verify_sram_signature, sizeof verify_sram_signature))
		{
            found_write_location = 1;
            printf("VerifySram identified at offset %lx, patching\n", write_location - rom);
            memcpy(write_location, thumb_branch_thunk, sizeof thumb_branch_thunk);
            1[(uint32_t*) write_location] = 0x08000000 + payload_base + VERIFY_SRAM_PATCHED[(uint32_t*) payload_bin];
		}
		int write_eeprom_match = try_eeprom ? match_any_variant(write_location, write_eeprom_variants, 5) : -1;
		if (write_eeprom_match >= 0)
		{
            found_write_location = 1;
            printf(gbata_converted
                ? "SRAM-patched ProgramEepromDword identified at offset %lx, patching\n"
                : "ProgramEepromDword identified at offset %lx, patching\n", write_location - rom);
            memcpy(write_location, thumb_branch_thunk, sizeof thumb_branch_thunk);
            1[(uint32_t*) write_location] = 0x08000000 + payload_base + WRITE_EEPROM_PATCHED[(uint32_t*) payload_bin];
		}
        int read_eeprom_match = try_eeprom ? match_any_variant(write_location, read_eeprom_variants, 3) : -1;
        if (read_eeprom_match >= 0)
		{
            found_write_location = 1;
            printf(gbata_converted
                ? "SRAM-patched ReadEepromDword identified at offset %lx, patching\n"
                : "ReadEepromDword identified at offset %lx, patching\n", write_location - rom);
            memcpy(write_location, thumb_branch_thunk, sizeof thumb_branch_thunk);
            1[(uint32_t*) write_location] = 0x08000000 + payload_base + READ_EEPROM_PATCHED[(uint32_t*) payload_bin];
		}
        if (try_eeprom && match_any_variant(write_location, read_eeprom_fixed6_variants, 1) >= 0)
        {
            found_write_location = 1;
            printf("ReadEepromDword (fixed 6-bit addressing) identified at offset %lx, patching\n", write_location - rom);
            memcpy(write_location, thumb_branch_thunk, sizeof thumb_branch_thunk);
            1[(uint32_t*) write_location] = 0x08000000 + payload_base + READ_EEPROM_FIXED6_PATCHED[(uint32_t*) payload_bin];
        }
        if (try_eeprom && match_any_variant(write_location, write_eeprom_fixed6_variants, 1) >= 0)
        {
            found_write_location = 1;
            printf("ProgramEepromDword (fixed 6-bit addressing) identified at offset %lx, patching\n", write_location - rom);
            memcpy(write_location, thumb_branch_thunk, sizeof thumb_branch_thunk);
            1[(uint32_t*) write_location] = 0x08000000 + payload_base + WRITE_EEPROM_FIXED6_PATCHED[(uint32_t*) payload_bin];
        }
        if (try_eeprom && match_any_variant(write_location, verify_eeprom_fixed6_variants, 1) >= 0)
        {
            found_write_location = 1;
            printf("VerifyEepromDword (fixed 6-bit addressing) identified at offset %lx, patching\n", write_location - rom);
            memcpy(write_location, thumb_branch_thunk, sizeof thumb_branch_thunk);
            1[(uint32_t*) write_location] = 0x08000000 + payload_base + VERIFY_EEPROM_FIXED6_PATCHED[(uint32_t*) payload_bin];
        }
        if (try_eeprom && !memcmp(write_location, verify_eeprom_signature, sizeof verify_eeprom_signature))
		{
            found_write_location = 1;
            printf(gbata_converted
                ? "SRAM-patched VerifyEepromDword identified at offset %lx, patching\n"
                : "VerifyEepromDword identified at offset %lx, patching\n", write_location - rom);
            memcpy(write_location, thumb_branch_thunk, sizeof thumb_branch_thunk);
            1[(uint32_t*) write_location] = 0x08000000 + payload_base + VERIFY_EEPROM_PATCHED[(uint32_t*) payload_bin];
		}
        if (try_eeprom && match_any_variant(write_location, identify_eeprom_variants, 3) >= 0)
        {
            found_write_location = 1;
            uint32_t meta_ptr = resolve_eeprom_meta_ptr(rom, write_location - rom);
            EEPROM_META[(uint32_t*) &rom[payload_base]] = meta_ptr;
            printf(gbata_converted
                ? "SRAM-patched IdentifyEeprom identified at offset %lx, RAM address of eeprom info is %x\n"
                : "IdentifyEeprom identified at offset %lx, RAM address of eeprom info is %x\n", write_location - rom, meta_ptr);
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
