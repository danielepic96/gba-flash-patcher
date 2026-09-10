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

/* --- Funzione generica di copia SRAM: due firme, una per ruolo ---
 *
 * Scrittura e verifica condividono lo stesso prologo (impostazione di
 * WAITCNT) e differiscono solo nel corpo del ciclo: ldrb+strb per la
 * copia, ldrb+ldrb+cmp per il confronto. In precedenza qui c'era UNA
 * firma corta di 16 byte piu' un controllo separato dei byte 34-37 per
 * decidere il ruolo.
 *
 * Quel meccanismo curava il sintomo sbagliato. Le wildcard agli indici
 * 8 e 12 erano state introdotte credendo che l'immediato della literal
 * pool variasse con la posizione della funzione; in realta' varia tra i
 * DUE RUOLI (0x0B nella scrittura, 0x0A nella verifica), perche' i due
 * corpi hanno lunghezza diversa e quindi la literal pool cade a distanza
 * diversa. Verificato su 23 occorrenze reali: dentro ciascun ruolo non
 * varia nulla nei primi 40 byte.
 *
 * Con due firme complete il ruolo e' determinato dalla firma stessa,
 * senza controlli a distanza fissa, e sparisce il caso "corpo non
 * riconosciuto" in cui prima non si agganciava nulla.
 *
 * Le wildcard su 8 e 12 restano comunque: sono immediati di literal
 * pool e in linea di principio dipendono dalla posizione. Che siano
 * costanti nel nostro campione puo' essere fortuna di compilazioni
 * identiche, e tenerle non costa nulla dato che il ruolo e' ormai
 * garantito dal corpo incluso nella firma. */
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

/* --- VerifySram, variante "push {r4,r7,lr}" (Tanbi Musou - Meine Liebe) ---
 * Il prologo e' identico a write_sram2_signature TRANNE il primo byte:
 * 0x90 (push {r4,r7,lr}) invece di 0x80 (push {r7,lr}). Non e' una
 * coincidenza - il ciclo di confronto ha bisogno di un registro in piu'
 * per il secondo puntatore - ma un solo byte e' un appiglio troppo
 * fragile, quindi la firma arriva fino al corpo del ciclo, dove il ruolo
 * e' esplicito: due ldrb seguiti da cmp (confronto) invece di ldrb + strb
 * (copia). La literal pool interna contiene solo costanti (WAITCNT e la
 * sua maschera), quindi non serve nessuna wildcard.
 * Convenzione di ritorno: 0 se tutto combacia, altrimenti l'indirizzo del
 * byte diverso - la stessa che verify_sram_patched gia' produce. */
static unsigned char verify_sram_push4_sig[] = {
    0x90, 0xB5, 0x83, 0xB0, 0x6F, 0x46, 0x38, 0x60, 0x79, 0x60, 0xBA, 0x60, 0x09, 0x48, 0x09, 0x49,
    0x0A, 0x88, 0x09, 0x4B, 0x11, 0x1C, 0x19, 0x40, 0x0A, 0x1C, 0x03, 0x23, 0x11, 0x1C, 0x19, 0x43,
    0x0A, 0x1C, 0x02, 0x80, 0xB8, 0x68, 0x41, 0x1E, 0x08, 0x1C, 0xB8, 0x60, 0x01, 0x21, 0xC8, 0x42,
    0x04, 0xD1, 0x13, 0xE0, 0x04, 0x02, 0x00, 0x04, 0xFC, 0xFF, 0x00, 0x00, 0x38, 0x1D, 0x01, 0x68,
    0x3C, 0x68, 0x0A, 0x78, 0x23, 0x78, 0x01, 0x34, 0x3C, 0x60, 0x01, 0x31, 0x01, 0x60, 0x9A, 0x42,
    0x03, 0xD0 };

/* --- Driver SRAM copiato in RAM (Motoracer Advance) ---
 * Il gioco tiene in ROM tre blocchi consecutivi (due copie identiche e un
 * confronto) e li ricopia in RAM per eseguirli da li'. Nessuna ricerca
 * statica lo trovava, per due motivi che si sommavano: l'indirizzo SRAM
 * arriva come parametro, quindi non compare come costante dentro la
 * routine, e WAITCNT viene impostato con base 0x04000200 + offset 4
 * anziche' con la costante 0x04000204. E' saltato fuori solo col
 * debugger, mettendo un watchpoint su 0x0E000000.
 *
 * Agganciare la copia in ROM basta: il thunk viene ricopiato in RAM
 * insieme al resto e li' funziona lo stesso, perche' tutte e tre le
 * destinazioni RAM sono allineate a 4 byte (la "ldr r3,[pc,#0]" del
 * thunk legge il proprio letterale, anch'esso copiato).
 *
 * Come sempre, i ruoli NON sono dedotti dal prologo (identico per tutte
 * e tre) ma dal corpo del ciclo: ldrb+strb = copia, ldrb+ldrb+cmp =
 * confronto. */
static unsigned char sram_ramexec_copy_sig[] = {
    0x90, 0xB4, 0x0A, 0x4F, 0x0A, 0x4B, 0xBC, 0x88, 0x1C, 0x40, 0x03, 0x23, 0x23, 0x43, 0xBB, 0x80,
    0x53, 0x1E, 0x00, 0x2A, 0x07, 0xD0, 0x02, 0x78, 0x01, 0x30, 0x0A, 0x70, 0x1A, 0x1C, 0x01, 0x3B,
    0x01, 0x31, 0x00, 0x2A };
/* Ritorna 0 se tutto combacia, altrimenti l'indirizzo del byte diverso:
 * la stessa convenzione che verify_sram_patched gia' produce. */
static unsigned char sram_ramexec_verify_sig[] = {
    0x90, 0xB4, 0x0C, 0x4F, 0x0C, 0x4B, 0xBC, 0x88, 0x1C, 0x40, 0x03, 0x23, 0x23, 0x43, 0xBB, 0x80,
    0x53, 0x1E, 0x00, 0x2A, 0x0C, 0xD0, 0x0F, 0x78, 0x02, 0x78, 0x01, 0x30, 0x01, 0x31, 0x97, 0x42,
    0x02, 0xD0, 0x48, 0x1E, 0x90, 0xBC, 0x70, 0x47 };

/* --- WriteSram, variante con push esteso (Rhythm Tengoku) ---
 * Stessa sostanza delle copie SRAM classiche - imposta WAITCNT con la
 * maschera 0xFFFC e poi copia byte per byte - ma salva quattro registri
 * invece di due nel prologo (push {r4,r5,r6,r7,lr} anziche'
 * push {r4,r5,lr}), il che bastava a renderla invisibile a tutte le
 * firme esistenti. Era la seconda voce della tabella dei driver, con le
 * altre due gia' agganciate.
 * La firma arriva fino al corpo del ciclo (ldrb + strb) cosi' il ruolo
 * di copia e' provato dal comportamento, non dedotto dal prologo. La
 * literal pool interna contiene solo costanti (WAITCNT e la sua
 * maschera), quindi non serve nessuna wildcard. */
static unsigned char write_sram_push4reg_sig[] = {
    0xF0, 0xB5, 0x04, 0x1C, 0x0E, 0x1C, 0x15, 0x1C, 0x03, 0x4A, 0x10, 0x88, 0x03, 0x49, 0x08, 0x40,
    0x03, 0x21, 0x08, 0x43, 0x10, 0x80, 0x0A, 0xE0, 0x04, 0x02, 0x00, 0x04, 0xFC, 0xFF, 0x00, 0x00,
    0x20, 0x78, 0x30, 0x70, 0x01, 0x34, 0x01, 0x36, 0x01, 0x3D, 0x00, 0x2D };

/* --- WriteSram, variante autonoma senza WAITCNT proprio ---
 * (prima voce di tabella in Yu-Gi-Oh Double Pack, Top Gun, Rockman EXE
 * 4.5, One Piece, 4 Games on One Game Pak; presente anche in Rocky, dove
 * pero' la regola dell'header salta comunque tutta la SRAM)
 *
 * E' la controparte di verify_sram_standalone_sig: stessa famiglia, non
 * imposta WAITCNT per conto proprio, nessuna literal pool e quindi
 * nessun byte dipendente dalla posizione. Come tutte le funzioni di
 * copia, gestisce entrambe le direzioni: il payload riconosce a runtime
 * quale dei due puntatori cade nell'area SRAM.
 *
 * Era sfuggita a tutte le firme precedenti: in Yu-Gi-Oh e' la PRIMA voce
 * della tabella dei driver, raggiunta solo tramite quel puntatore e con
 * zero chiamate 'bl' - il tipo di funzione che sembra morta se si guarda
 * un solo indizio invece di entrambi. */
static unsigned char write_sram_standalone_sig[] = {
    0x10, 0xB5, 0x04, 0x1C, 0x53, 0x1E, 0x00, 0x2A, 0x08, 0xD0, 0x01, 0x22, 0x52, 0x42, 0x20, 0x78,
    0x08, 0x70, 0x01, 0x34, 0x01, 0x31, 0x01, 0x3B, 0x93, 0x42, 0xF8, 0xD1, 0x10, 0xBC };

/* --- VerifySram, variante autonoma senza WAITCNT proprio ---
 * (Top Gun: Combat Zones, Rockman EXE 4.5, One Piece: Mezase King of
 * Belly, 4 Games on One Game Pak, e presente ma mai riconosciuta anche
 * in Rocky e Yu-Gi-Oh)
 *
 * A differenza di tutte le altre varianti SRAM viste finora, questa non
 * imposta WAITCNT per conto proprio (lo fa il chiamante prima); il corpo
 * e' un confronto byte-per-byte autonomo, senza nessuna literal pool -
 * nessun byte dipende dalla posizione, quindi nessuna wildcard serve.
 * Trovata analizzando i "siti driver SRAM non coperti" segnalati da
 * scanner.c: e' la riprova che quel controllo funziona anche su ROM che
 * risultavano gia' "ok" con le firme esistenti.
 * Convenzione di ritorno: 0 se tutto combacia, altrimenti l'indirizzo
 * del byte diverso - la stessa di verify_sram_patched. */
static unsigned char verify_sram_standalone_sig[] = {
    0x30, 0xB5, 0x05, 0x1C, 0x0B, 0x1C, 0x54, 0x1E, 0x00, 0x2A, 0x0C, 0xD0, 0x01, 0x22, 0x52, 0x42,
    0x19, 0x78, 0x28, 0x78, 0x01, 0x35, 0x01, 0x33, 0x81, 0x42, 0x01, 0xD0, 0x58, 0x1E };

/* --- Driver SRAM a copia generica (J-League Pocket) ---
 * Questi giochi hanno una tabella di quattro funzioni subito dopo la
 * stringa "SRAM_Vxxx" nell'header: copia, copia-eseguita-da-RAM,
 * confronto, confronto-eseguito-da-RAM. Le due "fast" non impostano
 * WAITCNT (lo fa il wrapper), quindi non assomigliano a nessuna delle
 * firme SRAM classiche e sfuggivano completamente al patcher.
 *
 * I due wrapper copiano la routine interna sullo stack e la eseguono
 * da li' (trampolino "bx r3"): agganciandoli, la copia non avviene
 * proprio, quindi il problema si risolve alla radice.
 *
 * ATTENZIONE: copia e confronto hanno prologhi che differiscono di UN
 * SOLO byte (la lista di registri nel push). Per questo le due firme
 * "fast" sono lunghe 40 byte: arrivano fino al corpo del ciclo, dove
 * la distinzione e' esplicita (strb = copia, ldrb+cmp = confronto) e
 * non affidata a un singolo byte. */
static unsigned char sram_gencopy_sig[] = {
    0x80, 0xB5, 0x83, 0xB0, 0x6F, 0x46, 0x38, 0x60, 0x79, 0x60, 0xBA, 0x60, 0xB8, 0x68, 0x41, 0x1E,
    0x08, 0x1C, 0xB8, 0x60, 0x01, 0x21, 0xC8, 0x42, 0x00, 0xD1, 0x09, 0xE0, 0x38, 0x1D, 0x01, 0x68,
    0x3A, 0x68, 0x13, 0x78, 0x0B, 0x70, 0x01, 0x32 };
static unsigned char sram_genverify_sig[] = {
    0x90, 0xB5, 0x83, 0xB0, 0x6F, 0x46, 0x38, 0x60, 0x79, 0x60, 0xBA, 0x60, 0xB8, 0x68, 0x41, 0x1E,
    0x08, 0x1C, 0xB8, 0x60, 0x01, 0x21, 0xC8, 0x42, 0x00, 0xD1, 0x0F, 0xE0, 0x38, 0x1D, 0x01, 0x68,
    0x3C, 0x68, 0x0A, 0x78, 0x23, 0x78, 0x01, 0x34 };

/* Wrapper che copiano la routine in RAM. I byte 12, 14 e 18 sono
 * immediati di "ldr rX, [pc, #imm]" e dipendono dalla posizione: in
 * wildcard. Il byte 2 e' la dimensione dello stack allocato ed e'
 * l'unica cosa che distingue il wrapper di copia (0xA7) da quello di
 * confronto (0xB7), quindi deve restare esatto - il che rende queste
 * due firme piu' specifiche di questo gioco rispetto alle "fast". */
static unsigned char sram_gencopy_ram_sig[] = {
    0x90, 0xB5, 0xA7, 0xB0, 0x6F, 0x46, 0x38, 0x60, 0x79, 0x60, 0xBA, 0x60, 0x00, 0x48, 0x00, 0x49, 0x0A, 0x88, 0x00, 0x4B };
static int         sram_gencopy_ram_wild[] = { 0,0,0,0,0,0,0,0,0,0,0,0, 1,0, 1,0, 0,0, 1,0 };
static unsigned char sram_genverify_ram_sig[] = {
    0x90, 0xB5, 0xB7, 0xB0, 0x6F, 0x46, 0x38, 0x60, 0x79, 0x60, 0xBA, 0x60, 0x00, 0x48, 0x00, 0x49, 0x0A, 0x88, 0x00, 0x4B };
static int         sram_genverify_ram_wild[] = { 0,0,0,0,0,0,0,0,0,0,0,0, 1,0, 1,0, 0,0, 1,0 };


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
    int has_flash_id = rom_contains(rom, romsize, "FLASH_V")
                     || rom_contains(rom, romsize, "FLASH512_V")
                     || rom_contains(rom, romsize, "FLASH1M_V");
    /* GBATA, quando converte un gioco da EEPROM a SRAM, lascia l'header
     * originale invariato (ancora "EEPROM_V...", solo con un marcatore
     * "(Patched)"): non aggiunge una vera stringa SRAM_V. Quindi la sola
     * presenza di EEPROM_V non basta per escludere la scansione SRAM,
     * altrimenti romperemmo proprio questo caso d'uso legittimo. */
    int try_eeprom = has_eeprom_id || !has_sram_id;

    /* Se l'header dichiara SIA EEPROM SIA SRAM, il salvataggio vero e'
     * l'EEPROM e la scansione SRAM va saltata del tutto.
     *
     * Verificato su Rocky (E): senza questa regola il gioco aggancia
     * anche il lato SRAM, e il suo auto-test di avvio - che scrive 10
     * byte e li rilegge - RIESCE invece di fallire come farebbe su una
     * cartuccia EEPROM originale, mandando il gioco in un loop infinito.
     * Il sintomo e' caratteristico: il primo avvio funziona (Flash
     * vergine, il test fallisce correttamente), il blocco arriva dal
     * SECONDO avvio in poi, quando il pattern di test e' ormai scritto.
     *
     * Non e' un problema di prestazioni e non e' risolvibile altrove:
     * l'unico modo e' non toccare affatto la SRAM in questi giochi.
     *
     * La stessa identica situazione si presenta con FLASH+SRAM insieme
     * (Top Gun: Combat Zones, Rockman EXE 4.5, From TV Animation One
     * Piece: Mezase King of Belly dichiarano entrambi): un driver Flash
     * nativo completo (sequenza di sblocco AA/55/80/AA/55/30) convive
     * con un driver SRAM, con selezione a runtime dell'hardware
     * collegato - la stessa architettura di Rocky, solo con Flash al
     * posto dell'EEPROM. Non abbiamo la controprova diretta che queste
     * tre ROM abbiano un auto-test capace di bloccarsi come quello di
     * Rocky, ma il rischio e' lo stesso per costruzione: se il vero
     * hardware e' Flash, la ChisCart lo emula correttamente da sola
     * (il driver del gioco parla gia' il protocollo giusto, senza
     * bisogno di alcuna patch), quindi non c'e' motivo di rischiare
     * toccando anche la SRAM. */
    int try_sram = !((has_eeprom_id || has_flash_id) && has_sram_id);
    if (has_eeprom_id && has_sram_id)
        puts("Header declares both EEPROM and SRAM - assuming EEPROM is the real save type and skipping SRAM signature scan");
    else if (has_flash_id && has_sram_id)
        puts("Header declares both FLASH and SRAM - assuming FLASH is the real save type and skipping SRAM signature scan");

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
		if (try_sram && !memcmp_wild(write_location, write_sram_generic_sig, write_sram_generic_wild, sizeof write_sram_generic_sig))
		{
            found_write_location = 1;
            printf("WriteSram identified at offset %lx, patching\n", write_location - rom);
            memcpy(write_location, thumb_branch_thunk, sizeof thumb_branch_thunk);
            1[(uint32_t*) write_location] = 0x08000000 + payload_base + WRITE_SRAM_PATCHED[(uint32_t*) payload_bin];
		}
		if (try_sram && !memcmp_wild(write_location, verify_sram_generic_sig, verify_sram_generic_wild, sizeof verify_sram_generic_sig))
		{
            found_write_location = 1;
            printf("VerifySram (generic variant) identified at offset %lx, patching\n", write_location - rom);
            memcpy(write_location, thumb_branch_thunk, sizeof thumb_branch_thunk);
            1[(uint32_t*) write_location] = 0x08000000 + payload_base + VERIFY_SRAM_PATCHED[(uint32_t*) payload_bin];
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
        if (try_sram && !memcmp(write_location, verify_sram_push4_sig, sizeof verify_sram_push4_sig))
        {
            found_write_location = 1;
            printf("VerifySram (push r4 variant) identified at offset %lx, patching\n", write_location - rom);
            memcpy(write_location, thumb_branch_thunk, sizeof thumb_branch_thunk);
            1[(uint32_t*) write_location] = 0x08000000 + payload_base + VERIFY_SRAM_PATCHED[(uint32_t*) payload_bin];
        }
        if (try_sram && !memcmp(write_location, sram_ramexec_copy_sig, sizeof sram_ramexec_copy_sig))
        {
            found_write_location = 1;
            printf("WriteSram (RAM-executed driver) identified at offset %lx, patching\n", write_location - rom);
            memcpy(write_location, thumb_branch_thunk, sizeof thumb_branch_thunk);
            1[(uint32_t*) write_location] = 0x08000000 + payload_base + WRITE_SRAM_PATCHED[(uint32_t*) payload_bin];
        }
        if (try_sram && !memcmp(write_location, sram_ramexec_verify_sig, sizeof sram_ramexec_verify_sig))
        {
            found_write_location = 1;
            printf("VerifySram (RAM-executed driver) identified at offset %lx, patching\n", write_location - rom);
            memcpy(write_location, thumb_branch_thunk, sizeof thumb_branch_thunk);
            1[(uint32_t*) write_location] = 0x08000000 + payload_base + VERIFY_SRAM_PATCHED[(uint32_t*) payload_bin];
        }
        if (try_sram && !memcmp(write_location, write_sram_push4reg_sig, sizeof write_sram_push4reg_sig))
        {
            found_write_location = 1;
            printf("WriteSram (extended push variant) identified at offset %lx, patching\n", write_location - rom);
            memcpy(write_location, thumb_branch_thunk, sizeof thumb_branch_thunk);
            1[(uint32_t*) write_location] = 0x08000000 + payload_base + WRITE_SRAM_PATCHED[(uint32_t*) payload_bin];
        }
        /* Le quattro firme che seguono descrivono solo la FORMA di un
         * ciclo di copia o di confronto byte: non contengono nulla di
         * specifico della SRAM (nessun WAITCNT, nessun indirizzo), quindi
         * combaciano anche con una memcpy o una memcmp qualsiasi. Sono
         * affidabili solo se il gioco dichiara SRAM nell'header.
         *
         * Senza questo vincolo il patcher agganciava due funzioni di
         * libreria in Pokemon Emerald, che dichiara solo FLASH1M e sulla
         * cartuccia funziona gia' nativamente: una patch li' e' puro
         * danno potenziale, senza alcun beneficio.
         *
         * Verificato su 20 ROM: ogni riscontro legittimo di queste firme
         * avviene in un gioco con header SRAM; l'unico caso senza header
         * SRAM era proprio il falso positivo. */
        if (try_sram && has_sram_id && !memcmp(write_location, write_sram_standalone_sig, sizeof write_sram_standalone_sig))
        {
            found_write_location = 1;
            printf("WriteSram (standalone variant) identified at offset %lx, patching\n", write_location - rom);
            memcpy(write_location, thumb_branch_thunk, sizeof thumb_branch_thunk);
            1[(uint32_t*) write_location] = 0x08000000 + payload_base + WRITE_SRAM_PATCHED[(uint32_t*) payload_bin];
        }
        if (try_sram && has_sram_id && !memcmp(write_location, verify_sram_standalone_sig, sizeof verify_sram_standalone_sig))
        {
            found_write_location = 1;
            printf("VerifySram (standalone variant) identified at offset %lx, patching\n", write_location - rom);
            memcpy(write_location, thumb_branch_thunk, sizeof thumb_branch_thunk);
            1[(uint32_t*) write_location] = 0x08000000 + payload_base + VERIFY_SRAM_PATCHED[(uint32_t*) payload_bin];
        }
        if (try_sram && has_sram_id && !memcmp(write_location, sram_gencopy_sig, sizeof sram_gencopy_sig))
        {
            found_write_location = 1;
            printf("WriteSram (generic copy driver) identified at offset %lx, patching\n", write_location - rom);
            memcpy(write_location, thumb_branch_thunk, sizeof thumb_branch_thunk);
            1[(uint32_t*) write_location] = 0x08000000 + payload_base + WRITE_SRAM_PATCHED[(uint32_t*) payload_bin];
        }
        if (try_sram && !memcmp_wild(write_location, sram_gencopy_ram_sig, sram_gencopy_ram_wild, sizeof sram_gencopy_ram_sig))
        {
            found_write_location = 1;
            printf("WriteSram (generic copy driver, RAM-executed) identified at offset %lx, patching\n", write_location - rom);
            memcpy(write_location, thumb_branch_thunk, sizeof thumb_branch_thunk);
            1[(uint32_t*) write_location] = 0x08000000 + payload_base + WRITE_SRAM_PATCHED[(uint32_t*) payload_bin];
        }
        if (try_sram && has_sram_id && !memcmp(write_location, sram_genverify_sig, sizeof sram_genverify_sig))
        {
            found_write_location = 1;
            printf("VerifySram (generic copy driver) identified at offset %lx, patching\n", write_location - rom);
            memcpy(write_location, thumb_branch_thunk, sizeof thumb_branch_thunk);
            1[(uint32_t*) write_location] = 0x08000000 + payload_base + VERIFY_SRAM_PATCHED[(uint32_t*) payload_bin];
        }
        if (try_sram && !memcmp_wild(write_location, sram_genverify_ram_sig, sram_genverify_ram_wild, sizeof sram_genverify_ram_sig))
        {
            found_write_location = 1;
            printf("VerifySram (generic copy driver, RAM-executed) identified at offset %lx, patching\n", write_location - rom);
            memcpy(write_location, thumb_branch_thunk, sizeof thumb_branch_thunk);
            1[(uint32_t*) write_location] = 0x08000000 + payload_base + VERIFY_SRAM_PATCHED[(uint32_t*) payload_bin];
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
        /* Un gioco che dichiara Flash non ha bisogno di patch: una
         * flashcart lo supporta nativamente. Vale sia quando l'header
         * dichiara Flash insieme a SRAM (Top Gun e simili) sia quando
         * dichiara solo Flash (Pokemon Emerald): in entrambi i casi il
         * messaggio generico "sei sicuro che il gioco salvi?" sarebbe
         * fuorviante, perche' il gioco salva benissimo. */
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
