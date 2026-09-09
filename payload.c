asm(R"(.section .text

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
    asm (R"(mov %[eeprom_meta_ptrptr], pc
    sub %[eeprom_meta_ptrptr], # . + 2 - eeprom_meta)" 
     : [eeprom_meta_ptrptr] "=r" (eeprom_meta_ptrptr));
    return **eeprom_meta_ptrptr;
}

#define SRAM_BASE ((volatile unsigned char*) (0x0E000000))
#define FLASH_MAGIC_0 (0x5555)
#define FLASH_MAGIC_1 (0x2AAA)

/*
 * FIX: il buffer di settore (fino a 2048 byte per SRAM) viveva come array
 * locale (VLA) sullo stack. Questo codice però non gira come una funzione
 * "normale" del gioco: viene raggiunto tramite un thunk che dirotta
 * l'esecuzione a metà di una routine del gioco ospite, quindi usa lo STACK
 * DEL GIOCO, la cui profondità/margine residuo in quel momento non è sotto
 * il nostro controllo. Un'allocazione di 2KB in quel contesto puo'
 * facilmente sforare lo stack e corrompere memoria adiacente, causando un
 * crash proprio al primo salvataggio.
 *
 * Il linker script (payload.ld) scarta tutto tranne .text, quindi non è
 * disponibile una vera sezione .bss/.data a runtime per questo payload:
 * non possiamo semplicemente dichiarare un array "static" normale.
 *
 * Soluzione: puntare il buffer a un indirizzo FISSO in EWRAM invece che
 * allocarlo sullo stack. L'indirizzo qui sotto è un punto di partenza
 * (in cima alla EWRAM, 0x02000000-0x0203FFFF) — se il gioco usa quella
 * zona di memoria per altro, potrebbe essere necessario cambiarlo e
 * ricompilare. E' l'unico valore da tarare per tentativi.
 */
#define SCRATCH_BUF_ADDR (0x0203F800)
#define SCRATCH_BUF_SIZE (2048) /* deve coprire il caso peggiore: 0x1000 >> 1 */

static int flashBusy(volatile unsigned char *tgt)
{
    /* Metodo standard "toggle bit": durante un'operazione in corso, il
     * bit 6 (0x40) del byte letto a questo indirizzo cambia valore ad
     * ogni lettura consecutiva. Quando smette di farlo, l'operazione e'
     * conclusa. E' il metodo usato dai driver Flash ufficiali Nintendo
     * (per questo i giochi Pokemon, che hanno il proprio driver Flash
     * originale, funzionano gia' su questa cartuccia). */
    unsigned char a = *tgt;
    unsigned char b = *tgt;
    return (a ^ b) & 0x40;
}

static void flashEraseSector(volatile unsigned char *tgt)
{
    SRAM_BASE[FLASH_MAGIC_0] = 0xAA;
    SRAM_BASE[FLASH_MAGIC_1] = 0x55;
    SRAM_BASE[FLASH_MAGIC_0] = 0x80;
    SRAM_BASE[FLASH_MAGIC_0] = 0xAA;
    SRAM_BASE[FLASH_MAGIC_1] = 0x55;
    *tgt = 0x30;
    __asm("nop");
    while(flashBusy(tgt));
    SRAM_BASE[FLASH_MAGIC_0] = 0xAA;
    SRAM_BASE[FLASH_MAGIC_1] = 0x55;
    SRAM_BASE[FLASH_MAGIC_0] = 0xF0;
}
static void flashProgramByte(volatile unsigned char *tgt, unsigned char data)
{
    SRAM_BASE[FLASH_MAGIC_0] = 0xAA;
    SRAM_BASE[FLASH_MAGIC_1] = 0x55;
    SRAM_BASE[FLASH_MAGIC_0] = 0xA0;
    *tgt = data;
    __asm("nop");
    while(flashBusy(tgt));
    SRAM_BASE[FLASH_MAGIC_0] = 0xAA;
    SRAM_BASE[FLASH_MAGIC_1] = 0x55;
    SRAM_BASE[FLASH_MAGIC_0] = 0xF0;
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

#define REG_IME (*(volatile unsigned short *) 0x04000208)

void write_core_patched(unsigned char *src, unsigned idx, unsigned size, int loadfactor_log2)
{
    unsigned sector_usage = 0x1000 >> loadfactor_log2;
    /* FIX: non piu' un array locale (VLA) sullo stack del chiamante.
     * Puntiamo a un indirizzo RAM fisso, riservato per questo scopo. */
    unsigned char *sector_buf = (unsigned char *) SCRATCH_BUF_ADDR;

    /* Interrupt lasciati attivi (rimossa la disattivazione IME che
     * avevamo qui in precedenza): causava una distorsione audio
     * percepibile durante il salvataggio, perche' bloccava il mixer
     * audio del gioco per tutta la durata dell'operazione. Era una
     * precauzione contro la corruzione del buffer di appoggio da
     * parte dell'interrupt di VBlank, aggiunta prima di scoprire i
     * bug reali (buffer sullo stack, funzione di verifica scambiata
     * per scrittura). Ora che quelli sono risolti e i tempi sono
     * molto piu' brevi, il rischio residuo sembra basso. Se il
     * salvataggio dovesse tornare a corrompersi o non persistere,
     * questo e' il primo sospetto da reintrodurre:
     *   unsigned short saved_ime = REG_IME;
     *   REG_IME = 0;
     * (e il corrispondente REG_IME = saved_ime; alla fine). */

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
        
        /* La Flash puo' portare i bit da 1 a 0 programmando direttamente:
         * solo il passaggio inverso (0 -> 1) richiede di cancellare
         * l'intero settore. Se i byte nuovi non richiedono di riportare
         * a 1 nessun bit, programmiamo quindi soltanto i byte che
         * cambiano, senza erase e senza riscrivere tutto il settore.
         *
         * Non e' un'ottimizzazione cosmetica. J-League Pocket, quando
         * non trova un salvataggio valido, azzera i 32KB di SRAM in
         * blocchi da 16 byte: con un erase + riscrittura completa del
         * settore per ogni blocco servirebbero milioni di operazioni, e
         * il gioco sembrava bloccato all'avvio. Su Flash vergine (tutta
         * 0xFF) questo percorso evita l'erase del tutto, perche' da
         * 0xFF si puo' scrivere qualsiasi valore.
         *
         * Per decidere leggiamo dalla Flash solo i byte effettivamente
         * interessati, non tutto il settore: l'intero settore serve
         * soltanto nel ramo con erase, dove va salvato e riscritto.
         * Cosi' anche il buffer di appoggio in EWRAM viene toccato solo
         * quando serve davvero. */
        int changed = 0;
        int need_erase = 0;
        for (int i = 0; i < len; ++i)
        {
            unsigned char oldb = sector[(prefix + i) << loadfactor_log2];
            unsigned char newb = src[i];
            if (oldb != newb)
            {
                changed = 1;
                if ((unsigned char) (oldb & newb) != newb)
                    need_erase = 1;
            }
        }

        if (changed && need_erase)
        {
            my_memcpy(sector_buf, 1, sector, 1 << loadfactor_log2, sector_usage);
            my_memcpy(sector_buf + prefix, 1, src, 1, len);
            flashEraseSector(sector);
            for (int i = 0; i < sector_usage; ++i)
                flashProgramByte(&sector[i << loadfactor_log2], sector_buf[i]);
        }
        else if (changed)
        {
            for (int i = 0; i < len; ++i)
                if (sector[(prefix + i) << loadfactor_log2] != src[i])
                    flashProgramByte(&sector[(prefix + i) << loadfactor_log2], src[i]);
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
    /* Analizzando il gioco abbiamo scoperto che questa funzione generica
     * di copia viene usata SIA per scrivere (RAM -> SRAM/Flash) SIA per
     * leggere (SRAM/Flash -> RAM), a seconda di quale dei due puntatori
     * cade nell'area SRAM/Flash (0x0E000000-0x0E00FFFF). Non esiste una
     * funzione ReadSram separata in questo gioco: tutte le chiamate,
     * in entrambe le direzioni, passano da qui. Prima riconoscevamo
     * solo la direzione di scrittura (assumendo dst sempre in SRAM),
     * il che rompeva silenziosamente tutte le letture. */
    if (((unsigned) dst & 0xFF000000) == 0x0E000000)
    {
        /* dst e' nell'area SRAM/Flash: scrittura RAM -> Flash */
        write_core_patched(src, 0x00007FFF & (unsigned) dst, size, 1);
    }
    else if (((unsigned) src & 0xFF000000) == 0x0E000000)
    {
        /* src e' nell'area SRAM/Flash: lettura Flash -> RAM */
        read_core_patched(dst, 0x00007FFF & (unsigned) src, size, 1);
    }
    else
    {
        /* Nessuno dei due e' nell'area SRAM/Flash: eseguiamo una copia
         * normale, cioe' esattamente quello che faceva la funzione
         * originale che abbiamo sostituito.
         *
         * Prima qui non facevamo nulla. Finora non era un problema
         * perche' le funzioni agganciate erano dedicate al salvataggio,
         * ma alcuni giochi (es. J-League Pocket) usano come driver SRAM
         * una copia byte-per-byte del tutto generica: se il gioco la
         * riusa anche per copie normali in RAM, "non fare nulla" le
         * romperebbe in silenzio. Copiare e' sempre almeno corretto
         * quanto il comportamento originale. */
        my_memcpy(dst, 1, src, 1, size);
    }
}
void read_sram_patched(unsigned char *src, unsigned char *dst, unsigned size)
{
    /* Per questo gioco non viene mai chiamata (non esiste una ReadSram
     * distinta: write_sram_patched gestisce già entrambe le direzioni
     * riconoscendo quale puntatore cade nell'area SRAM/Flash). La
     * teniamo comunque, come redirect, per compatibilità con altri
     * giochi che potrebbero avere una vera funzione ReadSram separata
     * e distinta, dato che patcher.c è uno strumento generico. */
    write_sram_patched(src, dst, size);
}
unsigned char *verify_sram_patched(unsigned char *src, unsigned char *tgt, unsigned size)
{
    /* Come write_sram_patched, non diamo per scontato quale dei due
     * puntatori sia la SRAM. La convenzione classica vuole che sia il
     * secondo (tgt), ma il driver a copia generica di alcuni giochi usa
     * la stessa funzione in entrambi i versi: se indovinassimo male,
     * mascheremmo un indirizzo RAM come indice SRAM e il confronto
     * fallirebbe sempre, facendo credere al gioco che il salvataggio
     * sia corrotto. */
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
        /* nessuno dei due e' in area SRAM: confronto normale, come
         * faceva la funzione originale */
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

/*
 * --- Varianti a indirizzamento FISSO a 6 bit (Rayman Advance) ---
 *
 * Alcuni giochi non hanno una routine "IdentifyEeprom" che rilevi a
 * runtime la dimensione dell'EEPROM: costruiscono la sequenza di comandi
 * bit per bit direttamente dentro read/write, con un indirizzamento a 6
 * bit deciso in fase di compilazione. Lo si riconosce sia dal controllo
 * "indirizzo <= 63" all'inizio della funzione, sia dai conteggi dei
 * trasferimenti DMA verso 0x0D000000: 9 bit di richiesta + 68 bit di
 * risposta per la lettura, 73 bit in un'unica trasmissione per la
 * scrittura (2 comando + 6 indirizzo + 64 dati + 1 stop).
 *
 * 6 bit di indirizzo = 64 blocchi da 8 byte = 512 byte = EEPROM da
 * 4Kbit. Usiamo quindi loadfactor_log2 = 7, lo stesso valore che il
 * percorso normale sceglie quando eeprom_meta->addrs == 0x40 (cioe'
 * proprio il caso 64 blocchi). Con 7 i 512 byte logici si distribuiscono
 * sull'intero spazio Flash da 64KB: ogni settore da 4KB ne contiene 32,
 * quindi una scrittura da 8 byte ne riprogramma 32 anziche' 512, e
 * l'usura si distribuisce su 16 settori invece di concentrarsi su uno.
 */
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
    /* Convenzione di ritorno ricavata dal disassemblato della routine
     * originale: uno slot inizializzato a 0, sovrascritto con
     * 0x80 << 8 = 0x8000 solo se il confronto trova una discrepanza.
     * Quindi 0 = tutto combacia, 0x8000 = mismatch. */
    return verify_core_patched(src, addr << 3, 1 << 3,
                               EEPROM_FIXED6_LOADFACTOR_LOG2) < 0 ? 0 : 0x8000;
}
