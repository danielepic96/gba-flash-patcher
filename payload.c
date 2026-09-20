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

/* Due livelli, ed entrambi possono essere vuoti.
 *
 * Il primo e' la parola che il patcher scrive qui sopra: resta 0 se
 * IdentifyEeprom non ha combaciato, e succede - le firme del driver e
 * quella di IdentifyEeprom sono indipendenti, quindi gli agganci possono
 * essere installati lo stesso. Dereferenziare uno zero sul GBA non da'
 * errore: restituisce spazzatura, e da li' in poi si lavorerebbe su
 * metadati inventati. Il controllo va fatto qui, perche' il !eeprom_meta
 * dei chiamanti arriva dopo entrambe le dereferenziazioni e lo zero non
 * lo vedrebbe mai.
 *
 * Il secondo e' la variabile del gioco, che vale 0 finche' IdentifyEeprom
 * non l'ha riempita: anche quello e' un "metadati non ancora
 * disponibili" legittimo, non un errore. */
__attribute__((noinline)) struct eeprom_meta **get_eeprom_meta_slot(void)
{
    struct eeprom_meta ***eeprom_meta_ptrptr;
    asm volatile (
        ".align 2\n\t"
        "mov %[eeprom_meta_ptrptr], pc\n\t"
        "sub %[eeprom_meta_ptrptr], # . + 2 - eeprom_meta"
        : [eeprom_meta_ptrptr] "=r" (eeprom_meta_ptrptr)
    );
    return *eeprom_meta_ptrptr;
}

/* I due livelli restano distinti perche' significano cose diverse, e la
 * differenza conta per la migrazione: con lo slot a zero non sapremo mai
 * nulla, con lo slot valido e la variabile ancora a zero lo sapremo fra
 * poco. Vedi eeprom_loadfactor. */
static struct eeprom_meta *get_eeprom_meta(void)
{
    struct eeprom_meta **slot = get_eeprom_meta_slot();
    return slot ? *slot : 0;
}

#define SRAM_BASE ((volatile unsigned char*) (0x0E000000))
#define FLASH_MAGIC_0 (0x5555)
#define FLASH_MAGIC_1 (0x2AAA)
/* Mappa della EWRAM usata dal payload. La EWRAM va da 0x02000000 a
 * 0x0203FFFF e i dati dei giochi crescono verso l'alto a partire dal
 * fondo, quindi la cima e' la zona che viene occupata per ultima ed e'
 * li' che ci mettiamo.
 *
 * AMD/JEDEC, invariato rispetto alla versione precedente:
 *   0x0203F7F8 .. 0x0203F7FF   cache del protocollo, 8 byte
 *   0x0203F800 .. 0x0203FFFF   buffer, 2 KB (se ne usa 0x1000>>lf)
 *
 * Intel/Sharp, ancorato in cima e lungo quanto serve (0x10000>>lf):
 *   0x0203FE00 .. 0x0203FFFF     512 byte   con loadfactor_log2 = 7
 *   0x0203E000 .. 0x0203FFFF       8 KB     con loadfactor_log2 = 3
 *   0x02038000 .. 0x0203FFFF      32 KB     con loadfactor_log2 = 1
 *
 * Perche' su Intel serve tanto: l'unita' di cancellazione e' un blocco
 * da 64 KB, cioe' l'intera area di salvataggio. Con un buffer da 2 KB il
 * giro lettura-modifica-riscrittura non si chiude e tutto cio' che sta
 * fuori dalla finestra scritta viene perso; con un buffer grande quanto
 * l'area si chiude, e non si perde niente.
 *
 * Il prezzo e' che su una cartuccia Intel quella memoria viene
 * sovrascritta durante il salvataggio: se il gioco la stava usando si
 * guasta. E' una scelta deliberata - meglio un guasto immediato e
 * visibile che un salvataggio che si porta via gli altri slot in
 * silenzio - e non ha alcun effetto sulle cartucce AMD, dove questa
 * memoria non viene mai toccata.
 *
 * Con loadfactor_log2 1 o 3 il buffer Intel ricopre anche gli 8 byte
 * della cache del protocollo, che viene percio' riscritta alla fine di
 * write_core_patched.
 *
 * I giochi EEPROM non passano da qui: usano il journal, che ha la sua
 * mappa poco piu' sotto. Le due non convivono mai, perche' una cartuccia
 * e' o SRAM o EEPROM. */
#define SCRATCH_BUF_ADDR (0x0203F800)
#define SCRATCH_BUF_SIZE (2048)
#define EWRAM_END        (0x02040000)
#define FLASH_MAX_ATTEMPTS 3

/* Tetto di attesa, su entrambi i protocolli.
 *
 * Su AMD la via d'uscita la darebbe il chip: DQ5 e' il flag del suo timer
 * interno e si alza MENTRE l'operazione e' ancora in corso, quindi basta
 * guardarlo. Ma vale solo per un chip che DQ5 lo implementa davvero, e
 * AMD e' il ripiego di ogni identificazione fallita - e' cioe' il ramo su
 * cui finisce anche un chip che non abbiamo riconosciuto. Un chip Intel
 * scambiato per AMD resta in read array, le scritture di sblocco non
 * significano niente per lui, e la lettura restituisce il byte
 * memorizzato: durante un erase aspettiamo bit 7 a 1, quindi un banale
 * 0x00 nel salvataggio da bit 7 diverso e bit 5 a zero, e si gira per
 * sempre. Il contatore e' la seconda rete dietro DQ5.
 *
 * Su Intel non esiste nemmeno la prima rete: SR.4 e SR.5 sono bit di
 * esito, validi solo quando SR.7 vale 1, e finche' il chip e' occupato
 * leggono 0. Li' il contatore e' l'unica uscita.
 *
 * Ogni giro del ciclo contiene una lettura dalla cartuccia, che con
 * WAITCNT a 3 costa 8 cicli, piu' confronto e salto: una quindicina di
 * cicli in tutto. A 16.777.216 Hz fanno circa un milione di giri al
 * secondo.
 *
 * I valori sono volutamente larghi. Un tetto che scatta su un chip sano
 * e' peggio del problema che risolve: interromperebbe una cancellazione
 * a meta'. Un erase di blocco Intel puo' arrivare a qualche secondo nei
 * casi peggiori, un program di un byte sta sotto il millisecondo. */
#define FLASH_LOOPS_PER_SECOND 1048576UL
#define FLASH_TIMEOUT_ERASE    (8UL * FLASH_LOOPS_PER_SECOND)    /* ~8 s   */
#define FLASH_TIMEOUT_PROGRAM  (FLASH_LOOPS_PER_SECOND / 20UL)   /* ~50 ms */

#define PROTO_AMD_JEDEC 0
#define PROTO_INTEL_SHARP 1

#define MFR_INTEL    0x89
#define MFR_SHARP_A  0xB0
#define MFR_SHARP_B  0x05

/* Wait state dell'area di salvataggio.
 *
 * La funzione del gioco che sostituiamo comincia proprio impostando i
 * due bit bassi di WAITCNT a 3, cioe' 8 cicli: l'attesa piu' lunga,
 * quella che qualsiasi chip regge. Il nostro thunk prende il posto del
 * prologo, quindi quel passaggio veniva SALTATO e gli accessi alla Flash
 * avvenivano con il valore che il gioco si era lasciato dietro.
 *
 * Su un chip veloce non si nota. Su uno lento - le cartucce economiche -
 * e' il modo classico di ottenere letture inaffidabili e scritture che
 * non attecchiscono. Il wait state detta anche la distanza fra le
 * scritture della sequenza di sblocco: a 2 cicli si susseguono a circa
 * 0,12 us, a 8 cicli a 0,5 us, e un chip lento potrebbe non stare dietro
 * alla prima.
 *
 * Il valore precedente non viene ripristinato perche' non lo faceva
 * nemmeno la funzione originale: lo impostava a 3 all'ingresso e lo
 * lasciava li'. Questi due bit riguardano solo l'area di salvataggio e
 * non la ROM, quindi lasciarli al massimo non rallenta il gioco, e
 * protegge anche gli accessi che il gioco facesse per conto suo. */
#define REG_WAITCNT (*(volatile unsigned short *) 0x04000204)

static void flashSetWaitState(void)
{
    REG_WAITCNT = (unsigned short) ((REG_WAITCNT & 0xFFFC) | 3);
}

static int detect_flash_type(void)
{
    flashSetWaitState();

    /* I due byte prima del comando di identificazione. Se dopo il
     * comando non e' cambiato nessuno dei due, il chip non e' entrato in
     * quella modalita' - capita sulle cartucce economiche che non la
     * implementano - e quello che leggeremmo sarebbe un dato qualsiasi,
     * non un identificativo. Guardarne due invece di uno rende la
     * coincidenza praticamente impossibile, e in caso di dubbio si
     * ricade su AMD, che e' il verso sicuro. */
    unsigned char before_mfr = SRAM_BASE[0x0000];
    unsigned char before_dev = SRAM_BASE[0x0001];

    SRAM_BASE[FLASH_MAGIC_0] = 0xAA;
    SRAM_BASE[FLASH_MAGIC_1] = 0x55;
    SRAM_BASE[FLASH_MAGIC_0] = 0x90;
    __asm("nop");
    unsigned char m_id = SRAM_BASE[0x0000];
    unsigned char d_id = SRAM_BASE[0x0001];

    /* Due reset, sempre, prima di qualsiasi uscita.
     *
     * 0x90 e' il comando di identificazione di entrambe le famiglie, ma si
     * esce in due modi diversi: 0xF0 su AMD, 0xFF su Intel. Mandarne uno
     * solo lascia scoperto il caso del chip che HA risposto a 0x90 ma il
     * cui codice costruttore non e' fra i tre riconosciuti: si esce dal
     * fondo, come AMD, con il chip ancora in modalita' identificazione.
     * Da li' in poi ogni lettura della finestra restituisce i byte di
     * identificazione invece dei dati - il payload li copierebbe nel
     * buffer del gioco e, peggio, li riprogrammerebbe nella Flash dopo
     * una cancellazione.
     *
     * Il reset AMD va mandato nella forma a TRE CICLI, preceduto dalla
     * sequenza di sblocco. Su silicio vero basterebbe la scrittura
     * singola di 0xF0 - il datasheet la ammette da qualunque stato - ma
     * non tutte le implementazioni la riconoscono: mGBA, per dirne una,
     * accetta 0xF0 soltanto dopo 0xAA e 0x55 e all'indirizzo di sblocco,
     * e con la scrittura singola il chip resta in identificazione per
     * sempre. La forma a tre cicli e' valida anche sui chip veri, quindi
     * non si perde niente a usarla.
     *
     * Il 0xFF di Intel resta una scrittura singola, che per quella
     * famiglia e' la forma giusta. Mandarli entrambi non costa niente:
     * ciascuno dei due e' privo di significato per l'altra famiglia. */
    SRAM_BASE[FLASH_MAGIC_0] = 0xAA;
    SRAM_BASE[FLASH_MAGIC_1] = 0x55;
    SRAM_BASE[FLASH_MAGIC_0] = 0xF0;
    __asm("nop");
    SRAM_BASE[0x0000] = 0xFF;
    __asm("nop");

    if (m_id == before_mfr && d_id == before_dev)
        return PROTO_AMD_JEDEC;

    if (m_id == MFR_INTEL || m_id == MFR_SHARP_A || m_id == MFR_SHARP_B)
        return PROTO_INTEL_SHARP;

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
    /* expected vale 0xFF solo per l'erase: un program con dato 0xFF non
     * arriva mai qui, perche' nel ramo senza cancellazione un byte 0xFF
     * implica che la cella sia gia' 0xFF e venga saltata, e nel ramo con
     * cancellazione i 0xFF si saltano per definizione. */
    unsigned long budget = (expected == 0xFF) ? FLASH_TIMEOUT_ERASE
                                              : FLASH_TIMEOUT_PROGRAM;

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
            /* La condizione di uscita e' solo il contatore. Guardare qui
             * i bit di errore sarebbe inutile: sono validi solo con
             * SR.7 = 1, e con SR.7 = 1 siamo gia' usciti dall'if sopra. */
        } while (--budget);
        *tgt = 0x50;
        *tgt = 0xFF;
        return 0;
    }

    unsigned char value = expected & 0x80;
    volatile unsigned char a;
    /* DQ5 resta la condizione principale: se il chip lo implementa si esce
     * di li' senza consumare il contatore, che interviene solo quando DQ5
     * non arriva mai. In entrambi i casi si ricontrolla DQ7 una volta prima
     * di dichiarare il fallimento, perche' l'operazione potrebbe essere
     * terminata proprio nel giro in cui siamo usciti. */
    do {
        a = *tgt;
        if ((a & 0x80) == value)
            return 1;
    } while (!(a & 0x20) && --budget);
    if ((*tgt & 0x80) == value)
        return 1;
    *tgt = 0xF0;
    __asm("nop");
    return 0;
}

/* flashEraseSector e flashProgramByte restituiscono 1 se l'operazione e'
 * andata a buon fine, 0 se tutti i tentativi sono falliti.
 *
 * Prima erano void e il chiamante proseguiva comunque. Due conseguenze:
 * dopo una cancellazione fallita il settore resta cancellato a meta' e la
 * riprogrammazione ci scriveva sopra, producendo 'vecchio AND nuovo' -
 * cioe' il blocco misto che nel ripiego di can_buffer abbiamo deciso di
 * non produrre mai; e su un chip che non risponde i tetti di attesa si
 * moltiplicano per il numero di byte (3 tentativi da 50 ms per ognuno dei
 * 32768 byte fanno piu' di un'ora). Alla prima operazione fallita conviene
 * fermare tutta la scrittura: il blocco e' gia' perso, insistere lo rovina
 * di piu' e basta. */
static int flashEraseSector(volatile unsigned char *tgt, int protocol)
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
                return 1;
            *tgt = (protocol == PROTO_AMD_JEDEC) ? 0xF0 : 0xFF;
            __asm("nop");
        }
    }
    return 0;
}

static int flashProgramByte(volatile unsigned char *tgt, unsigned char data, int protocol)
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
                return 1;
            *tgt = (protocol == PROTO_AMD_JEDEC) ? 0xF0 : 0xFF;
            __asm("nop");
        }
    }
    return 0;
}
int my_memcpy(volatile unsigned char *dst, int dstride, volatile unsigned char *src, int sstride, unsigned size)
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

/* Il puntatore e' volatile: la finestra della cartuccia non e' memoria
 * normale, e le letture non vanno accorpate ne' spostate rispetto alle
 * scritture dei comandi. */
volatile unsigned char *translate(unsigned idx, int loadfactor_log2)
{
    return (volatile unsigned char *) (0x0E000000 | idx << loadfactor_log2);
}

void write_core_patched(unsigned char *src, unsigned idx, unsigned size, int loadfactor_log2)
{
    flashSetWaitState();
    int protocol = flash_protocol();
    /* Dimensione in byte dell'unita' di cancellazione del chip. E' l'unica
     * assunzione che, se sbagliata, provoca perdita di dati invece che
     * lentezza: cancelleremmo piu' di quanto poi ripristiniamo.
     *
     * VERIFICATO: le cartucce repro montano tutte chip AMD/JEDEC con
     * settori da 4KB. L'unica eccezione nota sono gli Atmel originali,
     * che lavorano a pagine da 128 byte, e quelli sulle repro non
     * compaiono. Non serve quindi ricavare la dimensione da un
     * identificativo.
     *
     * Se un giorno saltasse fuori un Atmel non basterebbe cambiare
     * questo numero: quella famiglia ha un modello di scrittura diverso
     * - si scrive una pagina intera e la cancellazione avviene da se' -
     * quindi servirebbe un secondo percorso di codice, non una voce di
     * tabella.
     *
     * I chip Intel/Sharp cancellano a blocchi da 64KB. Il ciclo qui sotto
     * resta lo stesso: cambiano solo l'unita' e il buffer, e con un'unita'
     * da 64KB il ciclo fa sempre un giro solo, perche' un blocco copre
     * gia' tutta l'area di salvataggio. */
    /* Con segno, perche' viene confrontato con len e con prefix, che con
     * segno lo sono: un confronto misto fra int e unsigned promuove l'int
     * a unsigned, e un valore negativo diventerebbe enorme. Qui non puo'
     * succedere - i valori vanno da 512 a 65536 - ma il confronto misto e'
     * proprio il modo in cui questi errori passano inosservati. */
    int sector_usage;
    unsigned char *sector_buf;
    if (protocol == PROTO_INTEL_SHARP)
    {
        /* Ancorato in cima alla EWRAM e lungo esattamente quanto serve:
         * con loadfactor_log2 3 o 7 si toccano 8 KB o 512 byte invece di
         * 32, e sono comunque i byte piu' alti, i meno esposti.
         *
         * Qui l'unita' di cancellazione e' l'intera area di salvataggio,
         * quindi ogni chiamata che richiede la cancellazione riscrive
         * tutta l'area invece di un settore. Per la SRAM va bene, perche'
         * i giochi scrivono il salvataggio in una o poche chiamate
         * grandi. Sarebbe insostenibile per le EEPROM, che scrivono 8
         * byte per volta - ma quelle non passano piu' da questa funzione:
         * hanno il loro percorso a journal. */
        sector_usage = 0x10000 >> loadfactor_log2;
        sector_buf   = (unsigned char *) (EWRAM_END - sector_usage);
    }
    else
    {
        /* loadfactor_log2 non vale mai 0 - i chiamanti passano 1, 3 o 7 -
         * quindi questo vale al massimo 2048, cioe' SCRATCH_BUF_SIZE: il
         * buffer AMD copre sempre l'intero settore da 4 KB. Con 0 servirebbe
         * il doppio e si sborderebbe oltre la cima della EWRAM. */
        sector_usage = 0x1000 >> loadfactor_log2;
        sector_buf   = (unsigned char *) SCRATCH_BUF_ADDR;
    }

    /* I dati che il gioco ci passa possono trovarsi dentro il buffer.
     * Riguarda in pratica il solo percorso Intel, dove il buffer arriva a
     * 32 KB di EWRAM e lo spazio di lavoro del gioco puo' caderci dentro;
     * sui 2 KB in cima usati da AMD non e' successo in nessuno dei giochi
     * provati, e finche' e' cosi' questo controllo e' vero e il percorso
     * AMD si comporta esattamente come prima.
     *
     * Se le due aree si sovrapponessero, la copia della Flash nel buffer
     * distruggerebbe i dati di origine prima di averli letti, e nella
     * Flash finirebbe spazzatura: un salvataggio scritto correttamente e
     * pieno di valori sbagliati, che nessuna verifica intercetta. In quel
     * caso i blocchi che richiedono la cancellazione non vengono scritti
     * affatto - vedi il ramo piu' sotto. */
    unsigned src_lo = (unsigned) src;
    unsigned buf_lo = (unsigned) sector_buf;
    int can_buffer = (src_lo + size <= buf_lo) || (src_lo >= buf_lo + sector_usage);

    /* Alla prima operazione fallita si esce dal ciclo invece di proseguire
     * sui blocchi successivi: il chip non risponde piu' come dovrebbe, e
     * insistere significa solo moltiplicare i tetti di attesa. Si esce con
     * break e non con return perche' la cache del protocollo va comunque
     * ripristinata in fondo alla funzione. */
    int failed = 0;

    while (size)
    {
        int prefix = (sector_usage - 1) & idx;
        volatile unsigned char *sector = translate(idx - prefix, loadfactor_log2);
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
        if (need_erase && can_buffer)
        {
            my_memcpy(sector_buf, 1, sector, 1 << loadfactor_log2, sector_usage);
            my_memcpy(sector_buf + prefix, 1, src, 1, len);
            if (!flashEraseSector(sector, protocol))
                break;
            for (int i = 0; i < sector_usage; ++i)
            {
                if (sector_buf[i] != 0xFF
                    && !flashProgramByte(&sector[i << loadfactor_log2], sector_buf[i], protocol))
                {
                    failed = 1;
                    break;
                }
            }
            if (failed)
                break;
        }
        else if (need_erase)
        {
            /* Serve la cancellazione ma il buffer non e' utilizzabile,
             * perche' i dati di origine ci stanno dentro. Qui non si
             * scrive niente, di proposito.
             *
             * Cancellare e riscrivere la sola finestra porterebbe via
             * tutto il resto del blocco. Programmare i soli byte
             * compatibili sarebbe peggio ancora: siamo in questo ramo
             * proprio perche' almeno un byte richiede una transizione
             * 0->1, quindi quel byte resterebbe vecchio e il blocco
             * finirebbe misto - ne' il salvataggio nuovo ne' quello
             * vecchio - con le programmazioni gia' fatte irreversibili.
             *
             * Non facendo nulla il vecchio salvataggio resta intero e
             * coerente. La verifica del gioco fallisce e il giocatore
             * vede che il salvataggio non riesce: un guasto visibile e
             * senza danni collaterali.
             *
             * Gli altri blocchi della stessa chiamata non sono coinvolti:
             * quelli che non richiedono cancellazione passano dal ramo
             * sotto e vengono scritti normalmente. */
        }
        else
        {
            for (int i = 0; i < len; ++i)
            {
                unsigned char oldb = sector[(prefix + i) << loadfactor_log2];
                unsigned char newb = src[i];
                if (oldb != newb
                    && !flashProgramByte(&sector[(prefix + i) << loadfactor_log2], newb, protocol))
                {
                    failed = 1;
                    break;
                }
            }
            if (failed)
                break;
        }
        src += len;
        idx += len;
        size -= len;
    }

    /* Su Intel il buffer copre anche gli 8 byte della cache del
     * protocollo, che a questo punto sono stati sovrascritti: la
     * riscriviamo, cosi' la chiamata successiva non deve ripetere la
     * rilevazione. Non e' una questione di correttezza - senza cache si
     * rileva di nuovo e basta - ma di tempo. */
    if (protocol == PROTO_INTEL_SHARP)
        FLASH_PROTO_CACHE = (FLASH_PROTO_MAGIC << 8) | (unsigned) protocol;
}

void read_core_patched(unsigned char *dst, unsigned idx, unsigned size, int loadfactor_log2)
{
    flashSetWaitState();
    my_memcpy(dst, 1, translate(idx, loadfactor_log2), 1 << loadfactor_log2, size);
}

int verify_core_patched(unsigned char *src, unsigned idx, unsigned size, int loadfactor_log2)
{
    flashSetWaitState();
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

/* La maschera 0x00007FFF e il ribaltamento oltre la fine dell'area NON
 * sono sviste, e non vanno "corretti".
 *
 * La SRAM del GBA e' da 32 KB e si specchia dentro la finestra da 64 KB:
 * sull'hardware vero un accesso a 0x0E008000 tocca la stessa cella di
 * 0x0E000000. Mascherare a 15 bit riproduce esattamente quello.
 *
 * Lo stesso vale per un indice che supera la fine dell'area mentre il
 * ciclo di write_core_patched avanza. L'interleaving e' scelto in modo
 * che l'area logica riempia esattamente i 64 KB della finestra - 32768x2,
 * 8192x8, 512x128 fanno tutti 65536 - quindi quando l'indice logico
 * sfora, l'indirizzo fisico supera i 64 KB e la cartuccia, che decodifica
 * solo i 16 bit bassi, lo riporta all'inizio. Ribaltamento logico e
 * fisico coincidono per costruzione, e per la SRAM coincidono anche con
 * quello che farebbe l'hardware.
 *
 * Rifiutare o troncare ci renderebbe meno fedeli di cio' che stiamo
 * emulando. Il caso che andava chiuso - un salvataggio da 64 KB ripiegato
 * sulla propria prima meta' - riguarda solo i giochi FLASH, e si chiude
 * nel patcher non agganciandoli affatto, non qui. */
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
    /* Le funzioni originali restituiscono sempre un puntatore dentro il
     * SECONDO argomento, quale che sia dei due a stare nella finestra
     * della cartuccia (nelle firme finiscono tutte con un sub r0, <secondo
     * puntatore>, #1). Ricostruire l'indirizzo come 0x0E000000 | indice
     * era corretto solo quando la finestra era tgt; quando invece era src,
     * il chiamante si aspettava un puntatore dentro il proprio buffer in
     * RAM e si ritrovava un indirizzo di cartuccia.
     *
     * Ricavare lo scostamento e sommarlo a tgt copre correttamente
     * entrambi i casi, e nel primo restituisce l'indirizzo che il gioco ci
     * ha passato invece di una sua versione normalizzata - se aveva usato
     * un mirror, se lo ritrova. */
    int error_idx = verify_core_patched(ram, idx, size, 1);
    return error_idx < 0 ? 0 : tgt + (unsigned) (error_idx - (int) idx);
}

/* Senza metadati non si rifiuta: si procede con 3, cioe' l'EEPROM da
 * 64 Kbit. E' il ripiego che il codice prendeva gia' prima, quando la
 * dereferenziazione di troppo faceva leggere un valore qualsiasi che
 * quasi mai valeva 0x40 - solo che ora e' una scelta esplicita invece
 * del risultato di una lettura indefinita. Rifiutare sarebbe peggio:
 * quei giochi oggi salvano, e smetterebbero. */
#define EEPROM_DEFAULT_LOADFACTOR_LOG2 3

/* Il fattore serve a una cosa sola: rileggere un eventuale salvataggio nel
 * formato precedente per convertirlo. E' una operazione irreversibile che
 * capita una volta sola, quindi sbagliare il passo qui non da' un
 * salvataggio lento, da' un salvataggio distrutto.
 *
 * Senza metadati bisogna distinguere due casi che finora erano lo stesso:
 *
 * - il patcher non ha trovato IdentifyEeprom, la casella e' zero e sara'
 *   zero per sempre. Il gioco ha sempre lavorato con il ripiego 3, quindi
 *   il suo vecchio salvataggio e' scritto con passo 3: convertire con 3 e'
 *   la scelta giusta, non un ripiego.
 *
 * - la casella e' valida ma la variabile del gioco e' ancora a zero:
 *   IdentifyEeprom non e' stata ancora eseguita. Qui il fattore vero
 *   potrebbe essere 7, e usare 3 leggerebbe il vecchio salvataggio con il
 *   passo sbagliato e lo riscriverebbe irriconoscibile. Si restituisce -1,
 *   che per ej_ready significa "non convertire adesso": la chiamata
 *   fallisce, il gioco identifica la EEPROM e alla successiva si converte
 *   con il passo giusto. */
static int eeprom_loadfactor(struct eeprom_meta *m)
{
    if (m)
        return m->addrs == 0x40 ? 7 : 3;
    return get_eeprom_meta_slot() ? -1 : EEPROM_DEFAULT_LOADFACTOR_LOG2;
}

/* ================================================================
 * EEPROM: strato a journal
 * ================================================================
 *
 * Le EEPROM non usano piu' translate() ne' write_core_patched. Il motivo
 * e' l'usura: scrivere un blocco da 8 byte dentro un settore costava
 * quasi sempre una cancellazione dell'intero settore, cioe' circa una
 * cancellazione per blocco modificato. Con il journal una scrittura e'
 * una programmazione in spazio vergine, e si cancella solo quando il
 * journal si riempie.
 *
 * La logica sta in ejournal.c, che e' incluso qui sotto e non altrove:
 * deve stare DOPO get_eeprom_meta, perche' quella funzione calcola la
 * distanza dalla tabella dei salti con un immediato Thumb a 8 bit e non
 * sopporta di essere allontanata. Aggiungere codice dopo di lei e'
 * sempre sicuro, prima no.
 *
 * Mappa in EWRAM del journal (vale solo per i giochi EEPROM):
 *
 *   0x0203F800 .. 0x0203FFFF   indice, 1024 voci da 2 byte
 *   0x0203F7F8 .. 0x0203F7FF   cache del protocollo (gia' esistente)
 *   0x0203F7F0 .. 0x0203F7F7   controllo del journal, 8 byte
 *   0x0203D7F0 .. 0x0203F7EF   buffer temporaneo da 8 KB, SOLO su chip a
 *                              blocco unico e SOLO durante migrazione e
 *                              compattazione
 *
 * Su una cartuccia AMD il buffer temporaneo non serve: la migrazione usa
 * l'area dell'indice, che in quel momento non e' ancora valida. Quindi
 * l'occupazione permanente resta di 2064 byte, come prima del journal. */

#define EJ_CTRL_ADDR      (SCRATCH_BUF_ADDR - 16)
#define EJ_INDEX_ADDR     (SCRATCH_BUF_ADDR)
#define EJ_INDEX_LEN      (2048)
#define EJ_TMP_INTEL_LEN  (8192)
#define EJ_TMP_INTEL      (EJ_CTRL_ADDR - EJ_TMP_INTEL_LEN)

struct ej_ctrl;

/* Il journal indirizza la finestra in modo piatto, senza interlacciamento:
 * e' proprio lo spazio liberato dall'interlacciamento a ospitarlo. */
static unsigned char ej_rd(unsigned off)
{
    return *(volatile unsigned char *) (0x0E000000 | (off & 0xFFFF));
}

static int ej_pgm(unsigned off, const unsigned char *s, unsigned n)
{
    int protocol = flash_protocol();
    for (unsigned i = 0; i < n; ++i)
    {
        volatile unsigned char *t =
            (volatile unsigned char *) (0x0E000000 | ((off + i) & 0xFFFF));
        if (*t == s[i])
            continue;                      /* gia' cosi': niente da fare */
        if (!flashProgramByte(t, s[i], protocol))
            return 0;
    }
    return 1;
}

static int ej_erase(unsigned off)
{
    return flashEraseSector(
        (volatile unsigned char *) (0x0E000000 | (off & 0xFFFF)),
        flash_protocol());
}

static int ej_single_block(void)
{
    return flash_protocol() == PROTO_INTEL_SHARP;
}

static struct ej_ctrl *ej_ctrl(void)
{
    return (struct ej_ctrl *) EJ_CTRL_ADDR;
}

static unsigned short *ej_index(void)
{
    return (unsigned short *) EJ_INDEX_ADDR;
}

static unsigned char *ej_tmp(unsigned *len)
{
    if (ej_single_block())
    {
        *len = EJ_TMP_INTEL_LEN;
        return (unsigned char *) EJ_TMP_INTEL;
    }
    *len = EJ_INDEX_LEN;
    return (unsigned char *) EJ_INDEX_ADDR;
}

#include "ejournal.c"

/* Il fattore di interlacciamento non serve piu' a indirizzare: serve solo
 * a leggere un eventuale salvataggio nel formato precedente, la prima
 * volta, per convertirlo. */
unsigned write_eeprom_patched(unsigned short addr, unsigned char *src)
{
    flashSetWaitState();
    struct eeprom_meta *eeprom_meta = get_eeprom_meta();
    /* Il limite che controllavano le funzioni originali, con lo stesso
     * confronto: nelle firme c'e' un cmp con cfg->addrs seguito da bcc.
     * Se i metadati mancano il limite non e' noto e non si controlla. */
    if (eeprom_meta && addr >= eeprom_meta->addrs)
        return 1;
    return ej_write_block(addr, src, eeprom_loadfactor(eeprom_meta)) ? 0 : 1;
}

unsigned read_eeprom_patched(unsigned short addr, unsigned char *dst)
{
    flashSetWaitState();
    return ej_read_block(addr, dst, eeprom_loadfactor(get_eeprom_meta())) ? 0 : 1;
}

unsigned verify_eeprom_patched(unsigned short addr, unsigned char *src)
{
    flashSetWaitState();
    unsigned char cur[8];
    if (!ej_read_block(addr, cur, eeprom_loadfactor(get_eeprom_meta())))
        return 1;
    for (int i = 0; i < 8; ++i)
        if (cur[i] != src[i])
            return 1;
    return 0;
}

#define EEPROM_FIXED6_LOADFACTOR_LOG2 7

/* Il passo del vecchio formato per il ramo a 6 bit fissi.
 *
 * Normalmente e' 7 e basta: quelle funzioni lavorano per costruzione su
 * una EEPROM da 4 Kbit. Ma le firme fixed6 e quelle a indirizzamento
 * variabile sono indipendenti, e niente impedisce che combacino tutte e
 * due nella stessa ROM. Se i metadati sono disponibili e dicono un'altra
 * cosa - cioe' che questa cartuccia non e' da 4 Kbit - allora il
 * salvataggio vecchio e' scritto con un passo diverso da 7, e convertirlo
 * con 7 lo renderebbe irriconoscibile. In quel caso si restituisce -1, che
 * per ej_ready significa non convertire.
 *
 * Senza metadati si resta a 7, che e' il comportamento di sempre: per un
 * gioco fixed6 vero e' il valore giusto. */
static int eeprom_fixed6_loadfactor(void)
{
    struct eeprom_meta *m = get_eeprom_meta();
    if (m && m->addrs != 0x40)
        return -1;
    return EEPROM_FIXED6_LOADFACTOR_LOG2;
}

/* Le funzioni originali controllano il limite - nelle firme fixed6 c'e'
 * un cmp r1,#0x3F seguito da bls - e il nostro thunk sovrascrive quel
 * controllo senza rimpiazzarlo. Un indirizzo fuori range non darebbe
 * errore: si ribalterebbe su un blocco valido e lo sovrascriverebbe.
 *
 * Con un gioco che si comporta bene non succede mai. Conta nello scenario
 * che ci riguarda davvero, cioe' una firma che combacia per sbaglio su una
 * funzione che non e' il driver EEPROM e che viene chiamata con parametri
 * qualsiasi: li' il controllo trasforma "corrompe il salvataggio in
 * silenzio" in "non fa niente".
 *
 * Solo sulla scrittura. La lettura e la verifica non possono danneggiare
 * nulla - al massimo restituiscono dati ribaltati - e aggiungere li' un
 * controllo cambierebbe comportamento senza togliere nessun rischio.
 *
 * Il valore restituito resta quello del successo: non sappiamo cosa
 * restituiscano gli originali sul ramo d'errore, e inventare una
 * convenzione sarebbe peggio che non segnalare. Quello che conta e' non
 * scrivere. */
#define EEPROM_FIXED6_MAX_ADDR 0x3F

unsigned write_eeprom_fixed6_patched(unsigned short addr, unsigned char *src)
{
    flashSetWaitState();
    if (addr > EEPROM_FIXED6_MAX_ADDR)
        return 0;
    return ej_write_block(addr, src, eeprom_fixed6_loadfactor()) ? 0 : 1;
}

unsigned read_eeprom_fixed6_patched(unsigned short addr, unsigned char *dst)
{
    flashSetWaitState();
    return ej_read_block(addr, dst, eeprom_fixed6_loadfactor()) ? 0 : 1;
}

unsigned verify_eeprom_fixed6_patched(unsigned short addr, unsigned char *src)
{
    flashSetWaitState();
    unsigned char cur[8];
    if (!ej_read_block(addr, cur, eeprom_fixed6_loadfactor()))
        return 0x8000;
    for (int i = 0; i < 8; ++i)
        if (cur[i] != src[i])
            return 0x8000;
    return 0;
}
