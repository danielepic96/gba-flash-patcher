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
 * Giochi SRAM:
 *   0x0203F7F8 .. 0x0203F7FB   indirizzo delle routine di lettura in RAM
 *   0x0203F7FC .. 0x0203F7FF   cache del descrittore del chip
 *   0x0203F800 .. 0x0203FFFF   buffer del settore, 2 KB (se ne usa
 *                              0x1000>>lf)
 *
 * I giochi EEPROM non usano il buffer del settore: hanno il journal, che
 * ha la sua mappa poco piu' sotto e riusa le stesse due celle. Le due
 * mappe non convivono mai, perche' una cartuccia e' o SRAM o EEPROM.
 *
 * CHIP RICONOSCIUTI
 *
 * Il chip viene identificato una volta (comando 0x90) e da li' ogni
 * operazione si regola sui suoi parametri. La tabella e' quella della
 * libreria FLASH_V123, letta dal disassemblato di Golden Sun - L'Era
 * Perduta; e' una libreria per chip da 64 KB, senza cambio banco, cioe'
 * esattamente il nostro caso.
 *
 *   chip                  codici     wait  tetto     dopo la           bit di
 *                                    state erase     cancellazione     stato
 *   SST 39VF512           0xBF 0xD4    1     40 tick controllo+margine   no
 *   SST 39xF010/020/040   0xBF 0xD5-D7 3     40 tick niente              no
 *   Macronix MX29L512     0xC2 0x1C    3   2000 tick niente              si'
 *   Macronix MX29L010     0xC2 0x09    3   2000 tick niente              si'
 *   Panasonic MN63F805MNP 0x32 0x1B    0    500 tick niente              no
 *   Sanyo LE26FV10N1TS    0x62 0x13    3   2000 tick niente              si'
 *   Atmel AT29LV512       0x1F 0x3D    3   (pagine da 128 byte, 40 tick)
 *   sconosciuto           -            3     40 tick controllo+margine   no
 *
 * Il program di un byte ha per tutti il tetto di 10 tick.
 *
 * "Wait state" e' quello tenuto durante cancellazione e program; letture
 * e verifica girano sempre a 3, e a 3 lo si rimette alla fine di ogni
 * operazione, come fa la libreria.
 *
 * "Controllo+margine" e' la routine che la libreria usa per SST e per i
 * chip sconosciuti: dopo la cancellazione si verifica che l'intero settore
 * sia a 0xFF e, se non lo e', si ripete fino a 80 volte; poi si cancella
 * ancora per margine, una volta se era riuscita subito e sei se aveva
 * avuto bisogno di ripetizioni. Macronix e Panasonic cancellano e basta.
 *
 * DOVE CI SI SCOSTA DA GOLDEN SUN, e perche':
 *
 *  - SST 39LF/VF010, 020 e 040 (0xD5, 0xD6, 0xD7) non sono in nessuna
 *    libreria Nintendo: sono i chip delle cartucce repro, e lo 040 e'
 *    quello montato sulla ChisCart. I parametri vengono dal loro
 *    datasheet (DS20005023): cancellazione del settore in 25 ms al
 *    massimo, program in 20 us, e fine operazione segnalata dal bit 7,
 *    che e' cio' che l'attesa guarda confrontando il byte intero. Niente
 *    bit 5: su questi chip non e' un bit di stato - il datasheet dichiara
 *    validi i soli bit 7 e 6 - quindi non lo si interpreta. E niente
 *    controllo+margine: quella routine serve a chi non sa dire quando ha
 *    finito, e raddoppia le cancellazioni su un chip garantito per 10000.
 *    Wait state 3 perche' e' quello con cui la ChisCart e' stata provata.
 *  - Macronix e' riconosciuto con due codici: lo 0x1C del chip da 512
 *    Kbit, che e' l'unico di FLASH_V123, e lo 0x09 di quello da 1 Mbit,
 *    che viene da FLASH1M_V103. Non dal solo costruttore: un Macronix di
 *    un'altra serie potrebbe avere settori piu' grandi di 4 KB, e finisce
 *    fra gli sconosciuti come ogni altro chip che non conosciamo.
 *  - Su Macronix l'attesa guarda anche il bit 5, manda il reset a tutti i
 *    fallimenti e la cancellazione si ritenta fino a cinque volte. E' la
 *    logica della libreria FLASH1M_V103 (Smeraldo) ed e' il percorso
 *    provato sulla ChisCart. FLASH_V123 su Macronix non guarda il bit 5 e
 *    cancella una volta sola.
 *  - Sanyo non e' in FLASH_V123: e' preso da FLASH1M_V103, dove usa le
 *    stesse funzioni e gli stessi tempi di Macronix.
 *  - Le ottimizzazioni di scrittura restano: si cancella solo quando un
 *    bit deve tornare a 1, dopo la cancellazione i byte a 0xFF si rileggono
 *    invece di programmarli, e le EEPROM passano dal journal. La libreria
 *    riscrive sempre il settore intero, ma lei serve giochi Flash che
 *    salvano a settori; noi adattiamo SRAM ed EEPROM, che scrivono a pezzi.
 *
 * Il ramo Intel/Sharp che c'era in una versione precedente e' stato
 * tolto: chip con quei comandi sulla finestra di salvataggio non se ne
 * conoscono. */
#define SCRATCH_BUF_ADDR (0x0203F800)
#define SCRATCH_BUF_SIZE (2048)
/* Descrittore del chip: un byte che riassume la riga della tabella qui
 * sopra. Sta in una parola invece che in una tabella di costanti perche'
 * il payload e' fatto di sola .text - il linker scarta tutto il resto -
 * e per lo stesso motivo le scelte sono catene di if e non switch. */
#define CF_WAIT_MASK     0x03   /* wait state durante erase e program     */
#define CF_STATUS        0x04   /* bit 5, reset e tentativi multipli      */
#define CF_VERIFY        0x08   /* controllo del settore e margine        */
#define CF_ATMEL         0x10   /* scrittura a pagine                     */
#define CF_ERASE_40      0x00   /* tetto della cancellazione, in tick     */
#define CF_ERASE_500     0x20
#define CF_ERASE_2000    0x40
#define CF_ERASE_MASK    0x60

#define CHIP_SST         (1 | CF_VERIFY | CF_ERASE_40)
#define CHIP_SST39       (3 | CF_ERASE_40)
#define CHIP_MACRONIX    (3 | CF_STATUS | CF_ERASE_2000)
#define CHIP_PANASONIC   (0 | CF_ERASE_500)
#define CHIP_SANYO       (3 | CF_STATUS | CF_ERASE_2000)
#define CHIP_ATMEL       (3 | CF_ATMEL)
#define CHIP_UNKNOWN     (3 | CF_VERIFY | CF_ERASE_40)

/* Chip con CF_STATUS, come EraseFlashSector_MX di FLASH1M_V103: un
 * tentativo piu' fino a quattro ripetizioni, cinque in tutto. Gli altri
 * chip senza CF_VERIFY cancellano una volta sola, come in FLASH_V123. */
#define FLASH_ERASE_ATTEMPTS 5
/* Chip con CF_VERIFY, come la routine SST di FLASH_V123: fino a 80 ripetizioni
 * (si rinuncia all'ottantunesimo fallimento), poi le cancellazioni di
 * margine. */
#define FLASH_B_ERASE_GIVEUP   0x51
#define FLASH_B_MARGIN_CLEAN   1
#define FLASH_B_MARGIN_RETRIED 6
/* Atmel, come le routine Atmel di FLASH_V123: tre tentativi per
 * pagina. */
#define ATMEL_PAGE          128u
#define ATMEL_PAGE_ATTEMPTS 3

/* Tetto di attesa.
 *
 * La via d'uscita la darebbe il chip: DQ5 e' il flag del suo timer
 * interno e si alza MENTRE l'operazione e' ancora in corso, quindi basta
 * guardarlo. Ma vale solo per un chip che DQ5 lo implementa davvero: su
 * uno che non lo fa, o che non capisce affatto i nostri comandi e resta
 * in lettura, il byte letto puo' non coincidere mai con quello atteso e
 * avere il bit 5 a zero, e si girerebbe per sempre. Il contatore e' la
 * seconda rete dietro DQ5.
 *
 * Ogni giro del ciclo contiene una lettura dalla cartuccia, che con
 * WAITCNT a 3 costa 8 cicli, piu' chiamata, confronto e salto. La stima
 * qui sotto - circa un milione di giri al secondo - e' per difetto: il
 * giro vero e' piu' lento, quindi i tetti reali sono piu' larghi.
 *
 * Un tetto che scatta su un chip sano e' peggio del problema che risolve:
 * interromperebbe una cancellazione a meta'. */
#define FLASH_LOOPS_PER_SECOND 1048576UL
/* I tetti sono quelli delle tabelle maxTime delle librerie Nintendo,
 * espressi nei loro tick: timer a 256 cicli con ricarica 65469, cioe' un
 * tick ogni ~1 ms. Qui il tempo si conta in giri del ciclo di attesa;
 * eseguito dalla ROM il giro e' piu' lento della stima, quindi il tetto
 * reale e' uguale o piu' largo di quello Nintendo, mai piu' stretto. */
#define FLASH_TICKS(n)          ((unsigned long) (n) * (FLASH_LOOPS_PER_SECOND / 1000UL))
#define FLASH_TIMEOUT_PROGRAM   FLASH_TICKS(10)     /* tutti i chip       */
#define FLASH_TIMEOUT_ERASE_2000 FLASH_TICKS(2000)  /* Macronix, Sanyo    */
#define FLASH_TIMEOUT_ERASE_500  FLASH_TICKS(500)   /* Panasonic          */
#define FLASH_TIMEOUT_ERASE_40   FLASH_TICKS(40)    /* SST e sconosciuti  */
#define FLASH_TIMEOUT_PAGE      FLASH_TICKS(40)     /* pagina Atmel       */

#define REG_IME (*(volatile unsigned short *) 0x04000208)

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

/* Letture dalla Flash eseguite dalla RAM, come nella libreria Nintendo.
 *
 * FLASH1M_V103 non legge mai la Flash da codice in ROM: SetReadFlash1
 * copia la routine di lettura di un byte in un buffer sullo stack (IWRAM)
 * e tutte le letture - attesa di fine operazione, identificazione,
 * ReadFlash, VerifyFlashSector - passano da li'. Le scritture dei comandi
 * restano in ROM. Si fa lo stesso: tre routine minime, scritte qui come
 * codice macchina Thumb, vengono copiate in un buffer sullo stack della
 * funzione d'ingresso e chiamate tramite puntatore.
 *
 *   rd1      ldrb r0,[r0] / bx lr                         lettura di un byte
 *   rdcopy   (dst, flash, size, passo) copia Flash -> RAM  come ReadFlash_Core
 *   rdverify (ram, flash, size, passo) -> byte rimasti     come VerifyFlashSector_Core
 *
 * Il buffer vive finche' e' viva la funzione che l'ha preparato; il suo
 * indirizzo sta in una cella fissa in cima alla EWRAM, perche' il payload
 * non ha variabili globali.
 *
 * La cella e' quella a SCRATCH_BUF_ADDR - 8, dove prima stava la cache
 * del protocollo: e' memoria che il payload scriveva gia' in tutti i
 * giochi provati. NON va messa a SCRATCH_BUF_ADDR - 12: li' coincide con
 * i campi head, slot e pad di struct ej_ctrl (0x0203F7F4..F7), e ogni
 * scrittura di c->head da parte del journal cambierebbe questo puntatore,
 * mandando la lettura successiva a un indirizzo qualsiasi. */
#define RAMCODE_PTR (*(volatile unsigned *) (SCRATCH_BUF_ADDR - 8))
#define RAMCODE_HALFWORDS 27
#define RAMCODE_OFF_RD1      0
#define RAMCODE_OFF_RDCOPY   4
#define RAMCODE_OFF_RDVERIFY 0x1A

static void flashRamSetup(volatile unsigned short *buf)
{
    buf[0]  = 0x7800; buf[1]  = 0x4770;                         /* rd1 */
    buf[2]  = 0xB410; buf[3]  = 0x2A00; buf[4]  = 0xD005;       /* rdcopy */
    buf[5]  = 0x780C; buf[6]  = 0x7004; buf[7]  = 0x3001;
    buf[8]  = 0x18C9; buf[9]  = 0x3A01; buf[10] = 0xE7F7;
    buf[11] = 0xBC10; buf[12] = 0x4770;
    buf[13] = 0xB430; buf[14] = 0x2A00; buf[15] = 0xD007;       /* rdverify */
    buf[16] = 0x7804; buf[17] = 0x780D; buf[18] = 0x42AC;
    buf[19] = 0xD103; buf[20] = 0x3001; buf[21] = 0x18C9;
    buf[22] = 0x3A01; buf[23] = 0xE7F5; buf[24] = 0x0010;
    buf[25] = 0xBC30; buf[26] = 0x4770;
    RAMCODE_PTR = (unsigned) buf;
}

typedef unsigned char (*rd1_fn)(volatile unsigned char *);
typedef void (*rdcopy_fn)(volatile unsigned char *, volatile unsigned char *, unsigned, unsigned);
typedef unsigned (*rdverify_fn)(volatile unsigned char *, volatile unsigned char *, unsigned, unsigned);

static unsigned char frd(volatile unsigned char *p)
{
    return ((rd1_fn) (RAMCODE_PTR + RAMCODE_OFF_RD1 + 1))(p);
}

static void fcopy(volatile unsigned char *dst, volatile unsigned char *flash, unsigned size, unsigned stride)
{
    ((rdcopy_fn) (RAMCODE_PTR + RAMCODE_OFF_RDCOPY + 1))(dst, flash, size, stride);
}

static unsigned fverify(volatile unsigned char *ram, volatile unsigned char *flash, unsigned size, unsigned stride)
{
    return ((rdverify_fn) (RAMCODE_PTR + RAMCODE_OFF_RDVERIFY + 1))(ram, flash, size, stride);
}

static void flashSetWaitState(void)
{
    REG_WAITCNT = (unsigned short) ((REG_WAITCNT & 0xFFFC) | 3);
}

/* Wait state del chip per la durata di una cancellazione o di un program.
 * Chi la chiama rimette 3 con flashSetWaitState appena l'attesa e' finita,
 * come fanno le routine della libreria. */
static void flashSetWriteWait(int chip)
{
    REG_WAITCNT = (unsigned short) ((REG_WAITCNT & 0xFFFC) | (chip & CF_WAIT_MASK));
}

/* Reset nella forma a tre cicli all'indirizzo di sblocco. Nintendo scrive
 * il solo 0xF0 a 0x5555, e su silicio vero basterebbe; qui lo si fa
 * precedere da 0xAA/0x55 perche' non tutte le implementazioni accettano
 * la scrittura singola - mGBA, per dirne una, riconosce 0xF0 soltanto
 * dopo la sequenza di sblocco. La forma a tre cicli e' valida anche sui
 * chip veri, quindi non si perde niente a usarla. */
static void flashResetAmd(void)
{
    SRAM_BASE[FLASH_MAGIC_0] = 0xAA;
    SRAM_BASE[FLASH_MAGIC_1] = 0x55;
    SRAM_BASE[FLASH_MAGIC_0] = 0xF0;
    __asm("nop");
}

/* Ritardo come quello della libreria Nintendo: un contatore volatile a
 * 16 bit da 20000 (0x4E20) decrementato in un ciclo, circa 20 ms. Nintendo
 * lo usa dopo il comando di identificazione 0x90, prima di leggere i due
 * byte, e di nuovo dopo l'uscita con 0xF0. */
static void flashDelayId(void)
{
    volatile unsigned short n = 20000;
    while (n)
        n = n - 1;
}

/* Identificazione, come ReadFlashId: 0x90, attesa, lettura dei due codici,
 * uscita con 0xF0, attesa. Lo 0xF0 e' scritto due volte come in
 * FLASH1M_V103 (FLASH_V123 lo scrive una volta sola): la seconda scrittura
 * e' innocua per tutti e serve ai chip di quella libreria.
 *
 * I due byte letti PRIMA del comando servono a riconoscere il chip che in
 * modalita' identificazione non ci entra affatto: se dopo il comando non
 * e' cambiato nessuno dei due, quello che si legge e' il salvataggio e non
 * un codice, e prenderlo per buono potrebbe far scegliere la routine
 * Atmel su un chip che Atmel non e'. In quel caso il chip e' sconosciuto. */
static int detect_flash_chip(void)
{
    unsigned char before_mfr = frd(&SRAM_BASE[0x0000]);
    unsigned char before_dev = frd(&SRAM_BASE[0x0001]);

    SRAM_BASE[FLASH_MAGIC_0] = 0xAA;
    SRAM_BASE[FLASH_MAGIC_1] = 0x55;
    SRAM_BASE[FLASH_MAGIC_0] = 0x90;
    flashDelayId();
    unsigned char m_id = frd(&SRAM_BASE[0x0000]);
    unsigned char d_id = frd(&SRAM_BASE[0x0001]);

    SRAM_BASE[FLASH_MAGIC_0] = 0xAA;
    SRAM_BASE[FLASH_MAGIC_1] = 0x55;
    SRAM_BASE[FLASH_MAGIC_0] = 0xF0;
    SRAM_BASE[FLASH_MAGIC_0] = 0xF0;   /* Nintendo lo scrive due volte */
    flashDelayId();

    if (m_id == before_mfr && d_id == before_dev)
        return CHIP_UNKNOWN;

    /* Sempre con il codice esatto, costruttore e dispositivo. Vale
     * soprattutto per Atmel: la scrittura a pagine su un chip che non la
     * capisce non scrive niente di buono. */
    if (m_id == 0xC2 && (d_id == 0x1C || d_id == 0x09))
        return CHIP_MACRONIX;
    if (m_id == 0x32 && d_id == 0x1B)
        return CHIP_PANASONIC;
    if (m_id == 0x62 && d_id == 0x13)
        return CHIP_SANYO;
    if (m_id == 0xBF && d_id == 0xD4)
        return CHIP_SST;
    if (m_id == 0xBF && d_id >= 0xD5 && d_id <= 0xD7)
        return CHIP_SST39;
    if (m_id == 0x1F && d_id == 0x3D)
        return CHIP_ATMEL;

    return CHIP_UNKNOWN;
}

/* Il descrittore si ricorda in una cella in cima alla EWRAM, cosi'
 * l'identificazione - due attese da 20 ms - si paga una volta sola. Se il
 * gioco ci scrive sopra la firma non combacia e si identifica di nuovo. */
#define FLASH_CHIP_CACHE (*(volatile unsigned *) (SCRATCH_BUF_ADDR - 4))
#define FLASH_CHIP_MAGIC (0x464C43U)

static int flash_chip(void)
{
    unsigned cached = FLASH_CHIP_CACHE;
    if ((cached >> 8) == FLASH_CHIP_MAGIC)
        return (int) (cached & 0xFF);
    int c = detect_flash_chip();
    FLASH_CHIP_CACHE = (FLASH_CHIP_MAGIC << 8) | (unsigned) c;
    return c;
}

/* Attesa di fine operazione: si rilegge la cella finche' restituisce il
 * byte atteso. Finche' il chip lavora, il bit 7 e' il complemento del
 * dato, quindi il byte non puo' coincidere; quando coincide l'operazione
 * e' finita e il dato e' gia' quello giusto.
 *
 * Con status_bits (Macronix e Sanyo) e' WaitForFlashWrite_Common di
 * FLASH1M_V103: si esce anche quando il chip alza il bit 5, e se dopo una
 * rilettura il dato non coincide si manda il reset all'indirizzo di
 * sblocco.
 *
 * Senza (tutti gli altri) e' l'attesa di FLASH_V123: conta solo il tempo
 * e non si manda nessun reset. Il bit 5 non si guarda perche' su quei
 * chip non e' detto che sia un bit di stato, e potrebbe valere 1 a
 * operazione ancora in corso. */
static int flashWaitData(volatile unsigned char *tgt, unsigned char expected,
                         unsigned long budget, int status_bits)
{
    volatile unsigned char a;
    for (;;) {
        a = frd(tgt);
        if (a == expected)
            return 1;
        if ((status_bits && (a & 0x20)) || !--budget) {
            if (frd(tgt) == expected)
                return 1;
            if (status_bits)
                flashResetAmd();
            return 0;
        }
    }
}

/* Un comando di cancellazione del settore e la sua attesa, con il wait
 * state e il tetto del chip. */
static int flashEraseOnce(volatile unsigned char *tgt, int chip)
{
    unsigned long budget = FLASH_TIMEOUT_ERASE_40;
    if ((chip & CF_ERASE_MASK) == CF_ERASE_500)
        budget = FLASH_TIMEOUT_ERASE_500;
    if ((chip & CF_ERASE_MASK) == CF_ERASE_2000)
        budget = FLASH_TIMEOUT_ERASE_2000;

    flashSetWriteWait(chip);
    SRAM_BASE[FLASH_MAGIC_0] = 0xAA;
    SRAM_BASE[FLASH_MAGIC_1] = 0x55;
    SRAM_BASE[FLASH_MAGIC_0] = 0x80;
    SRAM_BASE[FLASH_MAGIC_0] = 0xAA;
    SRAM_BASE[FLASH_MAGIC_1] = 0x55;
    *tgt = 0x30;
    int ok = flashWaitData(tgt, 0xFF, budget, chip & CF_STATUS);
    flashSetWaitState();
    return ok;
}

/* Tutti i 4096 byte fisici del settore a 0xFF? E' il controllo che la
 * routine SST di Nintendo esegue dalla RAM dopo ogni cancellazione. */
static int flashSectorBlank(volatile unsigned char *sector)
{
    for (unsigned i = 0; i < 0x1000; ++i)
        if (frd(&sector[i]) != 0xFF)
            return 0;
    return 1;
}

/* flashEraseSector e flashProgramByte restituiscono 1 se l'operazione e'
 * andata a buon fine, 0 se e' fallita. Alla prima operazione fallita il
 * chiamante ferma tutta la scrittura: dopo una cancellazione fallita il
 * settore e' a meta', e su un chip che non risponde proseguire
 * moltiplicherebbe i tetti di attesa per il numero di byte.
 *
 * Non vanno chiamate su un Atmel, che non ha ne' cancellazione ne' program
 * del singolo byte: i chiamanti lo deviano prima. */
static int flashEraseSector(volatile unsigned char *tgt, int chip)
{
    if (!(chip & CF_VERIFY))
    {
        /* Macronix, Sanyo, Panasonic, SST 39xF0x0: si cancella e ci si fida
         * dell'attesa. Cinque tentativi dove c'e' il bit di stato a dire
         * che e' fallita, uno solo altrimenti. */
        int attempts = (chip & CF_STATUS) ? FLASH_ERASE_ATTEMPTS : 1;
        while (attempts--)
            if (flashEraseOnce(tgt, chip))
                return 1;
        return 0;
    }

    /* SST e sconosciuti. Senza bit di stato e con un tetto cosi' corto
     * l'unica prova che la cancellazione sia riuscita e' rileggere il
     * settore, quindi si cancella e si controlla finche' non risulta
     * vuoto. */
    volatile unsigned char *sector =
        (volatile unsigned char *) ((unsigned) tgt & ~0xFFFu);
    unsigned tries = 0;
    while (!flashEraseOnce(tgt, chip) || !flashSectorBlank(sector))
        if (++tries == FLASH_B_ERASE_GIVEUP)
            return 0;

    /* Cancellazioni di margine: il settore risulta vuoto, ma con un tetto
     * cosi' corto le celle potrebbero essere appena oltre la soglia. Come
     * in Nintendo l'esito di queste non decide niente.
     *
     * Una cosa in piu' rispetto a Nintendo: se una di queste scade, si
     * aspetta comunque che il chip finisca, con il tetto lungo. Su un SST
     * non capita mai. Capita su un chip sconosciuto piu' lento dei 40
     * tick, e senza questa attesa i program successivi partirebbero a
     * cancellazione ancora in corso e fallirebbero tutti. */
    for (unsigned n = tries ? FLASH_B_MARGIN_RETRIED : FLASH_B_MARGIN_CLEAN; n; --n)
        if (!flashEraseOnce(tgt, chip))
            (void) flashWaitData(tgt, 0xFF, FLASH_TIMEOUT_ERASE_2000, 0);
    return 1;
}

static int flashProgramByte(volatile unsigned char *tgt, unsigned char data, int chip)
{
    /* ProgramByte: sequenza di program e attesa del dato, un solo
     * tentativo. Se fallisce, la scrittura si ferma. */
    flashSetWriteWait(chip);
    SRAM_BASE[FLASH_MAGIC_0] = 0xAA;
    SRAM_BASE[FLASH_MAGIC_1] = 0x55;
    SRAM_BASE[FLASH_MAGIC_0] = 0xA0;
    *tgt = data;
    int ok = flashWaitData(tgt, data, FLASH_TIMEOUT_PROGRAM, chip & CF_STATUS);
    flashSetWaitState();
    return ok;
}

/* Copia da RAM a RAM: le letture dalla Flash passano tutte da fcopy. Il
 * vecchio conteggio dei byte diversi non lo leggeva nessuno, e costava una
 * lettura in piu' di ciascuno dei due puntatori. */
static void my_memcpy(volatile unsigned char *dst, int dstride, volatile unsigned char *src, int sstride, unsigned size)
{
    while (size)
    {
        *dst = *src;
        dst += dstride;
        src += sstride;
        --size;
    }
}

/* Il puntatore e' volatile: la finestra della cartuccia non e' memoria
 * normale, e le letture non vanno accorpate ne' spostate rispetto alle
 * scritture dei comandi. */
static volatile unsigned char *translate(unsigned idx, int loadfactor_log2)
{
    return (volatile unsigned char *) (0x0E000000 | idx << loadfactor_log2);
}

/* ================================================================
 * Atmel AT29LV512: scrittura a pagine
 * ================================================================
 *
 * Questo chip non ha un comando di cancellazione del settore ne' un
 * program del singolo byte. Si manda lo sblocco con 0xA0 e poi i 128 byte
 * di una pagina uno dopo l'altro; quando il caricamento si ferma il chip
 * cancella la pagina e la riscrive da se'. I byte non caricati
 * resterebbero a 0xFF, quindi la pagina va sempre mandata intera.
 *
 * Come nelle routine Atmel di FLASH_V123:
 *  - gli interrupt sono spenti durante il caricamento: il chip considera
 *    finita la pagina se passano piu' di 150 us fra un byte e l'altro, e
 *    un interrupt del gioco in mezzo la farebbe partire a meta';
 *  - si attende sull'ULTIMO byte caricato, che durante la scrittura
 *    restituisce il bit 7 invertito;
 *  - tre tentativi per pagina.
 * In piu' rispetto a Nintendo, a scrittura finita la pagina viene
 * riletta e confrontata per intero. */
static int atmelWritePage(volatile unsigned char *page, const unsigned char *buf)
{
    for (int attempt = 0; attempt < ATMEL_PAGE_ATTEMPTS; ++attempt)
    {
        unsigned short ime = REG_IME;
        REG_IME = 0;
        SRAM_BASE[FLASH_MAGIC_0] = 0xAA;
        SRAM_BASE[FLASH_MAGIC_1] = 0x55;
        SRAM_BASE[FLASH_MAGIC_0] = 0xA0;
        for (unsigned i = 0; i < ATMEL_PAGE; ++i)
            page[i] = buf[i];
        REG_IME = ime;

        if (flashWaitData(&page[ATMEL_PAGE - 1], buf[ATMEL_PAGE - 1], FLASH_TIMEOUT_PAGE, 0)
            && !fverify((volatile unsigned char *) buf, page, ATMEL_PAGE, 1))
            return 1;
    }
    return 0;
}

/* Scrive size byte logici a partire da idx, con il passo 1 << lf, una
 * pagina fisica per volta: la si legge, si sostituiscono i byte che
 * cambiano e, solo se qualcosa e' cambiato davvero, la si riscrive.
 *
 * Non c'e' decisione sulla cancellazione e non serve il buffer da 2 KB:
 * bastano i 128 byte della pagina, sullo stack. Restituisce 1 se tutte le
 * pagine sono andate a buon fine.
 *
 * noinline di proposito: se il compilatore la fondesse nei chiamanti, quei
 * 128 byte finirebbero nel loro stack anche sugli altri chip, che e' lo
 * stack del gioco. */
__attribute__((noinline))
static int atmel_write(const unsigned char *src, unsigned idx, unsigned size, int loadfactor_log2)
{
    unsigned char buf[ATMEL_PAGE];
    unsigned step = 1u << loadfactor_log2;

    while (size)
    {
        unsigned phys = (idx << loadfactor_log2) & 0xFFFFu;
        unsigned off = phys & (ATMEL_PAGE - 1);
        volatile unsigned char *page =
            (volatile unsigned char *) (0x0E000000 | (phys - off));
        int changed = 0;

        fcopy(buf, page, ATMEL_PAGE, 1);
        while (off < ATMEL_PAGE && size)
        {
            if (buf[off] != *src)
            {
                buf[off] = *src;
                changed = 1;
            }
            ++src;
            ++idx;
            --size;
            off += step;
        }
        if (changed && !atmelWritePage(page, buf))
            return 0;
    }
    return 1;
}

/* EEPROM su Atmel: niente journal.
 *
 * Il journal vive di program in spazio vergine, senza cancellare, ed e'
 * proprio cio' che questo chip non sa fare: ogni scrittura riscrive la
 * pagina intera, quindi un record in coda costerebbe quanto riscrivere il
 * blocco al suo posto, e una interruzione rovinerebbe anche i record
 * vicini. Qui i blocchi si scrivono direttamente, e non serve altro: la
 * pagina da 128 byte e' gia' un'unita' di cancellazione piccola.
 *
 * Il passo e' sempre 3, per entrambe le misure di EEPROM: un blocco da 8
 * byte occupa 64 byte fisici e sta dentro una pagina sola, quindi una
 * scrittura di blocco e' una scrittura di pagina, e ogni pagina ospita
 * due blocchi soltanto. Con il passo 7 delle EEPROM da 4 Kbit un blocco
 * si spargerebbe su otto pagine. Non c'e' un formato precedente da
 * rispettare: prima di questa versione il payload su Atmel non scriveva. */
#define ATMEL_EEPROM_LF     3
#define ATMEL_EEPROM_BLOCKS 1024u

static int atmel_eeprom_write(unsigned addr, const unsigned char *src)
{
    if (addr >= ATMEL_EEPROM_BLOCKS)
        return 0;
    return atmel_write(src, addr << 3, 8, ATMEL_EEPROM_LF);
}

static int atmel_eeprom_read(unsigned addr, unsigned char *dst)
{
    if (addr >= ATMEL_EEPROM_BLOCKS)
        return 0;
    fcopy(dst, translate(addr << 3, ATMEL_EEPROM_LF), 8, 1u << ATMEL_EEPROM_LF);
    return 1;
}

static int atmel_eeprom_verify(unsigned addr, unsigned char *src)
{
    if (addr >= ATMEL_EEPROM_BLOCKS)
        return 0;
    return !fverify(src, translate(addr << 3, ATMEL_EEPROM_LF), 8, 1u << ATMEL_EEPROM_LF);
}

void write_core_patched(unsigned char *src, unsigned idx, unsigned size, int loadfactor_log2)
{
    volatile unsigned short ramcode[RAMCODE_HALFWORDS];
    flashRamSetup(ramcode);
    flashSetWaitState();
    int chip = flash_chip();
    if (chip & CF_ATMEL)
    {
        /* Percorso a pagine, del tutto separato da quello qui sotto. */
        (void) atmel_write(src, idx, size, loadfactor_log2);
        return;
    }
    /* Dimensione in byte dell'unita' di cancellazione del chip. E' l'unica
     * assunzione che, se sbagliata, provoca perdita di dati invece che
     * lentezza: cancelleremmo piu' di quanto poi ripristiniamo.
     *
     * Tutti i chip che passano di qui lavorano a settori da 4 KB: e' la
     * geometria di tutti i chip che riconosciamo, Atmel escluso, ed e'
     * quella che la libreria Nintendo assume anche per i chip sconosciuti.
     *
     * loadfactor_log2 non vale mai 0 - da qui passa solo la SRAM, con 1 -
     * quindi sector_usage vale al massimo 2048, cioe' SCRATCH_BUF_SIZE: il
     * buffer copre sempre l'intero settore da 4 KB. Con 0 servirebbe il
     * doppio e si sborderebbe oltre la cima della EWRAM.
     *
     * Con segno, perche' viene confrontato con len e con prefix, che con
     * segno lo sono: un confronto misto fra int e unsigned promuove l'int
     * a unsigned, e un valore negativo diventerebbe enorme. */
    int sector_usage = 0x1000 >> loadfactor_log2;
    unsigned char *sector_buf = (unsigned char *) SCRATCH_BUF_ADDR;

    /* I dati che il gioco ci passa possono trovarsi dentro il buffer. Sui
     * 2 KB in cima alla EWRAM non e' successo in nessuno dei giochi
     * provati, e finche' e' cosi' questo controllo e' sempre vero.
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
     * insistere significa solo moltiplicare i tetti di attesa. */
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
        /* Il gioco scrive la SRAM a pezzi di qualunque misura (FE6 la
         * azzera a blocchi da 64 byte), mentre ProgramFlashSector di
         * Nintendo e' chiamata una volta per settore intero. Cancellare
         * il settore a ogni chiamata vorrebbe dire centinaia di
         * cancellazioni per un solo salvataggio. Si cancella quindi solo
         * quando serve davvero, cioe' quando un bit deve tornare da 0 a 1;
         * altrimenti si programmano direttamente i byte cambiati. */
        int need_erase = 0;
        for (int i = 0; i < len; ++i)
        {
            unsigned char oldb = frd(&sector[(prefix + i) << loadfactor_log2]);
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
            /* Come ProgramFlashSector - cancellazione del settore e
             * program dei suoi byte - con una differenza: i byte che devono
             * restare 0xFF non si programmano, si rileggono soltanto.
             *
             * Il program di 0xFF non cambia la cella; in Nintendo serve di
             * fatto a controllare che la cancellazione l'abbia raggiunta,
             * perche' l'attesa confronta il byte riletto con quello atteso.
             * La rilettura da' lo stesso controllo con una lettura al posto
             * di quattro scritture piu' l'attesa: se la cella non e' 0xFF
             * la cancellazione non e' riuscita e ci si ferma, come avrebbe
             * fatto il program. */
            fcopy(sector_buf, sector, sector_usage, 1 << loadfactor_log2);
            my_memcpy(sector_buf + prefix, 1, src, 1, len);
            if (!flashEraseSector(sector, chip))
                break;
            for (int i = 0; i < sector_usage; ++i)
            {
                volatile unsigned char *cell = &sector[i << loadfactor_log2];
                int ok = (sector_buf[i] == 0xFF)
                       ? (frd(cell) == 0xFF)
                       : flashProgramByte(cell, sector_buf[i], chip);
                if (!ok)
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
            /* I dati di origine stanno dentro il buffer di lavoro:
             * cancellare senza poter ricostruire il settore perderebbe il
             * resto del blocco. Non si scrive niente; il vecchio
             * salvataggio resta intero e la verifica del gioco segnala il
             * fallimento. */
        }
        else
        {
            for (int i = 0; i < len; ++i)
            {
                unsigned char oldb = frd(&sector[(prefix + i) << loadfactor_log2]);
                unsigned char newb = src[i];
                if (oldb != newb
                    && !flashProgramByte(&sector[(prefix + i) << loadfactor_log2], newb, chip))
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
}

void read_core_patched(unsigned char *dst, unsigned idx, unsigned size, int loadfactor_log2)
{
    volatile unsigned short ramcode[RAMCODE_HALFWORDS];
    flashRamSetup(ramcode);
    flashSetWaitState();
    fcopy(dst, translate(idx, loadfactor_log2), size, 1 << loadfactor_log2);
}

int verify_core_patched(unsigned char *src, unsigned idx, unsigned size, int loadfactor_log2)
{
    volatile unsigned short ramcode[RAMCODE_HALFWORDS];
    flashRamSetup(ramcode);
    flashSetWaitState();
    /* Il confronto gira in RAM come VerifyFlashSector_Core; restituisce
     * quanti byte mancavano al primo diverso, 0 se coincidono tutti. */
    unsigned left = fverify(src, translate(idx, loadfactor_log2), size, 1 << loadfactor_log2);
    if (left)
        return (int) (idx + (size - left));
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
 *   0x0203F7FC .. 0x0203F7FF   cache del descrittore del chip
 *   0x0203F7F8 .. 0x0203F7FB   indirizzo delle routine di lettura in RAM
 *   0x0203F7F0 .. 0x0203F7F7   controllo del journal, 8 byte
 *
 * Su un Atmel il journal non si usa (vedi atmel_eeprom_write) e di questa
 * mappa restano solo le due celle in alto.
 *
 * In tutto 2064 byte. La migrazione dal formato precedente ha bisogno di
 * un appoggio temporaneo e usa l'area dell'indice, che in quel momento
 * non e' ancora valida: non serve altra memoria. */

#define EJ_CTRL_ADDR      (SCRATCH_BUF_ADDR - 16)
#define EJ_INDEX_ADDR     (SCRATCH_BUF_ADDR)
#define EJ_INDEX_LEN      (2048)

struct ej_ctrl;

/* Il journal indirizza la finestra in modo piatto, senza interlacciamento:
 * e' proprio lo spazio liberato dall'interlacciamento a ospitarlo. */
static unsigned char ej_rd(unsigned off)
{
    return frd((volatile unsigned char *) (0x0E000000 | (off & 0xFFFF)));
}

static int ej_pgm(unsigned off, const unsigned char *s, unsigned n)
{
    int chip = flash_chip();
    for (unsigned i = 0; i < n; ++i)
    {
        volatile unsigned char *t =
            (volatile unsigned char *) (0x0E000000 | ((off + i) & 0xFFFF));
        if (frd(t) == s[i])
            continue;                      /* gia' cosi': niente da fare */
        if (!flashProgramByte(t, s[i], chip))
            return 0;
    }
    return 1;
}

static int ej_erase(unsigned off)
{
    return flashEraseSector(
        (volatile unsigned char *) (0x0E000000 | (off & 0xFFFF)),
        flash_chip());
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
    *len = EJ_INDEX_LEN;
    return (unsigned char *) EJ_INDEX_ADDR;
}

#include "ejournal.c"

/* Il fattore di interlacciamento non serve piu' a indirizzare: serve solo
 * a leggere un eventuale salvataggio nel formato precedente, la prima
 * volta, per convertirlo. */
unsigned write_eeprom_patched(unsigned short addr, unsigned char *src)
{
    volatile unsigned short ramcode[RAMCODE_HALFWORDS];
    flashRamSetup(ramcode);
    flashSetWaitState();
    struct eeprom_meta *eeprom_meta = get_eeprom_meta();
    /* Il limite che controllavano le funzioni originali, con lo stesso
     * confronto: nelle firme c'e' un cmp con cfg->addrs seguito da bcc.
     * Se i metadati mancano il limite non e' noto e non si controlla. */
    if (eeprom_meta && addr >= eeprom_meta->addrs)
        return 1;
    if (flash_chip() & CF_ATMEL)
        return atmel_eeprom_write(addr, src) ? 0 : 1;
    return ej_write_block(addr, src, eeprom_loadfactor(eeprom_meta)) ? 0 : 1;
}

unsigned read_eeprom_patched(unsigned short addr, unsigned char *dst)
{
    volatile unsigned short ramcode[RAMCODE_HALFWORDS];
    flashRamSetup(ramcode);
    flashSetWaitState();
    if (flash_chip() & CF_ATMEL)
        return atmel_eeprom_read(addr, dst) ? 0 : 1;
    return ej_read_block(addr, dst, eeprom_loadfactor(get_eeprom_meta())) ? 0 : 1;
}

unsigned verify_eeprom_patched(unsigned short addr, unsigned char *src)
{
    volatile unsigned short ramcode[RAMCODE_HALFWORDS];
    flashRamSetup(ramcode);
    flashSetWaitState();
    if (flash_chip() & CF_ATMEL)
        return atmel_eeprom_verify(addr, src) ? 0 : 1;
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
    volatile unsigned short ramcode[RAMCODE_HALFWORDS];
    flashRamSetup(ramcode);
    flashSetWaitState();
    if (addr > EEPROM_FIXED6_MAX_ADDR)
        return 0;
    if (flash_chip() & CF_ATMEL)
        return atmel_eeprom_write(addr, src) ? 0 : 1;
    return ej_write_block(addr, src, eeprom_fixed6_loadfactor()) ? 0 : 1;
}

unsigned read_eeprom_fixed6_patched(unsigned short addr, unsigned char *dst)
{
    volatile unsigned short ramcode[RAMCODE_HALFWORDS];
    flashRamSetup(ramcode);
    flashSetWaitState();
    if (flash_chip() & CF_ATMEL)
        return atmel_eeprom_read(addr, dst) ? 0 : 1;
    return ej_read_block(addr, dst, eeprom_fixed6_loadfactor()) ? 0 : 1;
}

unsigned verify_eeprom_fixed6_patched(unsigned short addr, unsigned char *src)
{
    volatile unsigned short ramcode[RAMCODE_HALFWORDS];
    flashRamSetup(ramcode);
    flashSetWaitState();
    if (flash_chip() & CF_ATMEL)
        return atmel_eeprom_verify(addr, src) ? 0 : 0x8000;
    unsigned char cur[8];
    if (!ej_read_block(addr, cur, eeprom_fixed6_loadfactor()))
        return 0x8000;
    for (int i = 0; i < 8; ++i)
        if (cur[i] != src[i])
            return 0x8000;
    return 0;
}
