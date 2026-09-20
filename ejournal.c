/*
 * ejournal.c - strato di memorizzazione a journal per le EEPROM emulate
 *              su Flash.
 *
 * PERCHE'
 *
 * Il percorso EEPROM scriveva un blocco da 8 byte per volta dentro un
 * settore, e siccome programmare puo' solo portare bit da 1 a 0, quasi
 * ogni blocco modificato costava una CANCELLAZIONE dell'intero settore
 * piu' la sua riscrittura. Circa una cancellazione per blocco cambiato:
 * un salvataggio che ne tocca un centinaio consuma un centinaio di cicli,
 * e con una resistenza tipica di 100.000 cicli si arriva a consumare un
 * settore nell'ordine del migliaio di salvataggi.
 *
 * Qui le scritture diventano APPEND in spazio vergine: nessuna
 * cancellazione. Si cancella solo quando il journal si riempie, e in quel
 * momento si riscrive un'immagine compatta. Tre ordini di grandezza in
 * meno di usura, e in piu' ogni scrittura e' atomica: un record
 * interrotto a meta' viene ignorato e il valore precedente sopravvive,
 * mentre oggi una interruzione fra cancellazione e riscrittura porta via
 * l'intero settore.
 *
 * DOVE STA LA VERITA'
 *
 * Sempre nella Flash. Quello che teniamo in EWRAM e' solo un indice per
 * non riscandire il journal a ogni lettura: se il gioco ce lo sovrascrive
 * o lo troviamo invalido, si ricostruisce leggendo. Nessun dato esiste
 * unicamente in RAM, tranne nelle due finestre esplicitamente marcate
 * dentro la migrazione e la compattazione su chip a blocco unico.
 *
 * FORMATO SUI 64 KB DELLA FINESTRA
 *
 *   0x0000..0x2FFF  slot base A   intestazione 16 B, poi 8192 B di dati
 *   0x3000..0x5FFF  slot base B   idem
 *   0x6000..0xFFFF  journal       4096 record da 10 B
 *
 * Lo slot valido e' quello con il numero di generazione piu' alto. I due
 * slot servono alla compattazione: si riempie quello inattivo e solo
 * quando e' completo si dichiara valido, cosi' esiste sempre una copia
 * buona. Su un chip Intel, dove l'unita' di cancellazione e' l'intero
 * blocco da 64 KB, i due slot non possono proteggere da un'interruzione -
 * la cancellazione li porta via entrambi - e la compattazione ha una
 * finestra di vulnerabilita' di un paio di secondi, una volta ogni
 * qualche migliaio di scritture. Il formato pero' resta identico, cosi'
 * un salvataggio e' leggibile su entrambe le famiglie.
 *
 * Intestazione dello slot (16 byte):
 *   +0  numero di generazione, 4 byte little endian
 *   +4  otto byte riservati, lasciati a 0xFF
 *   +12 firma "GBJ1", 4 byte, programmata PER ULTIMA
 *
 * La firma per ultima e' cio' che rende l'intestazione atomica: se la
 * corrente va via mentre si scrive, la firma non combacia e lo slot viene
 * ignorato.
 *
 * Record del journal (10 byte):
 *   +0  otto byte di dati
 *   +8  indice del blocco, 2 byte little endian, programmato PER ULTIMO
 *
 * Stessa ragione: un record interrotto ha indice 0xFFFF e non porta
 * nessun dato valido. La scrittura si perde, ma niente si corrompe.
 *
 * Quel record pero' NON e' spazio libero, ed e' l'errore da non fare: i
 * suoi byte di dati sono gia' programmati, quindi non si puo' riusarlo -
 * programmare non rialza i bit - e non si puo' nemmeno prenderlo per la
 * fine del journal. Spazio libero vuol dire tutti e dieci i byte a 0xFF,
 * niente di meno; chi scorre il journal salta i record a meta' e va
 * avanti. Vedi ej_rec_blank.
 *
 * QUESTO FILE NON E' AUTONOMO. Chi lo include deve aver definito:
 *
 *   static unsigned char   ej_rd(unsigned off);
 *   static int             ej_pgm(unsigned off, const unsigned char *s, unsigned n);
 *   static int             ej_erase(unsigned off);
 *   static int             ej_single_block(void);
 *   static struct ej_ctrl *ej_ctrl(void);
 *   static unsigned short *ej_index(void);
 *   static unsigned char  *ej_tmp(unsigned *len);
 *
 * Cosi' lo stesso codice gira sul banco di prova con una Flash simulata e
 * dentro il payload sull'hardware vero: quello che viene verificato e'
 * esattamente quello che viene spedito.
 */

#define EJ_BLK          8u                    /* byte per blocco EEPROM   */
#define EJ_BLOCKS_MAX   1024u                 /* EEPROM da 64 Kbit        */

#define EJ_SLOT_A       0x0000u
#define EJ_SLOT_B       0x3000u
#define EJ_SLOT_SPAN    0x3000u               /* tre settori da 4 KB      */
#define EJ_HDR_LEN      16u
#define EJ_HDR_SEQ      0u
#define EJ_HDR_MAGIC    12u

#define EJ_JOURNAL      0x6000u
#define EJ_WINDOW       0x10000u
#define EJ_REC          10u
#define EJ_RECS         ((EJ_WINDOW - EJ_JOURNAL) / EJ_REC)   /* 4096 */

#define EJ_NONE         0xFFFFu               /* record mai scritto        */

/* "Questo blocco sta nella base", come voce dell'indice in EWRAM.
 *
 * Non vale 0xFFFF di proposito. L'indice e' esposto al gioco, e i due modi
 * in cui una memoria viene rovinata sono l'azzeramento a 0x00 e il
 * riempimento a 0xFF: se "sta nella base" si scrivesse 0xFFFF, un indice
 * spazzato a 0xFF sarebbe indistinguibile da un indice legittimo che dice
 * "sono tutti nella base", e ogni lettura ricadrebbe sulla base. Con la
 * base ancora vuota - cioe' finche' non c'e' stata una compattazione -
 * quello non e' un valore vecchio ma coerente: e' un salvataggio che
 * sembra cancellato. E la compattazione successiva lo renderebbe vero.
 *
 * Spostando il valore di un solo passo, entrambi i motivi classici di
 * corruzione diventano riconoscibili e fanno ricostruire dalla Flash. */
#define EJ_INBASE       0xFFFEu
#define EJ_SECTOR       0x1000u

struct ej_ctrl
{
    unsigned magic;        /* EJ_CTRL_MAGIC quando indice e testa valgono */
    unsigned short head;   /* primo record libero                         */
    unsigned char  slot;   /* 0 = A, 1 = B                                */
    unsigned char  pad;
};

#define EJ_CTRL_MAGIC   0x314A424Au           /* "JBJ1"                   */

/* La firma e' legata al contenuto del blocco di controllo, non costante.
 *
 * Indice e blocco di controllo stanno nella stessa EWRAM, esposti allo
 * stesso rischio: il gioco puo' scriverci sopra. Dell'indice adesso si
 * diffida voce per voce, del blocco di controllo ci si fidava soltanto
 * perche' la firma era al suo posto - ma slot e testa stanno negli stessi
 * otto byte, e bastava che cambiasse quel singolo byte di slot perche' le
 * letture arrivassero dalla base sbagliata e, peggio, perche' la
 * compattazione cancellasse la base viva scambiandola per quella libera.
 *
 * Facendo dipendere la firma da slot e testa, qualunque alterazione che
 * non passi di qui la fa tornare sbagliata, e si ricostruisce dalla Flash.
 * Non costa nessuna lettura in piu'. Dimenticare di risigillare dopo una
 * modifica non e' pericoloso: si ricostruisce una volta di troppo, il che
 * e' esattamente il verso giusto in cui sbagliare. */
static unsigned ej_seal(struct ej_ctrl *c)
{
    return EJ_CTRL_MAGIC ^ ((unsigned) c->head << 8) ^ ((unsigned) c->slot << 28);
}

static void ej_ctrl_commit(struct ej_ctrl *c) { c->magic = ej_seal(c); }
static int  ej_ctrl_valid(struct ej_ctrl *c)  { return c->magic == ej_seal(c); }

/* La firma si costruisce in un array locale invece di stare in una
 * costante. Il payload viene linkato con uno script che tiene solo
 * .text: una costante finirebbe in .rodata, che viene scartata, e il
 * riferimento resterebbe appeso. Cosi' i quattro byte diventano immediati
 * dentro il codice. */
static void ej_magic(unsigned char *b)
{
    b[0] = 'G'; b[1] = 'B'; b[2] = 'J'; b[3] = '1';
}

/* ---------------------------------------------------------------- */
/* utilita' di basso livello                                         */
/* ---------------------------------------------------------------- */

/* Azzerare l'indice con un ciclo semplice fa riconoscere a GCC il motivo
 * e lo sostituisce con una chiamata a memset, che qui non esiste: il
 * payload e' linkato senza libreria standard. Il puntatore volatile
 * impedisce quella trasformazione. */
static void ej_clear_index(void)
{
    volatile unsigned short *ix = ej_index();
    for (unsigned b = 0; b < EJ_BLOCKS_MAX; ++b)
        ix[b] = EJ_INBASE;
}

static unsigned ej_slot_base(int slot)
{
    return slot ? EJ_SLOT_B : EJ_SLOT_A;
}

static unsigned ej_rec_off(unsigned n)
{
    return EJ_JOURNAL + n * EJ_REC;
}

/* Intestazione valida? Restituisce 1 e riempie seq. */
static int ej_hdr_read(int slot, unsigned *seq)
{
    unsigned base = ej_slot_base(slot);
    unsigned char m[4];
    ej_magic(m);
    for (unsigned i = 0; i < 4; ++i)
        if (ej_rd(base + EJ_HDR_MAGIC + i) != m[i])
            return 0;
    unsigned v = 0;
    for (unsigned i = 0; i < 4; ++i)
        v |= (unsigned) ej_rd(base + EJ_HDR_SEQ + i) << (8 * i);
    *seq = v;
    return 1;
}

static int ej_hdr_write(int slot, unsigned seq)
{
    unsigned base = ej_slot_base(slot);
    unsigned char b[4];
    for (unsigned i = 0; i < 4; ++i)
        b[i] = (unsigned char) (seq >> (8 * i));
    if (!ej_pgm(base + EJ_HDR_SEQ, b, 4))
        return 0;
    /* la firma per ultima: e' lei a rendere valido lo slot */
    ej_magic(b);
    return ej_pgm(base + EJ_HDR_MAGIC, b, 4);
}

static unsigned ej_rec_index(unsigned n)
{
    unsigned off = ej_rec_off(n) + EJ_BLK;
    return (unsigned) ej_rd(off) | ((unsigned) ej_rd(off + 1) << 8);
}

/* Record davvero vergine, cioe' tutti e dieci i byte ancora a 0xFF.
 *
 * Non basta guardare l'indice. Un record si scrive in due tempi - prima
 * gli otto byte di dati, poi l'indice - e se la corrente va via in mezzo
 * restano byte gia' programmati con l'indice ancora 0xFFFF. La
 * ricostruzione si ferma li', perche' per lei indice 0xFFFF significa
 * "fine del journal", e propone quel record come primo libero.
 *
 * Riusarlo non e' possibile: programmare porta i bit solo da 1 a 0, e i
 * byte rimasti non tornano a 0xFF senza una cancellazione. La
 * programmazione fallisce, la testa non avanza, e da quel momento ogni
 * scrittura futura fallisce allo stesso punto: il gioco non salva piu',
 * definitivamente. Prima di usare un record bisogna quindi verificarlo,
 * e saltarlo se e' sporco. */
static int ej_rec_blank(unsigned n)
{
    unsigned off = ej_rec_off(n);
    for (unsigned i = 0; i < EJ_REC; ++i)
        if (ej_rd(off + i) != 0xFF)
            return 0;
    return 1;
}

/* ---------------------------------------------------------------- */
/* cancellazione                                                      */
/* ---------------------------------------------------------------- */

/* Cancella l'intervallo [from, to), un settore per volta.
 *
 * DA CHIAMARE SOLO quando ej_single_block() e' falso. Su un chip a
 * blocco unico non esiste il concetto di intervallo: qualunque
 * cancellazione porta via tutti i 64 KB, quindi i percorsi che devono
 * funzionare anche li' cancellano una volta sola, all'inizio, e non
 * chiamano mai questa. Tenere separate le due cose evita di cancellare
 * per sbaglio una base appena scritta. */
static int ej_erase_range(unsigned from, unsigned to)
{
    for (unsigned o = from; o < to; o += EJ_SECTOR)
        if (!ej_erase(o))
            return 0;
    return 1;
}

/* ---------------------------------------------------------------- */
/* lettura di un blocco dallo stato corrente                          */
/* ---------------------------------------------------------------- */

static void ej_fetch(unsigned blk, unsigned char *out)
{
    struct ej_ctrl *c = ej_ctrl();
    unsigned short *ix = ej_index();
    unsigned src;

    if (ix[blk] == EJ_INBASE)
        src = ej_slot_base(c->slot) + EJ_HDR_LEN + blk * EJ_BLK;
    else
        src = ej_rec_off(ix[blk]);

    for (unsigned i = 0; i < EJ_BLK; ++i)
        out[i] = ej_rd(src + i);
}

/* ---------------------------------------------------------------- */
/* ricostruzione dello stato leggendo la Flash                        */
/* ---------------------------------------------------------------- */

static int ej_rebuild(void)
{
    struct ej_ctrl *c = ej_ctrl();
    unsigned short *ix = ej_index();
    unsigned seq_a = 0, seq_b = 0;
    int ok_a = ej_hdr_read(0, &seq_a);
    int ok_b = ej_hdr_read(1, &seq_b);

    if (!ok_a && !ok_b)
        return 0;                       /* nessuna base: tocca al chiamante */

    if (ok_a && ok_b)
        c->slot = (seq_b > seq_a) ? 1 : 0;
    else
        c->slot = ok_b ? 1 : 0;

    ej_clear_index();

    /* Si scorre TUTTO il journal, senza uscite anticipate.
     *
     *
     * La differenza e' tutta nei record lasciati a meta'. Un record si
     * scrive in due tempi, prima i dati e poi l'indice, quindi una
     * interruzione in mezzo ne lascia uno con i dati gia' programmati e
     * l'indice ancora 0xFFFF. Fermarsi li' - come faceva la versione
     * precedente - vuol dire dichiarare finito il journal su un buco: la
     * scrittura successiva salta il record sporco e si sistema piu'
     * avanti, ma alla ricostruzione dopo lo spegnimento quel record e
     * tutti quelli che lo seguono tornano invisibili. Il gioco salva, la
     * verifica gli da' ragione, e al riavvio il salvataggio non c'e'.
     * Ogni volta, per sempre.
     *
     * Un buco si riconosce perche' ha dei byte gia' programmati: si salta
     * senza indicizzarlo - non porta un dato valido - ma si prosegue.
     *
     * Arrivare in fondo invece di fermarsi al primo vuoto serve anche a un
     * secondo caso. Dopo una compattazione la nuova base contiene gia'
     * tutti i record, e il journal viene cancellato settore per settore
     * dal basso verso l'alto: se quella cancellazione si interrompe, i
     * record che sopravvivono sono i piu' RECENTI. Rigiocarli tutti
     * riscrive gli stessi valori che la base ha gia' - inoffensivo - ma
     * fermarsi al primo vuoto ne rigiocherebbe solo un tratto iniziale,
     * cioe' i piu' vecchi, riportando indietro i blocchi che avevano
     * ricevuto un aggiornamento dopo. Scorrendo tutto, per ogni blocco
     * vince il record piu' alto sopravvissuto, che e' esattamente quello
     * da cui la base e' stata costruita.
     *
     * Resta fuori un caso, e va detto: se l'ultimo record di un blocco si
     * trovava proprio nel settore sorpreso a meta' cancellazione, quel
     * blocco puo' tornare a un valore precedente, o - se i suoi byte di
     * dati sono stati intaccati mentre l'indice si legge ancora - portare
     * dati rovinati. E' il settore in corso di cancellazione, non tutto il
     * journal: il danno e' limitato ai blocchi il cui aggiornamento piu'
     * recente cade li' dentro, cioe' fra i record piu' vecchi. Non e'
     * aggirabile - una cancellazione interrotta lascia il settore in uno
     * stato che nessuna lettura puo' interpretare - e va confrontato con
     * cio' che succedeva prima del journal, dove una interruzione durante
     * un salvataggio qualsiasi portava via un settore intero da 4 KB.
     *
     * La testa e' l'ultimo record occupato piu' uno, buchi compresi: cosi'
     * la ricostruzione e la scrittura considerano libere le stesse
     * posizioni.
     *
     * Il prezzo e' scorrere sempre i 4096 record invece di fermarsi:
     * qualche decina di migliaia di letture, una ventina di millisecondi,
     * una volta per accensione e una per compattazione. Accanto agli 8192
     * byte che una compattazione programma non si misura. */
    unsigned used = 0;
    for (unsigned n = 0; n < EJ_RECS; ++n)
    {
        unsigned bi = ej_rec_index(n);
        if (bi == EJ_NONE)
        {
            /* Nessun indice: o il journal finisce qui, o e' un record
             * lasciato a meta'. Si distinguono solo guardando i dati. */
            if (!ej_rec_blank(n))
                used = n + 1;           /* buco: occupato, ma senza dato */
            continue;
        }
        used = n + 1;
        if (bi < EJ_BLOCKS_MAX)
            ix[bi] = (unsigned short) n; /* l'ultimo vince */
    }
    c->head = (unsigned short) used;
    ej_ctrl_commit(c);
    return 1;
}

/* ---------------------------------------------------------------- */
/* compattazione                                                      */
/* ---------------------------------------------------------------- */

static int ej_compact(void)
{
    struct ej_ctrl *c = ej_ctrl();

    /* Si riparte sempre dalla Flash. La compattazione e' l'unico momento
     * in cui lo stato in EWRAM smette di essere una copia di comodo e
     * diventa la sorgente di quello che verra' scritto: il ramo a due slot
     * qui sotto costruisce la nuova base con ej_fetch, cioe' consultando
     * l'indice. Se il gioco quell'indice l'ha azzerato, ogni voce vale
     * 0xFFFF, ogni lettura ricade sulla base vecchia, e la compattazione
     * incide nella Flash i valori vecchi al posto di quelli buoni: la
     * perdita da temporanea diventa definitiva.
     *
     * La verifica per singola voce non basta a coprirlo, perche' una voce
     * azzerata e' indistinguibile da una voce che dice legittimamente
     * "questo blocco sta nella base". Rileggere il journal una volta,
     * prima di cominciare, costa qualche migliaio di letture - trascurabile
     * accanto agli 8192 byte che stiamo per programmare - e rimette
     * d'accordo indice, testa e slot con quello che c'e' scritto davvero.
     * Sistema anche lo slot, che altrimenti sarebbe l'ultimo byte di cui
     * ci si fida senza controllarlo, e con lo slot sbagliato si
     * cancellerebbe la base viva. */
    if (!ej_rebuild())
        return 0;

    unsigned seq = 0;
    (void) ej_hdr_read(c->slot, &seq);

    if (ej_single_block())
    {
        /* Unita' di cancellazione unica: non esiste un posto dove
         * costruire la nuova base senza distruggere la vecchia. Si legge
         * tutto in RAM, si cancella e si riscrive.
         *
         * FINESTRA DI VULNERABILITA': da qui alla scrittura
         * dell'intestazione i dati esistono solo in RAM. E' il limite del
         * blocco da 64 KB, non aggirabile senza un secondo blocco
         * indirizzabile, e capita una volta ogni EJ_RECS scritture. */
        unsigned tlen = 0;
        unsigned char *tmp = ej_tmp(&tlen);
        if (tlen < EJ_BLOCKS_MAX * EJ_BLK)
            return 0;

        /* L'immagine si costruisce leggendo la Flash, non consultando
         * l'indice, e tutto cio' che serve viene copiato in variabili
         * locali prima di toccare il buffer. Cosi' il modulo resta
         * corretto qualunque sia la posizione che il chiamante ha dato al
         * buffer temporaneo, anche se ricoprisse indice o controllo. */
        unsigned act = ej_slot_base(c->slot) + EJ_HDR_LEN;
        unsigned nrec = c->head;
        for (unsigned i = 0; i < EJ_BLOCKS_MAX * EJ_BLK; ++i)
            tmp[i] = ej_rd(act + i);
        for (unsigned n = 0; n < nrec; ++n)
        {
            unsigned bi = ej_rec_index(n);
            if (bi >= EJ_BLOCKS_MAX)
                continue;
            unsigned r = ej_rec_off(n);
            for (unsigned i = 0; i < EJ_BLK; ++i)
                tmp[bi * EJ_BLK + i] = ej_rd(r + i);
        }
        if (!ej_erase(0))
            return 0;
        for (unsigned b = 0; b < EJ_BLOCKS_MAX; ++b)
        {
            unsigned char *s = tmp + b * EJ_BLK;
            unsigned d = EJ_SLOT_A + EJ_HDR_LEN + b * EJ_BLK;
            for (unsigned i = 0; i < EJ_BLK; ++i)
                if (s[i] != 0xFF && !ej_pgm(d + i, s + i, 1))
                    return 0;
        }
        if (!ej_hdr_write(0, seq + 1))
            return 0;
        c->slot = 0;
    }
    else
    {
        /* Due slot: si riempie quello inattivo e lo si dichiara valido
         * solo alla fine. Fino a quel momento la base vecchia e il
         * journal restano intatti, quindi una interruzione in qualsiasi
         * punto lascia lo stato precedente perfettamente leggibile. */
        int dst = c->slot ? 0 : 1;
        unsigned dbase = ej_slot_base(dst);
        if (!ej_erase_range(dbase, dbase + EJ_SLOT_SPAN))
            return 0;
        for (unsigned b = 0; b < EJ_BLOCKS_MAX; ++b)
        {
            unsigned char v[EJ_BLK];
            ej_fetch(b, v);
            unsigned d = dbase + EJ_HDR_LEN + b * EJ_BLK;
            for (unsigned i = 0; i < EJ_BLK; ++i)
                if (v[i] != 0xFF && !ej_pgm(d + i, v + i, 1))
                    return 0;
        }
        if (!ej_hdr_write(dst, seq + 1))
            return 0;
        c->slot = (unsigned char) dst;

        /* Da qui la nuova base e' quella buona. Se la corrente manca
         * adesso, al riavvio si sceglie lo slot con generazione piu'
         * alta e si rigioca un journal i cui record sono gia' tutti
         * incorporati: stessi valori, nessun danno. */
        if (!ej_erase_range(EJ_JOURNAL, EJ_WINDOW))
            return 0;
    }

    ej_clear_index();
    c->head = 0;
    ej_ctrl_commit(c);
    return 1;
}

/* ---------------------------------------------------------------- */
/* migrazione dal formato interlacciato                               */
/* ---------------------------------------------------------------- */

/* Nel formato vecchio il byte logico i sta all'offset i << lf, quindi il
 * blocco b occupa b * (8 << lf) con passo 1 << lf. Per lf = 3 sono 64
 * byte fisici per blocco, per lf = 7 sono 1024: in entrambi i casi i dati
 * vecchi sono sparsi su tutta la finestra, compresa la zona dove andra' a
 * finire la nuova base. Per questo i blocchi che cadono dentro lo slot A
 * vengono prima messi al sicuro nello scratch. */
static int ej_migrate(int old_lf)
{
    struct ej_ctrl *c = ej_ctrl();
    unsigned stride = EJ_BLK << old_lf;
    unsigned step = 1u << old_lf;
    /* stride vale 8 << old_lf, quindi e' sempre una potenza di due: la
     * divisione diventa uno scorrimento. Non e' solo eleganza - l'ARM7TDMI
     * non ha istruzione di divisione, e il payload e' linkato senza le
     * librerie di supporto, quindi una divisione vera non si risolve. */
    unsigned rescue = EJ_SLOT_SPAN >> (3 + old_lf);
    if (!rescue)
        rescue = 1;                  /* un blocco piu' largo dello slot */

    /* Quanti blocchi poteva contenere il formato vecchio: la finestra
     * divisa per il passo. Con lf = 3 sono 1024, con lf = 7 sono 64.
     *
     * Serve fermarsi li'. Leggere oltre non trova altri dati: gli
     * indirizzi ricadono nella finestra per via della maschera e si
     * rileggerebbero gli stessi byte, duplicando il salvataggio in
     * blocchi che il gioco non usera' mai. Non romperebbe niente - i
     * controlli di limite li tengono fuori - ma riempirebbe la base di
     * copie inutili, e ogni compattazione da li' in avanti dovrebbe
     * riscriverle. */
    unsigned nblocks = EJ_WINDOW >> (3 + old_lf);
    if (nblocks > EJ_BLOCKS_MAX)
        nblocks = EJ_BLOCKS_MAX;
    if (rescue > nblocks)
        rescue = nblocks;
    unsigned tlen = 0;
    unsigned char *tmp = ej_tmp(&tlen);

    if (tlen < rescue * EJ_BLK)
        return 0;

    if (ej_single_block())
    {
        /* Blocco unico: non si puo' cancellare una parte sola, quindi
         * serve l'immagine intera in RAM.
         *
         * FINESTRA DI VULNERABILITA': vale l'intera migrazione. Capita
         * una volta sola, al primo salvataggio dopo la conversione. */
        if (tlen < EJ_BLOCKS_MAX * EJ_BLK)
            return 0;
        for (unsigned b = 0; b < nblocks; ++b)
            for (unsigned i = 0; i < EJ_BLK; ++i)
                tmp[b * EJ_BLK + i] = ej_rd(b * stride + i * step);
        if (!ej_erase(0))
            return 0;
        for (unsigned b = 0; b < nblocks; ++b)
        {
            unsigned char *s = tmp + b * EJ_BLK;
            unsigned d = EJ_SLOT_A + EJ_HDR_LEN + b * EJ_BLK;
            for (unsigned i = 0; i < EJ_BLK; ++i)
                if (s[i] != 0xFF && !ej_pgm(d + i, s + i, 1))
                    return 0;
        }
    }
    else
    {
        /* Mettiamo al sicuro i soli blocchi che vivono dentro lo slot A,
         * poi cancelliamo quei tre settori. Il resto del vecchio
         * salvataggio, da 0x3000 in su, non viene toccato finche' la
         * nuova base non e' completa. */
        for (unsigned b = 0; b < rescue; ++b)
            for (unsigned i = 0; i < EJ_BLK; ++i)
                tmp[b * EJ_BLK + i] = ej_rd(b * stride + i * step);

        if (!ej_erase_range(EJ_SLOT_A, EJ_SLOT_A + EJ_SLOT_SPAN))
            return 0;

        /* Prima i blocchi messi in salvo, per accorciare il tratto in cui
         * esistono soltanto in RAM. */
        for (unsigned b = 0; b < rescue; ++b)
        {
            unsigned char *s = tmp + b * EJ_BLK;
            unsigned d = EJ_SLOT_A + EJ_HDR_LEN + b * EJ_BLK;
            for (unsigned i = 0; i < EJ_BLK; ++i)
                if (s[i] != 0xFF && !ej_pgm(d + i, s + i, 1))
                    return 0;
        }
        for (unsigned b = rescue; b < nblocks; ++b)
        {
            unsigned d = EJ_SLOT_A + EJ_HDR_LEN + b * EJ_BLK;
            for (unsigned i = 0; i < EJ_BLK; ++i)
            {
                unsigned char v = ej_rd(b * stride + i * step);
                if (v != 0xFF && !ej_pgm(d + i, &v, 1))
                    return 0;
            }
        }
    }

    if (!ej_hdr_write(0, 1))
        return 0;
    c->slot = 0;

    /* Da qui la nuova base e' valida: il vecchio salvataggio non serve
     * piu' e la sua area diventa slot B e journal.
     *
     * Solo sui chip a settori: su un blocco unico e' gia' stato
     * cancellato tutto all'inizio, e una cancellazione adesso porterebbe
     * via la base appena scritta. */
    if (!ej_single_block() && !ej_erase_range(EJ_SLOT_B, EJ_WINDOW))
        return 0;

    ej_clear_index();
    c->head = 0;
    ej_ctrl_commit(c);
    return 1;
}

/* Chip vergine? Basta trovare un byte diverso da 0xFF per sapere che
 * qualcosa c'e' gia' scritto. */
static int ej_window_blank(void)
{
    for (unsigned o = 0; o < EJ_WINDOW; ++o)
        if (ej_rd(o) != 0xFF)
            return 0;
    return 1;
}

/* ---------------------------------------------------------------- */
/* interfaccia                                                        */
/* ---------------------------------------------------------------- */

/* Porta lo stato in EWRAM in linea con la Flash, convertendo o
 * inizializzando se serve. old_lf e' il fattore di interlacciamento che
 * il formato precedente usava per questo gioco. */
static int ej_ready(int old_lf)
{
    struct ej_ctrl *c = ej_ctrl();

    if (ej_ctrl_valid(c))
        return 1;
    if (ej_rebuild())
        return 1;

    if (ej_window_blank())
    {
        if (!ej_hdr_write(0, 1))
            return 0;
        c->slot = 0;
        c->head = 0;
        ej_clear_index();
        ej_ctrl_commit(c);
        return 1;
    }

    /* C'e' qualcosa scritto, in un formato che non e' il nostro, ma il
     * chiamante ci dice di non sapere ancora con che passo leggerlo.
     * Convertire adesso significherebbe scegliere a caso, e la conversione
     * non si ripete: meglio fallire questa chiamata e riprovare quando il
     * passo sara' noto. */
    if (old_lf < 0)
        return 0;

    return ej_migrate(old_lf);
}

/* L'indice in EWRAM e' una copia di comodo, la verita' sta nella Flash -
 * ma finora nessuno lo verificava mai. Il gioco quella memoria potrebbe
 * usarla: il blocco di controllo resterebbe intatto, l'indice no, e una
 * voce alterata farebbe consegnare al gioco gli otto byte di un altro
 * blocco senza che niente se ne accorga.
 *
 * Smascherarla costa due letture: ogni record porta scritto dentro a quale
 * blocco appartiene, quindi basta chiedere alla Flash se il record che la
 * voce indica e' davvero il nostro. Copre la voce che punta al
 * record sbagliato, quella che punta oltre la testa nel journal ancora
 * vergine, e - grazie a EJ_INBASE - anche la memoria spazzata a 0x00 o a
 * 0xFF. Resta fuori solo la voce che per coincidenza cade su un altro
 * record dello stesso blocco: si servirebbe un valore piu' vecchio, mai
 * spazzatura, e la compattazione non lo incide perche' riparte dalla
 * Flash.
 *
 * La verifica sta qui e non dentro ej_fetch di proposito: ej_fetch viene
 * chiamata in ciclo anche dalla compattazione, e ricostruire l'indice in
 * mezzo a una compattazione ne azzererebbe la testa a meta' lavoro. */
static int ej_index_trusted(unsigned blk)
{
    unsigned short e = ej_index()[blk];
    if (e == EJ_INBASE)
        return 1;
    return e < ej_ctrl()->head && ej_rec_index(e) == blk;
}

static int ej_read_block(unsigned blk, unsigned char *out, int old_lf)
{
    if (blk >= EJ_BLOCKS_MAX || !ej_ready(old_lf))
        return 0;
    if (!ej_index_trusted(blk) && !ej_rebuild())
        return 0;
    ej_fetch(blk, out);
    return 1;
}

static int ej_write_block(unsigned blk, const unsigned char *in, int old_lf)
{
    if (blk >= EJ_BLOCKS_MAX || !ej_ready(old_lf))
        return 0;
    if (!ej_index_trusted(blk) && !ej_rebuild())
        return 0;

    /* Dato identico: non si scrive niente. Nel journal un record inutile
     * costerebbe spazio e quindi una compattazione anticipata. */
    unsigned char cur[EJ_BLK];
    ej_fetch(blk, cur);
    unsigned same = 1;
    for (unsigned i = 0; i < EJ_BLK; ++i)
        if (cur[i] != in[i]) { same = 0; break; }
    if (same)
        return 1;

    struct ej_ctrl *c = ej_ctrl();

    /* Si scorre fino al primo record davvero vergine. Normalmente e' gia'
     * quello in testa e il ciclo non gira nemmeno: si salta solo dopo una
     * interruzione a meta' record, o dopo una programmazione fallita che
     * ha lasciato indietro dei byte. Dieci letture dalla cartuccia, meno
     * di un centesimo del costo di programmare il record. */
    while (c->head < EJ_RECS && !ej_rec_blank(c->head))
        c->head = (unsigned short) (c->head + 1);

    if (c->head >= EJ_RECS && !ej_compact())
        return 0;

    /* Il record e' vergine, quindi ej_pgm salta da se' i byte a 0xFF: la
     * cella vale gia' 0xFF e il confronto la scarta. */
    unsigned off = ej_rec_off(c->head);
    if (!ej_pgm(off, in, EJ_BLK))
        return 0;

    /* L'indice per ultimo: e' lui a rendere il record esistente. */
    unsigned char bi[2];
    bi[0] = (unsigned char) blk;
    bi[1] = (unsigned char) (blk >> 8);
    if (!ej_pgm(off + EJ_BLK, bi, 2))
        return 0;

    ej_index()[blk] = c->head;
    c->head = (unsigned short) (c->head + 1);
    ej_ctrl_commit(c);
    return 1;
}
