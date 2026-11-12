#include <stdio.h>

/* Converte un file binario in un sorgente C con un array unsigned char[]
 * e una variabile unsigned int con la lunghezza, compatibile con
 * payload_bin.h (extern unsigned char payload_bin[]; extern unsigned int payload_bin_len;)
 *
 * Uso: bin2c input.bin output.c nome_variabile
 * Esempio: bin2c payload.bin payload_bin.c payload_bin
 */

int main(int argc, char **argv)
{
    if (argc != 4)
    {
        fprintf(stderr, "Uso: %s input.bin output.c nome_variabile\n", argv[0]);
        return 1;
    }

    FILE *in = fopen(argv[1], "rb");
    if (!in)
    {
        perror("Impossibile aprire il file di input");
        return 1;
    }

    FILE *out = fopen(argv[2], "w");
    if (!out)
    {
        perror("Impossibile aprire il file di output");
        fclose(in);
        return 1;
    }

    fprintf(out, "unsigned char %s[] = {\n", argv[3]);

    int c;
    int col = 0;
    unsigned int total = 0;
    while ((c = fgetc(in)) != EOF)
    {
        fprintf(out, "0x%02x,", c);
        total++;
        if (++col == 16)
        {
            fprintf(out, "\n");
            col = 0;
        }
    }

    fprintf(out, "\n};\nunsigned int %s_len = %u;\n", argv[3], total);

    fclose(in);
    fclose(out);

    printf("Scritti %u byte in %s come array '%s'\n", total, argv[2], argv[3]);
    return 0;
}
