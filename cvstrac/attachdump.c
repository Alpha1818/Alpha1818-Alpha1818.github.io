/*
** This is a utility program used to output the content of the
** ATTACHMENT table of an SQLite version 2 database as SQL such
** that it can be imported into an SQLite version 3 database.
**
** If this program is compiled into an executable named "attachdump",
** Then you upgrade the database from CVSTrac version 1.2.1 to 2.0.x
** by doing this:
**
**         mv database.db database.db-v2
**         sqlite database.db-v2 | sqlite3 database.db
**         attachdump database.db-v2 | sqlite3 database.db
*/
#include <sqlite.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

/*
** Convert the low-order byte of the input character to an hexadecimal
** digit.
*/
static char toHex(unsigned char x){
  x &= 0xf;
  if( x<10 ){
    return x + '0';
  }else{
    return (x - 10) + 'A';
  }
}

/*
** Output the string.  Double any '\'' characters seen.
*/
static void outputQuoted(const char *z){
  if( z==0 ){
    printf("NULL");
  }else{
    putchar('\'');
    while( *z ){
      if( *z=='\'' ){
        putchar(*z);
      }
      putchar(*z);
      z++;
    }
    putchar('\'');
  }
}

/*
** Decode the string "in" into binary data and write it into "out".
** This routine reverses the encoded created by sqlite_encode_binary().
** The output will always be a few bytes less than the input.  The number
** of bytes of output is returned.  If the input is not a well-formed
** encoding, -1 is returned.
**
** The "in" and "out" parameters may point to the same buffer in order
** to decode a string in place.
*/
int blob_decode(const unsigned char *in, unsigned char *out){
  int i, c, e;
  e = *(in++);
  i = 0;
  while( (c = *(in++))!=0 ){
    if( c==1 ){
      c = *(in++);
      if( c==1 ){
        c = 0;
      }else if( c==2 ){
        c = 1;
      }else if( c==3 ){
        c = '\'';
      }else{
        return -1;
      }
    }
    out[i++] = (c + e)&0xff;
  }
  return i;
}


/*
** Output a single row of the attachment table.
*/
static int outputOneRow(void *notUsed, int argc, char **argv, char **colv){
  int i, n;
  unsigned char z[1000000];
  assert( argc==9 );
  printf("REPLACE INTO attachment VALUES(%s,", argv[0]);
  if( argv[1] && isdigit(argv[1][0]) ){
    printf("%s,", argv[1]);
  }else{
    outputQuoted(argv[1]);
    printf(",");
  }
  printf("%s,%s,", argv[2], argv[3]);
  outputQuoted(argv[4]);
  printf(",");
  outputQuoted(argv[5]);
  printf(",");
  outputQuoted(argv[6]);
  printf(",");
  outputQuoted(argv[7]);
  printf(",x'");
  n = blob_decode(argv[8], z);
  for(i=0; i<n; i++){
    putchar(toHex(z[i]>>4));
    putchar(toHex(z[i]));
  }
  printf("');\n");
  return 0;
}

/*
** Open the database whose name is shown on the command-line.
** Output to standard output an SQL dump of the attachment table
*/
int main(int argc, char **argv){
  sqlite *db;
  char *zErr;
  if( argc!=2 ){
    fprintf(stderr, "Usage: %s DATABASE-NAME\n", *argv);
    exit(1);
  }
  db = sqlite_open(argv[1], 0, 0);
  if( db==0 ){
    fprintf(stderr, "%s: cannot open %s\n", argv[0], argv[1]);
    exit(1);
  }
  printf("BEGIN;\n");
  if( sqlite_exec(db, "SELECT * FROM attachment", outputOneRow, 0, &zErr) ){
    fprintf(stderr, "%s: errory running the SQL statement: %s\n", zErr);
    exit(1);
  }
  printf("COMMIT;\n");
  sqlite_close(db);
  return 0;
}
