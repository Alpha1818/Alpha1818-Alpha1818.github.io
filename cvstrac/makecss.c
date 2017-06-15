/*
** Copyright (c) 2002 D. Richard Hipp
**
** This program is free software; you can redistribute it and/or
** modify it under the terms of the GNU General Public
** License as published by the Free Software Foundation; either
** version 2 of the License, or (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
** General Public License for more details.
** 
** You should have received a copy of the GNU General Public
** License along with this library; if not, write to the
** Free Software Foundation, Inc., 59 Temple Place - Suite 330,
** Boston, MA  02111-1307, USA.
**
** Author contact information:
**   drh@hwaci.com
**   http://www.hwaci.com/drh/
**
*******************************************************************************
**
** This file implements a standalone program used to generate generate a
** file, css.c, containing support for the "default" CVSTrac CSS stylesheet.
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

static int generate_file(const char *zName, const char *zFile){
  int i;
  char zLine[2000];
  FILE *in = fopen(zFile,"r");
  if( in==0 ){
    perror(zFile);
    return -1;
  }
  printf("static const char z%s[] =\n", zName);
  while( fgets(zLine,sizeof(zLine),in)!=0 ){
    for(i=0; zLine[i] && zLine[i]!='\n'; i++){}
    printf("@ %.*s\n", i, zLine);
  }
  printf(";\n");
  return 0;
}

int main(int argc, char **argv){
  if( argc!=2 ){
    fprintf(stderr,"Usage: %s ?stylesheet.css? >css.c\n", argv[0]);
    exit(1);
  }
  if( access(argv[1], 4) ){
    perror("Stylesheet file does not exist or is not readable");
    exit(1);
  }
  printf(
    "/*** AUTOMATICALLY GENERATED FILE - DO NOT EDIT ****\n"
    "**\n"
    "** This file was generated automatically by the makecss.c\n"
    "** program.  See the sources to that program for additional\n"
    "** information.\n"
    "*/\n"
    "#include \"config.h\"\n"
    "#include \"css.h\"\n"
    "\n"
  );
  generate_file("DefaultStylesheet",argv[1]);

  printf(
    "/*\n"
    "** WEBPAGE: /cvstrac_default.css\n"
    "*/\n"
    "void default_css(void){\n"
    "  cgi_set_content_type(\"text/css\");\n"
    "  /* CVSTrac build time */\n"
    "  cgi_append_header(\n"
    "    mprintf(\"Last-Modified: %%s\\r\\n\", cgi_rfc822_datestamp(%u)));\n"
    "  cgi_append_content(zDefaultStylesheet, strlen(zDefaultStylesheet));\n"
    "}\n"
    "\n"
    "/*\n"
    "** WEBPAGE: /cvstrac.css\n"
    "*/\n"
    "void cvstrac_css(void){\n"
    "  char *atn = db_short_query(\"SELECT atn FROM attachment \"\n"
    "                             \"WHERE tn=0 AND fname='%%q' \"\n"
    "                             \"ORDER BY date DESC LIMIT 1\", g.zPath);\n"
    "  if( atn && *atn ){\n"
    "    attachment_output(atoi(atn));\n"
    "    free(atn);\n"
    "    g.isConst = 0;\n"
    "  }else{\n"
    "    default_css();\n"
    "  }\n"
    "}\n"
    "\n",
    (unsigned int)time(0)
  );

  return 0;
}
