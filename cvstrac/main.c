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
** The main routine
*/
#include "config.h"
#include "main.h"
#include <time.h>
#include <pwd.h>
#include <sys/types.h>
#ifdef CVSTRAC_WINDOWS
# define WINVER 0x500
# include <windows.h>
# include <fcntl.h>
#endif

#if SQLITE_VERSION_NUMBER < 3001000
#  error "Requires SQLite 3.1 or greater"
#endif

#if CVSTRAC_I18N
#include <langinfo.h>
#endif

#if INTERFACE

/*
** Maximum number of distinct aux() values
*/
#define MX_AUX 10

struct Scm {
  const char *zSCM;       /* Which SCM subsystem is supported (i.e. "cvs") */
  const char *zName;      /* User-readable SCM name (i.e. "Subversion") */
  int canFilterModules;   /* non-zero if the SCM can filter modules */

  int (*pxHistoryUpdate)(int isReread);
  int (*pxHistoryReconstructPrep)();
  int (*pxHistoryRescanPrep)();
  int (*pxDiffVersions)(const char *zOldVersion, const char *zNewVersion,
                        const char *zFile);
  int (*pxDiffChng)(int cn, int bRaw);
  int (*pxIsFileAvailable)(const char *zFile);
  int (*pxDumpVersion)(const char *zVers, const char *zFile, int bRaw);
  int (*pxUserRead)(void);
  int (*pxUserWrite)(const char *zOmit);
};

/*
** All global variables are in this structure.
*/
struct Global {
  int argc; char **argv;  /* Command-line arguments to the program */
  struct Scm scm;         /* SCM-specific variables, callbacks, etc */
  const char *zName;      /* Base name of the program */
  const char *zUser;      /* Name of the user */
  const char *zHumanName; /* Human readable name of the user */
  char *zBaseURL;         /* Absolute base URL for any CVSTrac page */
  char *zLinkURL;         /* URL prefixed to all output URLs */
  char *zPath;            /* The URL for the current page */
  char *zExtra;           /* Additional path information following g.zPath */
  int okCheckout;         /* True if the user has CVS checkout permission */
  int okCheckin;          /* True if the user has CVS checkin permission */
  int okNewTkt;           /* True if the user can create new tickets */
  int okRead;             /* True if the user may view tickets */
  int okPassword;         /* True if the user may change his password */
  int okWrite;            /* True if the user can edit tickets */
  int okAdmin;            /* True if the user has administrative permission */
  int okSetup;            /* True if the user has setup permission */
  int okRdWiki;           /* True if the user can read wiki pages */
  int okWiki;             /* True if the user can write wiki pages */
  int okDelete;           /* True if able to delete wiki or tickets */
  int okQuery;            /* True if able to create new reports */
  int isAnon;             /* Anonymous user (not logged in) */
  int isConst;            /* True if the page is constant and cacheable. */
  int okTicketLink;       /* True for ticket info link titles */
  int okCheckinLink;      /* True for chng info link titles */
  int noFollow;           /* Output links with rel="nofollow" */
  int useUTF8;            /* CVSTrac running in UTF-8 locale */
  int isIIS;              /* True if CVSTrac is running inside Microsoft IIS */

  /* Storage for the aux() and/or option() SQL function arguments */
  int nAux;                    /* Number of distinct aux() or option() values */
  const char *azAuxName[MX_AUX]; /* Name of each aux() or option() value */
  char *azAuxParam[MX_AUX];      /* Param of each aux() or option() value */
  const char *azAuxVal[MX_AUX];  /* Value of each aux() or option() value */
  const char **azAuxOpt[MX_AUX]; /* Options of each option() value */
  int anAuxCols[MX_AUX];         /* Number of columns for option() values */
};
#endif

Global g;

/*
** The table of web pages supported by this application is generated 
** automatically by the "mkindex" program and written into a file
** named "page_index.h".  We include that file here to get access
** to the table.
*/
#include "page_index.h"

/*
** Search for a match against the given pathname.  Return TRUE on
** success and FALSE if not found.
*/
static int find_path(
  const char *zPath,       /* The pathname we are looking for */
  void (**pxFunc)(void)    /* Write pointer to handler function here */
){
  int upr, lwr;
  lwr = 0;
  upr = sizeof(aSearch)/sizeof(aSearch[0])-1;
  while( lwr<=upr ){
    int mid, c;
    mid = (upr+lwr)/2;
    c = strcmp(zPath, aSearch[mid].zPath);
    if( c==0 ){
      *pxFunc = aSearch[mid].xFunc;
      return 1;
    }else if( c<0 ){
      upr = mid - 1;
    }else{
      lwr = mid + 1;
    }
  }
  return 0;
}

/*
** Print a usage message and die
*/
static void usage(const char *argv0){
    fprintf(stderr, 
      "Usage: %s <command> ?<directory>? ?<project>?\n"
      "   Or: %s chroot <root> <user> <command> ?<directory>? ?<project>?\n"
      "   Or: %s server <port> <directory> ?<project>?\n"
      "   Or: %s chroot <root> <user> server <port> <directory> ?<project>?\n"
      "Where:\n"
      "  <command>    is one of \"cgi\", \"http\", \"init\", \"wikiinit\""
      " or \"update\".\n"
      "  <directory>  is the directory that contains the project database.\n"
      "  <project>    is the name of the project.\n"
      "  <port>       is a TCP port number to listen on.\n"
      "  <root>       is a chroot jail directory.\n"
      "  <user>       is the user to run as.\n",
      argv0, argv0, argv0, argv0);
    exit(1);
}

/* Check the database schema version.  Upgrade if the database schema
** if necessary.
*/
static void check_schema() {
  const char *zSchema = db_config("schema","1.0");
  if( strcmp(zSchema,"2.3") ){
    if( strcmp(zSchema,"1.1")<0 ) db_upgrade_schema_1();
    if( strcmp(zSchema,"1.2")<0 ) db_upgrade_schema_2();
    if( strcmp(zSchema,"1.3")<0 ) db_upgrade_schema_3();
    if( strcmp(zSchema,"1.4")<0 ) db_upgrade_schema_4();
    if( strcmp(zSchema,"1.5")<0 ) db_upgrade_schema_5();
    if( strcmp(zSchema,"1.6")<0 ) db_upgrade_schema_6();
    if( strcmp(zSchema,"1.7")<0 ) db_upgrade_schema_7();
    if( strcmp(zSchema,"1.8")<0 ) db_upgrade_schema_8();
    if( strcmp(zSchema,"1.9")<0 ) db_upgrade_schema_9();
    if( strcmp(zSchema,"2.0")<0 ) db_upgrade_schema_20();
    if( strcmp(zSchema,"2.1")<0 ) db_upgrade_schema_21();
    if( strcmp(zSchema,"2.2")<0 ) db_upgrade_schema_22();
    if( strcmp(zSchema,"2.3")<0 ) db_upgrade_schema_23();

    /* Good thing to do after you move tables around... */
    db_execute("VACUUM;");
  }
}

/*
** Run the program.
*/
int main(int argc, char **argv){
  int i, j;
  char *zSCM;
  char *zPath;
  char *zScript = NULL;
#ifdef CVSTRAC_WINDOWS
  char *zSoftware;
  int incorrectCase = 0;
#endif
  char *zPathStart;
  char *zUri;
  char *zDb;
  const char *zLogFile;
  int cmdlineProj;        /* True if project specified on command line */
  void (*xFunc)(void);
  
  /* Determine the SCM subsystem. Need to do this before anyone messes with
  ** argv.
  */
  i = strlen(argv[0]);
  while( i>0 && argv[0][i-1]!=OS_VAL('/','\\') ){ i--; }
  zSCM = mprintf("%s", &argv[0][i]);
  zPath = strstr(zSCM,"trac");
  if( zPath!=0 ) *zPath = 0;

  if( !strcmp(zSCM,"cvs") ){
    init_cvs();
  }else if(!strcmp(zSCM,"svn") ){
    init_svn();
  }else if(!strcmp(zSCM,"git") ){
    init_git();
  }else{
    fprintf(stderr,"%s: unknown SCM '%s'\n", argv[0], zSCM);
    exit(1);
  }
 
  /*
  ** Attempt to put this process in a chroot jail if requested by the
  ** user.  The program must be run as root for this to work.
  */
  if( argc>=5 && strcmp(argv[1],"chroot")==0 ){
    struct passwd *pwinfo;
    pwinfo = getpwnam(argv[3]);
    if( pwinfo==0 ){
      fprintf(stderr,"%s: no such user: %s\n", argv[0], argv[3]);
      exit(1);
    }
    if( chdir(argv[2]) || chroot(argv[2]) ){
      fprintf(stderr, "%s: Unable to change root directory to %s\n",
        argv[0], argv[2]);
      exit(1);
    }
    argv[3] = argv[0];
    argv += 3;
    argc -= 3;
    if( argc>=3 && strcmp(argv[1],"server")==0 ){
      cgi_http_server(atoi(argv[2]));
      argc--;
      argv[1] = argv[0];
      argv++;
      argv[1] = "http";
    }
    setgid(pwinfo->pw_gid);
    setuid(pwinfo->pw_uid);
  }else if( argc>=3 && strcmp(argv[1],"server")==0 ){
    cgi_http_server(atoi(argv[2]));
    argv[1] = argv[0];
    argv++;
    argv[1] = "http";
    argc--;
  }

  /*
  ** Make sure we have the right number of arguments left.
  */
  if( argc<2 || argc>4 ){
    usage(argv[0]);
  }

  /*
  ** For security, do not allow this program to be run as root.
  */
  if( getuid()==0 || getgid()==0 ){
    fprintf(stderr,"%s: execution by the superuser is disallowed\n", argv[0]);
    exit(1);
  }

  /* Change into the project directory. */
  if( argc>=3 && chdir(argv[2]) ){
    fprintf(stderr,"%s: unable to change directories to %s\n", argv[0],argv[2]);
    exit(1);
  }

#if CVSTRAC_I18N
  /* Set the appropriate locale */
  setlocale(LC_ALL, "");
  g.useUTF8 = (strcmp(nl_langinfo(CODESET), "UTF-8") == 0);
#endif

  /* Set up global variable g
  */
  g.argc = argc;
  g.argv = argv;
  if( argc>=4 ){
    /* The project name is specified on the command-line */
    g.zName = argv[3];
    if( g.zName ){
      /* strip path separators from project name. That's what argv[2]
      ** is intended for.
      */
      char* z = strrchr(g.zName, OS_VAL('/','\\') );
#ifdef CVSTRAC_WINDOWS
      /* Windows can use either kind of separator. If users _mix_ path
      ** separators, they're probably doomed.
      */
      if( !z ) z = strrchr(g.zName, '/');
#endif
      if( z ) g.zName = &z[1];
    }
    cmdlineProj = 1;
  }else{
    /* No project name on the command line.  Get the project name from
    ** either the URL or the HTTP_HOST parameter of the request.
    */
    i = strlen(argv[0]);
    while( i>0 && argv[0][i-1]!='/' ){ i--; }
    g.zName = mprintf("%s", &argv[0][i]);
    cmdlineProj = 0;
  }

#ifdef CVSTRAC_WINDOWS
  setmode( fileno(stdin), O_BINARY );  /* This lines needed on    */
  setmode( fileno(stdout), O_BINARY ); /* Windows/DOS boxes       */
#endif

  /* Figure out our behavior based on command line parameters and
  ** the environment.  
  */
  if( strcmp(argv[1],"cgi")==0 /* || getenv("GATEWAY_INTERFACE")!=0 */ ){
    cgi_init();
  }else if( strcmp(argv[1],"http")==0 ){
    cgi_handle_http_request();
  }else if( strcmp(argv[1],"init")==0 ){
    if( getuid()!=geteuid() ){
      fprintf(stderr,"Permission denied\n");
      exit(1);
    }
    db_init();
    exit(0);
  }else if( strcmp(argv[1],"wikiinit")==0 ){
    if( getuid()!=geteuid() ){
      fprintf(stderr,"Permission denied\n");
      exit(1);
    }
    initialize_wiki_pages();
    exit(0);
  }else if( strcmp(argv[1],"update")==0 ){
    check_schema();
    history_update(0);
    exit(0);
  }else if( strcmp(argv[1],"testcgi")==0 ){
    cgi_init();
    test_cgi_vardump();
    cgi_reply();
    exit(0);
  }else{
    usage(argv[0]);
  }

  /* Find the page that the user has requested, construct and deliver that
  ** page.
  */
  zPathStart = zPath = getenv("PATH_INFO");
#ifdef CVSTRAC_WINDOWS
  /* Microsoft IIS doesn't define REQUEST_URI variable,
  ** moreover it does not define well other variables, so we need to make
  ** few more fixes here below.
  */
  zSoftware = getenv("SERVER_SOFTWARE");
  if(zSoftware && strstr(zSoftware, "IIS")){
    char *zUri = getenv("REQUEST_URI");
    g.isIIS = 1;
    if(!zUri || !*zUri)
    {
      char newUri[512], *zQS = getenv("QUERY_STRING");
      snprintf(newUri, 512, "REQUEST_URI=%s%s%s",
        zPath ? zPath : "",
        (zQS && *zQS) ? "?" : "",
        (zQS && *zQS) ? zQS : "");
      putenv(newUri);
    }
  }
  if( g.isIIS ){
    zScript = getenv("SCRIPT_NAME");
    /* If the PATH_INFO & SCRIPT_NAME are the same, means we got
    ** IIS wildcard ScriptMap, therefore we allow only one level wilcard
    ** mappings. Othwerwise we remove common part of zPath and zScript.
    */
    if( zScript ){
      if( strcmp(zScript,zPath)==0
        && (zPathStart = zPath = strchr(zScript+1,'/'))
      ){
        zScript = mprintf("%.*s", zPath-zScript, zScript);
      }else{
        while(zPath && zScript && *zPath && *zScript && *zPath == *zScript) {
          zPath++;
          zPathStart++;
          zScript++;
        }
        zScript = getenv("SCRIPT_NAME");
      }
    }
  }
#endif
  zUri = getenv("REQUEST_URI");
  if( zUri==0 ) zUri = "/";
  if( zPath==0 || zPath[0]==0 ){
    for(i=0; zUri[i] && zUri[i]!='?' && zUri[i]!='#'; i++){}
    for(j=i; j>0 && zUri[j-1]!='/'; j--){}
    if( i==j ){
      cgi_set_status(404,"Not Found");
      @ <h1>Not Found</h1>
      @ <p>Page not found: %h(zUri)</p>
    }else{
      char *zBase = mprintf("%.*s/index", i-j, &zUri[j]);
      cgi_redirect(zBase);
    }
    cgi_reply();
    return 0;
  }

  /* 
  ** Extract the project name from the front of the path if no project
  ** was specified on the command line.
  */
  if( !cmdlineProj ){
    while(zPath[0]=='/') {zPath++;}    /* eat leading '/' */
    for(i=0; zPath[i] && zPath[i]!='/'; i++){}
    if( i>0 ){
#ifdef CVSTRAC_WINDOWS
      /*
      ** Try finding the correct case of the file name.
      */
      char *zDb = mprintf("%.*s.db", i, zPath);
      char zBuf[MAX_PATH];
      if(GetShortPathName(zDb, zBuf, MAX_PATH)
        && GetLongPathName(zBuf, zBuf, MAX_PATH)
        && !strncasecmp(zBuf, zPath, i)
        && strncmp(zBuf, zPath, i)){
        memcpy(zPath, zBuf, i);
        incorrectCase = 1;
      }
      free(zDb);
#endif
      g.zName = mprintf("%.*s", i, zPath);
      zPath = &zPath[i];    
    }else{
      cgi_set_status(404,"Not Found");
      @ <h1>Not Found</h1>
      @ <p>Page not found: %h(zPath)</p>
      cgi_reply();
      return 0;
    }
  }

  /*
  ** Calculate a "base" URL. This is a URL where we could redirect things,
  ** and more importantly it's the absolute URL we include in things like
  ** RSS output where there's no existing url to be relative to.
  */
  {
    char *zHost = getenv("HTTP_HOST");
    char *zMode = getenv("HTTPS");
    if( !g.isIIS ){
      /* zScript is already defined for IIS */
      zScript = getenv("SCRIPT_NAME");
    }
    char *zProto = (zMode && strcmp(zMode,"on")==0) ? "https" : "http";

    g.zBaseURL = mprintf("%s://%s%s%.*s", zProto, zHost,
                         zScript?zScript:"",  /* i.e. /cgi-bin/cvstrac */
                         (zPath-zPathStart), zPathStart);
#ifdef CVSTRAC_WINDOWS
    if(incorrectCase){
      /*
      ** Redirect to the URL containing the corrected case of project name.
      */
      char *zQS = getenv("QUERY_STRING");
      cgi_redirect(mprintf("%s%s%s%s", g.zBaseURL, zPath,
        (zQS && *zQS) ? "?" : "",
        (zQS && *zQS) ? zQS : ""));
    }
#endif
  }

  assert( zPath[0]==0 || zPath[0]=='/' );
  if( zPath[0]==0 ){
    /*
    ** No sub page, no trailing '/' in the URL. This is a bit of a problem.
    ** We like to generate relative urls for subpages (i.e. "tktview?tn=1").
    ** However, if the URL doesn't have a '/' after the project
    ** (http://host/project vs http://host/project/wikitoc),
    ** the browser can't/doesn't recognize that the subpage is _below_
    ** the current page. It thinks it's at the same level as "/project" and
    ** sends the user there.
    ** The easiest "fix" is to just redirect such requests with empty "paths"
    ** directly to the index. Then we know they'll have the '/' and the
    ** browser will handle relative paths correctly.
    */
    cgi_redirect(mprintf("%s/index", g.zBaseURL));
  }

  while(zPath[0]=='/') {zPath++;}    /* eat leading '/' */
  g.zPath = zPath;
  for(i=0; zPath[i] && zPath[i]!='/'; i++){}
  if( zPath[i]=='/' ){
    zPath[i] = 0;
    g.zExtra = &zPath[i+1];

    /* CGI parameters get this treatment elsewhere, but places like getfile
    ** will use g.zExtra directly.
    */
    dehttpize(g.zExtra);
  }else{
    g.zExtra = 0;
  }

  /* Prevent robots from indexing this site.
  */
  if( strcmp(g.zPath, "robots.txt")==0 ){
    cgi_set_content_type("text/plain");
    @ User-agent: *
    @ Disallow: /
    cgi_reply();
    exit(0);
  }

  /* Make sure the specified project really exists.  Return an error
  ** if it does not.
  */
  zDb = mprintf("%s.db", g.zName);
  if( access(zDb,0) ){
    free(zDb);
    zDb = mprintf("%s.db", g.zPath);
    if( !cmdlineProj && access(zDb,0)==0 ){
      cgi_redirect( mprintf("%s/index", g.zPath) );
    }else{
      cgi_set_status(404,"Not Found");
      @ <h1>Not Found</h1>
      @ <p>Project not found: %h(g.zName)</p>
      @ <p>Page not found: %h(g.zPath)</p>
    }
    cgi_reply();
    return 0;
  }
  free(zDb);

  check_schema();

#ifndef CVSTRAC_WINDOWS
  /* Ensure the CVSTrac process doesn't live indefinitely. If it takes more
  ** than this long, you're doing something wrong.
  */
  alarm(MX_CHILD_LIFETIME);
#endif
  /* Make a log file entry for this access.
  */
  zLogFile = db_config("logfile", 0);
  if( zLogFile ){
    cgi_logfile(zLogFile,"*");
  }

  /* Locate the method specified by the path and execute the function
  ** that implements that method.
  */
  if( !find_path(g.zPath, &xFunc) && !find_path("not_found",&xFunc) ){
    char *atn = db_short_query("SELECT atn FROM attachment "
                               "WHERE tn=0 AND fname='%q' "
                               "ORDER BY date DESC LIMIT 1", g.zPath);
    if( atn && *atn ){
      attachment_output(atoi(atn));
      free(atn);

      /* it's not actually constant because the URL can point at different
      ** attachments over time. */
      g.isConst = 0;
    }else{
      cgi_set_status(404,"Not Found");
      @ <h1>Not Found</h1>
      @ <p>Page not found: %h(g.zPath)</p>
    }
  }else{
    xFunc();
  }

  /* Return the result.
  */
  cgi_reply();
  return 0;
}
