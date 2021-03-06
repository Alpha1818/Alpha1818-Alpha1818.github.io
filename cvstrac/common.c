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
** Routines shared by many pages
*/
#include "config.h"
#include "common.h"

/*
** Output a string with the following substitutions:
**
**     %T      The title of the current page.
**     %N      Project name
**     %V      CVSTrac version number
**     %B      Base URL
**     %%      The character '%'
*/
static void output_with_subst(const char *zText, const char *zTitle){
  int i;
  while( zText[0] ){
    for(i=0; zText[i] && zText[i]!='%'; i++){}
    if( i>0 ) cgi_append_content(zText, i);
    if( zText[i]==0 ) break;
    switch( zText[i+1] ){
      case 'T':
        zText += i+2;
        cgi_printf("%h", zTitle);
        break;
      case 'N':
        zText += i+2;
        cgi_printf("%h", g.zName);
        break;
      case 'V':
        zText += i+2;
        cgi_printf("%h", "@VERSION@");
        break;
      case 'B':
        zText += i+2;
        cgi_printf("%h", g.zBaseURL);
        break;
      case 'D':
        {
          char *zQS = getenv("QUERY_STRING");
          zText += i+2;
          cgi_printf("%h%h%h", g.zPath,
            (zQS && *zQS) ? "?" : "",
            (zQS && *zQS) ? zQS : zQS
          );
        }
        break;
      case '%':
        zText += i+2;
        cgi_printf("%%");
        break;
      default:
        zText += i+1;
        cgi_printf("%%");
        break;
    }
  }
}

/*
** Read the whole contents of a file into memory obtained from
** malloc().  Return a pointer to the file contents.  Be sure
** the string is null terminated.
**
** A NULL pointer is returned if the file could not be read
** for any reason.
*/
char *common_readfile(const char *zFilename) {
  FILE *fp;
  char *zContent = NULL;
  size_t n;

  if ((fp = fopen(zFilename, "r")) != NULL) {
    fseek(fp, 0, SEEK_END);
    if ((n = ftell(fp)) > 0) {
      if ((zContent = (char *)malloc(n+1)) == NULL) {
        fclose(fp);
        return NULL;
      }
      fseek(fp, 0, SEEK_SET);
      if ((n = fread(zContent, 1, n, fp)) == 0) {
        free(zContent);
        fclose(fp);
        return NULL;
      }
      zContent[n] = '\0';
    }
    else {
      zContent = strdup("");
    }
    fclose(fp);
  }
  return zContent;
}

/*
** Read the whole contents of a file pointer into memory obtained from
** malloc().  Return a pointer to the file contents.  Be sure
** the string is null terminated.
**
** A NULL pointer is returned if the file could not be read
** for any reason. The caller is responsible for closing the file.
*/
char *common_readfp(FILE* fp) {
  char *zContent = NULL;
  char *z;
  size_t n = 0, m = 0;
  size_t rc;

  while( fp && !feof(fp) && !ferror(fp) ) {
    if( (n+1)>=m ){
      m = m ? (m*2) : 1024;
      z = realloc(zContent, m);
      if( z==NULL ){
        if( zContent!=NULL ) free(zContent);
        return NULL;
      }
      zContent = z;
    }
    rc = fread(&zContent[n], 1, m-(n+1), fp);
    if( rc>0 ){
      n += rc;
    }
    zContent[n] = 0;
  }

  return zContent;
}

/*
** Generate an error message screen.
*/
void common_err(const char *zFormat, ...){
  char *zMsg;

  va_list ap;
  va_start(ap, zFormat);
  zMsg = vmprintf(zFormat, ap);
  va_end(ap);
  cgi_reset_content();
  common_standard_menu(0,0);
  common_header("Oops!");
  @ <div class="error">
  @ <p>The following error has occurred:</p>
  @ <blockquote>%h(zMsg)</blockquote>
  if( g.okSetup ){
    @ <p>Query parameters:<p>
    cgi_print_all();
  }
  @ </div>
  common_footer();
  cgi_append_header("Pragma: no-cache\r\n");
  cgi_reply();
  exit(0);
}

/*
** The menu on the top bar of every page is defined by the following
** variables. Links are navigation links to other pages. Actions are
** links which apply to the current page.
*/
static const char *azLink[50];
static int nLink = 0;
static char *zOmitLink = NULL;

static const char *azAction[50];
static int nAction = 0;


const char *default_browse_url(void){
  if( !strncmp(g.zPath,"dir",3) ) {
    /* If the _current_ path is already a browse path, go with it */
    return g.zPath;
  }else{
    /* If cookie is set, it overrides default setting */
    char *zBrowseUrlCookieName = mprintf("%t_browse_url",g.zName);
    const char *zCookieValue = P(zBrowseUrlCookieName);
    free(zBrowseUrlCookieName);

    if( zCookieValue ) {
      if( !strcmp("dir",zCookieValue) ){
        return "dir";
      }else if( !strcmp("dirview",zCookieValue) ){
        return "dirview";
      }
    }
  }
  return db_config("default_browse_url","dir");
}

/*
** Prepopulate the set of navigation items with a standard set that includes
** links to all top-level pages except for zOmit.  If zOmit is NULL then
** include all items.
**
** If zSrchUrl is not NULL then use it as the URL for the "Search" menu
** option.
*/
void common_standard_menu(const char *zOmit, const char *zSrchUrl){
  const char *zLimit;
  if( g.okNewTkt ){
    azLink[nLink++] = "tktnew";
    azLink[nLink++] = "Ticket";
  }
  if( g.okCheckout ){
    azLink[nLink++] = default_browse_url();
    azLink[nLink++] = "Browse";
  }
  if( g.okRead ){
    azLink[nLink++] = "reportlist";
    azLink[nLink++] = "Reports";
  }
  if( g.okRdWiki || g.okRead || g.okCheckout ){
    azLink[nLink++] = "timeline";
    azLink[nLink++] = "Timeline";
  }
  if( g.okRdWiki ){
    azLink[nLink++] = "wiki";
    azLink[nLink++] = "Wiki";
  }
  if( g.okRdWiki || g.okRead || g.okCheckout ){
    azLink[nLink++] = zSrchUrl ? zSrchUrl : "search";
    azLink[nLink++] = "Search";
  }
  if( g.okCheckin ){
    azLink[nLink++] = "msnew";
    azLink[nLink++] = "Milestone";
  }
  if( g.okWrite && !g.isAnon ){
    azLink[nLink++] = "userlist";
    azLink[nLink++] = "Users";
  }
  if( g.okAdmin ){
    azLink[nLink++] = "setup";
    azLink[nLink++] = "Setup";
  }
  azLink[nLink++] = "login";
  if( g.isAnon ){
    azLink[nLink++] = "Login";
  }else{
    azLink[nLink++] = "Logout";
  }
  if( g.isAnon && (zLimit = db_config("throttle",0))!=0 && atof(zLimit)>0.0 ){
    azLink[nLink++] = "honeypot";
    azLink[nLink++] = "0Honeypot";
  }
  if( nLink>2 ){
    azLink[nLink++] = "index";
    azLink[nLink++] = "Home";
  }
  azLink[nLink] = 0;

  zOmitLink = zOmit ? mprintf("%s",zOmit) : NULL;
}

/*
** Add a new navigation entry to the menu that will appear at the top of the
** page.  zUrl is the URL that we jump to when the user clicks on
** the link and zName is the text that appears in the link.
*/
void common_add_nav_item(
  const char *zUrl,      /* The URL to be appended */
  const char *zName      /* The menu entry name */
){
  azLink[nLink++] = zUrl;
  azLink[nLink++] = zName;
  azLink[nLink] = 0;
}

/*
** Add a new action entry to the menu that will appear at the top of the
** page.  zUrl is the URL that we jump to when the user clicks on
** the link and zName is the text that appears in the link.
*/
void common_add_action_item(
  const char *zUrl,      /* The URL to be appended */
  const char *zName      /* The menu entry name */
){
  azAction[nAction++] = zUrl;
  azAction[nAction++] = zName;
  azAction[nAction] = 0;
}

/*
** Add a "help" link to a specific Wiki page. Currently, we place the help
** link in the "link" section rather than "action" section, although arguably
** it's context dependent. However, there should be a help link on pretty much
** any page, so...
*/
void common_add_help_item(
    const char *zWikiPage     /* name of the help page */
){
  if( g.okRdWiki
      && db_exists("SELECT 1 FROM wiki WHERE name='%q'", zWikiPage)){
    azLink[nLink++] = mprintf("wiki?p=%s", zWikiPage);
    azLink[nLink++] = "Help";
    azLink[nLink] = 0;
  }
}

/*
** Replace an existing navigation item with the new version given here.
** We don't have a corresponding function for the action menu since it's
** never prepopulated.
*/
void common_replace_nav_item(
  const char *zUrl,      /* The new URL */
  const char *zName      /* The menu entry name to be replaced */
){
  int i;
  for(i=0; i<nLink; i+=2){
    if( strcmp(azLink[i+1],zName)==0 ){
      if( zUrl==0 ){
        azLink[i] = azLink[nLink-2];
        azLink[i+1] = azLink[nLink-1];
        nLink--;
      }else{
        azLink[i] = zUrl;
      }
      break;
    }
  }
}

/*
** Function used for sorting entries in azLinks[]
*/
static int link_compare(const void *a, const void *b){
  const char **pA = (const char **)a;
  const char **pB = (const char **)b;
  return strcmp(pA[1], pB[1]);
}

/*
** Generate an HTML header common to all web pages.  zTitle is the
** title for the page, zUrl (optional) is the link for that title.
** azLink is an array of URI/Name pairs that
** are used to generate navigation quick-links on the title bar. azAction
** is an array of context-dependent actions applicable to the current page.
*/
void common_vlink_header(const char *zUrl, const char *zTitle, va_list ap){
  int i = 0;
  const char *zHeader = 0;
  char *zTitleTxt;

  zTitleTxt = vmprintf(zTitle, ap);
  zHeader = db_config("header", HEADER);
  if( zHeader && zHeader[0] ){
    char *z;
    if( zHeader[0]=='/' && (z = common_readfile(zHeader))!=0 ){
      zHeader = z;
    }
    output_with_subst(zHeader, zTitleTxt);
  }else{
    output_with_subst(HEADER, zTitleTxt);
  }

  /* "header" groups everything at the top */
  @ <div id="header">

  @ <h1 id="title">
  /* tannenba - remove zName from title */
  if( zUrl ){
    @ <a rel="nofollow" href="%h(zUrl)">%h(zTitleTxt)</a>
  }else{
    @ %h(zTitleTxt)
  }
  @ </h1>

  free(zTitleTxt);

  @ <p id="identity">
  if( !g.isAnon ){
    @ <a href="logout" title="Logout %h(g.zUser)">Logged in</a> as
    output_user(g.zUser);
  }else{
    /* We don't want to be redirected back to captcha page, but rather to 
    ** one from which we were redirected to captcha in the first place.
    */
    const char *zUri = (P("nxp")!=0) ? P("nxp") : getenv("REQUEST_URI");
    @ <a href="honeypot"><notatag arg="meaningless"></a>
    @ <a href="login?nxp=%T(zUri)" title="Log in">Not logged in</a>
  }
  @ </p>

  if( nLink ){
    nLink /= 2;
    qsort(azLink, nLink, 2*sizeof(azLink[0]), link_compare);
    @ <ul id="navigation">
    for(i=0; azLink[i] && azLink[i+1]; i+=2){
      const char *z = azLink[i+1];
      if( z[0]<'A' ) z++;
      if( zOmitLink && !strcmp(zOmitLink,azLink[i]) ){
        @ <li id="current"><a href="%h(azLink[i])">%h(z)</a></li>
      }else{
        @ <li><a href="%h(azLink[i])">%h(z)</a></li>
      }
    }
    @ </ul>
  }

  if( nAction ){
    nAction /= 2;
    qsort(azAction, nAction, 2*sizeof(azAction[0]), link_compare);
    @ <ul id="action">
    for(i=0; azAction[i] && azAction[i+1]; i+=2){
      const char *z = azAction[i+1];
      if( z[0]<'A' ) z++;
      @ <li><a href="%h(azAction[i])" rel="nofollow">%h(z)</a></li>
    }
    @ </ul>
  }
  @ </div>

  @ <div id="content">
}

/*
** Generate an HTML header common to all web pages.  zTitle is the
** title for the page, zUrl (optional) is the link for that title.
*/
void common_link_header(const char *zUrl, const char *zTitle,...){
  va_list ap;
  va_start(ap,zTitle);
  assert(zUrl != NULL);
  common_vlink_header(zUrl,zTitle,ap);
  va_end(ap);
}

/*
** Generate an HTML header common to all web pages.  zTitle is the
** title for the page.
*/
void common_header(const char *zTitle,...){
  va_list ap;
  va_start(ap,zTitle);
  common_vlink_header(NULL,zTitle,ap);
  va_end(ap);
}

/*
** Generate a common footer
*/
void common_footer(void){
  const char *zFooter;
  @ </div>
  zFooter = db_config("footer", FOOTER);
  if( zFooter && zFooter[0] ){
    char *z;
    if( zFooter[0]=='/' && (z = common_readfile(zFooter))!=0 ){
      zFooter = z;
    }
    output_with_subst(zFooter, "");
  }else{
    output_with_subst(FOOTER, "");
  }
}

/*
** Generate an about screen
**
** WEBPAGE: /about
*/
void common_about(void){
  login_check_credentials();
  common_add_nav_item("index", "Home");
  common_header("About This Server", azLink);
  @ <p>This website is implemented using CVSTrac version @VERSION@.</p>
  @
  @ <p>CVSTrac implements a patch-set and
  @ bug tracking system for %h(g.scm.zName).
  @ For additional information, visit the CVSTrac homepage at</p>
  @ <blockquote>
  @ <a href="http://www.cvstrac.org/">http://www.cvstrac.org/</a>
  @ </blockquote>
  @
  @ <p>Copyright &copy; 2002-2006 <a href="mailto:drh@hwaci.com">
  @ D. Richard Hipp</a>.
  @ The CVSTrac server is released under the terms of the GNU
  @ <a href="http://www.gnu.org/copyleft/gpl.html">
  @ General Public License</a>.</p>
  common_footer(); 
}

/*
** Generate an "icon".
*/
void common_icon(const char* zIcon){
  @ <span class="icon %h(zIcon)">&nbsp;</span>\
}
