/*
** System header files used by all modules
*/
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <stdarg.h>
#include <sqlite3.h>
#include <assert.h>
#if defined(__linux__) || defined(__sun__)
#include <crypt.h>
#endif
#if defined(_WIN32) || defined(WIN32) || defined(__CYGWIN__) || defined(__MINGW32__) || defined(__BORLANDC__)
/* MinGW headers have no consts so producing warnings "discards qualifiers" */
char *crypt(const char *key, const char *salt);
#include <process.h>
#include <direct.h>
#include <io.h>
#endif

/*
** Standard colors.  These colors can also be changed using a stylesheet.
*/

/* A blue border and background.  Used for the title bar and for dates
** in a timeline.
*/
#define BORDER1       "#a0b5f4"      /* Stylesheet class: border1 */
#define BG1           "#d0d9f4"      /* Stylesheet class: bkgnd1 */

/* A red border and background.  Use for releases in the timeline.
*/
#define BORDER2       "#ec9898"      /* Stylesheet class: border2 */
#define BG2           "#f7c0c0"      /* Stylesheet class: bkgnd2 */

/* A gray background.  Used for column headers in the Wiki Table of Contents
** and to highlight ticket properties.
*/
#define BG3           "#d0d0d0"      /* Stylesheet class: bkgnd3 */

/* A light-gray background.  Used for title bar, menus, and rlog alternation
*/
#define BG4           "#f0f0f0"      /* Stylesheet class: bkgnd4 */

/* A deeper gray background.  Used for branches
*/
#define BG5           "#dddddd"      /* Stylesheet class: bkgnd5 */

/* Default HTML page header */
#define HEADER "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">\n" \
               "<html>\n" \
               "<head>\n" \
               "<link rel=\"stylesheet\" title=\"CVSTrac Stylesheet\"\n" \
               "      type=\"text/css\" href=\"%B/cvstrac.css\">\n" \
               "<link rel=\"alternate stylesheet\"\n" \
               "      title=\"Default Stylesheet\"\n" \
               "      type=\"text/css\" href=\"%B/cvstrac_default.css\">\n" \
               "<link rel=\"alternate\" type=\"application/rss+xml\"\n" \
               "   title=\"%N Timeline Feed\" href=\"%B/timeline.rss\">\n" \
               "<link rel=\"index\" title=\"Index\" href=\"%B/index\">\n" \
               "<link rel=\"search\" title=\"Search\" href=\"%B/search\">\n" \
               "<link rel=\"help\" title=\"Help\"\n" \
               "   href=\"%B/wiki?p=CvstracDocumentation\">\n" \
               "<title>%N: %T</title>\n</head>\n" \
               "<body>"

/* Default HTML page footer */
#define FOOTER "<div id=\"footer\">\n" \
               "<a href=\"about\">CVSTrac version %V</a>\n" \
               "</div>\n" \
               "</body></html>\n"

/*
** Defaults for the wikitext input
** textarea for entering wiki-markup: should be either "physical" or "virtual"
*/
#define WIKI_TEXTAREA_WRAP         "virtual"
#define WIKI_TEXTAREA_ROWS         "30"
#define WIKI_TEXTAREA_COLS         "70"

/* In the timeline, check-in messages are truncated at the first space
** that is more than MX_CKIN_MSG from the beginning, or at the first
** paragraph break that is more than MN_CKIN_MSG from the beginning.
*/
#define MN_CKIN_MSG   100
#define MX_CKIN_MSG   300

/* Maximum number of seconds for any HTTP or CGI handler to live. This
** prevents denials of service caused by bad queries, endless loops, or
** other possibilties.
*/
#define MX_CHILD_LIFETIME 300

/* If defined, causes the query_authorizer() function to return SQLITE_DENY on
** invalid calls rather than just SQLITE_IGNORE. This is not recommended for
** production use since it's basically a denial of service waiting to happen,
** but CVSTrac developers _should_ enable it to catch incorrect use of
** db_query calls (i.e. using them for something other than SELECT).
*/
/* #define USE_STRICT_AUTHORIZER 1 */

/* Unset the following to disable internationalization code. */
#ifndef CVSTRAC_I18N
# define CVSTRAC_I18N 1
#endif

#if CVSTRAC_I18N
# include <locale.h>
# include <langinfo.h>
#endif
#ifndef CODESET
# undef CVSTRAC_I18N
# define CVSTRAC_I18N 0
#endif

/* CVSTrac may run on Windows environment, however it requires some tweaks
** that are related to UNIX incompatibilities such as slashes, device names, etc.
** Those fixes also affect running CVSTrac on IIS.
**
** OS_VAL macro is being used to define constants that have different values
** on UNIX and Windows platforms. This macro simplyfies all platform dependent
** code.
*/
#if defined(_WIN32) || defined(WIN32) || defined(__CYGWIN__) || defined(__MINGW32__) || defined(__BORLANDC__)
# define CVSTRAC_WINDOWS
# define OS_VAL(unix, win) win
#else
# define OS_VAL(unix, win) unix
#endif
