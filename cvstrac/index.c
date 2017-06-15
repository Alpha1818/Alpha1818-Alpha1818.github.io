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
** Code to generate the index page
*/
#include "config.h"
#include "index.h"

/*
** Return TRUE if the given string contains at least one non-space
** character
*/
static int not_blank(const char *z){
  while( isspace(*z) ){ z++; }
  return *z!=0;
}

/*
** WEBPAGE: /
** WEBPAGE: /index
** WEBPAGE: /index.html
** WEBPAGE: /mainmenu
*/
void index_page(void){
  int cnt = 0;
  login_check_credentials();
  common_standard_menu("index", 0);

  common_add_help_item("CvstracDocumentation");

  /* If the user has wiki read permission and a wiki page named HomePage
  ** exists and is not empty and is locked (meaning that only an 
  ** administrator could have created it), then use that page as the
  ** main menu rather than the built-in main menu.
  **
  ** The built-in main menu is always reachable using the /mainmenu URL
  ** instead of "/index" or "/".
  */
  if( g.okRdWiki && g.zPath[0]!='m' ){
    char *zBody = db_short_query(
        "SELECT text FROM wiki WHERE name='HomePage' AND locked");
    if( zBody && not_blank(zBody) ){
      common_add_nav_item("mainmenu", "Main Menu");
      common_header("Home Page");
      /* menu_sidebar(); */
      output_wiki(zBody, "", "HomePage");
      common_footer();
      return;
    }
  }

  /* Render the built-in main-menu page.
  */
  common_header("Main Index");
  @ <dl id="index">
  if( g.zPath[0]=='m' ){
    @ <dt>
    @ <a href="index"><b>Home Page</b></a>
    @ </dt>
    @ <dd>
    @ View the Wiki-based homepage for this project.
    @ </dd>
    @
    cnt++;
  }
  if( g.okNewTkt ){
    @ <dt>
    @ <a href="tktnew"><b>Ticket</b></a>
    @ </dt>
    @ <dd>
    @ Create a new Ticket with a defect report or enhancement request.
    @ </dd>
    @
    cnt++;
  }
  if( g.okCheckout ){
    @ <dt>
    @ <a href="%h(default_browse_url())"><b>Browse</b></a>
    @ </dt>
    @ <dd>
    @ Browse the %s(g.scm.zName) repository tree.
    @ </dd>
    @
    cnt++;
  }   
  if( g.okRead ){
    @ <dt>
    @ <a href="reportlist"><b>Reports</b></a>
    @ </dt>
    @ <dd>
    @ View summary reports of Tickets.
    @ </dd>
    @
    cnt++;
  }
  if( g.okRdWiki || g.okRead || g.okCheckout ){
    @ <dt>
    @ <a href="timeline"><b>Timeline</b></a>
    @ </dt>
    @ <dd>
    @ View a chronology of changes.
    @ </dd>
    @ 
    cnt++;
  }
  if( g.okRdWiki ){
    @ <dt>
    @ <a href="wiki"><b>Wiki</b></a>
    @ </dt>
    @ <dd>
    @ View the Wiki documentation pages.
    @ </dd>
    cnt++;
  }
  if( g.okRead || g.okCheckout || g.okRdWiki ){
    const char *az[5];
    int n=0;
    if( g.okRead ) az[n++] = "Tickets";
    if( g.okCheckout ) az[n++] = "Check-ins";
    if( g.okRdWiki ) az[n++] = "Wiki pages";
    if( g.okCheckout ) az[n++] = "Filenames";
    @ <dt>
    @ <a href="search"><b>Search</b></a>
    @ </dt>
    @ <dd>
    if( n==4 ){
      @ Search for keywords in %s(az[0]), %s(az[1]), %s(az[2]), and/or %s(az[3])
    }else if( n==3 ){
      @ Search for keywords in %s(az[0]), %s(az[1]), and/or %s(az[2])
    }else if( n==2 ){
      @ Search for keywords in %s(az[0]) and/or %s(az[1])
    }else{
      @ Search for keywords in %s(az[0])
    }
    @ </dd>
    @
    cnt++;
  }
  if( g.okCheckin ){
    @ <dt>
    @ <a href="msnew"><b>Milestones</b></a>
    @ </dt>
    @ <dd>
    @ Create new project milestones.
    @ </dd>
    @ 
    cnt++;
  }
  if( g.okWrite && !g.isAnon ){
    @ <dt>
    @ <a href="userlist"><b>User</b></a>
    @ </dt>
    @ <dd>
    @ Create, edit, and delete users.
    @ </dd>
    @ 
    cnt++;
  }
  if( g.okAdmin ){
    @ <dt>
    @ <a href="setup"><b>Setup</b></a>
    @ </dt>
    @ <dd>
    @ Setup global system parameters.
    @ </dd>
    @ 
    cnt++;
  }
  if( g.okRdWiki ){
    @ <dt>
    @ <a href="wiki?p=CvstracDocumentation"><b>Documentation</b></a>
    @ </dt>
    @ <dd>
    @ Read the online manual.
    @ </dd>
    @
    cnt++;
  }
  if( g.isAnon ){
    if( cnt==0 ){
      login_needed();
      return;
    }
    @ <dt>
    @ <a href="login"><b>Login</b></a>
    @ </dt>
    @ <dd>
    @ Log in.
    @ </dd>
    @ 
  }else{
    @ <dt>
    @ <a href="logout"><b>Logout</b></a>
    @ </dt>
    @ <dd>
    @ Log off or change password.
    @ </dd>
    @ 
  }
  @ </dl>
  @ 
  common_footer();
}
