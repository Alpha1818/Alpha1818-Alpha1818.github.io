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
** Routines for handling user account
*/
#define _XOPEN_SOURCE
#include <unistd.h>
#include "config.h"
#include "user.h"




/*void default_account(void){
   login_check_credentials();
  if( !g.okWrite && g.isAnon ){
    login_needed();
    return;
  }
  common_standard_menu("userlist", 0);
  common_add_help_item("CvstracAdminUsers");
  common_add_action_item("useredit", "Add User");

  common_footer();
}*/
/*
** WEBPAGE: /userlist
*/
void user_list(void){
  char **azResult;
  int i;

  login_check_credentials();
  if( !g.okWrite && g.isAnon ){
    login_needed();
    return;
  }
  common_standard_menu("userlist", 0);
  common_add_help_item("CvstracAdminUsers");
  common_add_action_item("useredit", "Add User");
  common_header("User List");
  @ <table cellspacing=0 cellpadding=0 border=0>
  @ <tr>
  @   <th align="right" class="nowrap">User ID</th>
  @   <th>&nbsp;&nbsp;&nbsp;Permissions&nbsp;&nbsp;&nbsp;</th>
  @   <th class="nowrap">In Real Life</th>
  @ </tr>
  azResult = db_query(
    "SELECT id, name, email, capabilities FROM user ORDER BY id");
  for(i=0; azResult[i]; i+= 4){
    @ <tr>
    @ <td align="right">
    if( g.okAdmin ){
      @ <a href="useredit?id=%t(azResult[i])">
    }
    @ <span class="nowrap">%h(azResult[i])</span>
    if( g.okAdmin ){
      @ </a>
    }
    @ </td>
    @ <td align="center">%s(azResult[i+3])</td>
    if( azResult[i+2] && azResult[i+2][0] ){
      char *zE = azResult[i+2];
      @ <td align="left" class="nowrap">%h(azResult[i+1])
      @    (<a href="mailto:%h(zE)">%h(zE)</a>)</td>
    } else {
      @ <td align="left" class="nowrap">%h(azResult[i+1])</td>
    }
    @ </tr>
  }
  @ </table>
  @ <hr>
  @ <p><b>Notes:</b></p>
  @ <ol>
  @ <li><p>The permission flags are as follows:</p>
  @ <table>
  @ <tr><td>a</td><td width="10"></td>
  @     <td>Admin: Create or delete users and ticket report formats</td></tr>
  @ <tr><td>d</td><td></td>
  @     <td>Delete: Erase anonymous wiki, tickets, and attachments</td></tr>
  @ <tr><td>i</td><td></td>
  @     <td>Check-in: A Contributors License Agreement (CLA) signed by this user has been filed (required to add anything to %h(g.scm.zName)) </td></tr>
  @ <tr><td>j</td><td></td><td>Read-Wiki: View wiki pages</td></tr>
  @ <tr><td>k</td><td></td><td>Wiki: Create or modify wiki pages</td></tr>
  @ <tr><td>n</td><td></td><td>New: Create new tickets</td></tr>
  @ <tr><td>o</td><td></td>
  @     <td>Check-out: Read code out of the %h(g.scm.zName) repository</td></tr>
  @ <tr><td>p</td><td></td><td>Password: Change password</td></tr>
  @ <tr><td>q</td><td></td><td>Query: Create or edit report formats</td></tr>
  @ <tr><td>r</td><td></td><td>Read: View tickets and change histories</td></tr>
  @ <tr><td>s</td><td></td><td>Setup: Change CVSTrac options</td></tr>
  @ <tr><td>w</td><td></td><td>Write: Edit tickets</td></tr>
  @ </table>
  @ </li>
  @
  @ <li><p>
  @ If a user named "<b>anonymous</b>" exists, then anyone can access
  @ the server without having to log in.  The permissions on the
  @ anonymous user determine the access rights for anyone who is not
  @ logged in.
  @ </p></li>
  @
  if( !strcmp(g.scm.zSCM,"cvs") ){
    @ <li><p>
    @ You must be using CVS version 1.11 or later in order to give users
    @ read-only access to the repository.
    @ With earlier versions of CVS, all users with check-out
    @ privileges also automatically get check-in privileges.
    @ </p></li>
    @
    @ <li><p>
    @ Changing a users ID or password modifies the <b>CVSROOT/passwd</b>,
    @ <b>CVSROOT/readers</b>, and <b>CVSROOT/writers</b> files in the CVS
    @ repository, if those files have write permission turned on.  Users
    @ IDs in <b>CVSROOT/passwd</b> that are unknown to CVSTrac are preserved.
    if( g.okSetup ){
      @ Use the "Import CVS Users" button on the 
      @ <a href="setup_user">user setup</a> page
      @ to import CVS users into CVSTrac.
    }
    @ </p></li>
  }
  @ </ol>
  common_footer();
}

/*
** WEBPAGE: /useredit
*/
void user_edit(void){
  char **azResult;
  const char *zId, *zName, *zEMail, *zCap;
  char *oaa, *oas, *oar, *oaw, *oan, *oai, *oaj, *oao, *oap ;
  char *oak, *oad, *oaq;
  /*name used in the newly added functions searchPHRASE: 608504*/
  /*const char *name_account, *id_card, *email_account, *cap_account, *pass_account;*/
   /*name used in the newly added functions searchPHRASE: 608504*/
  int doWrite;
  int higherUser = 0;  /* True if user being edited is SETUP and the */
                       /* user doing the editing is ADMIN.  Disallow editing */
#ifdef CVSTRAC_WINDOWS
  char *odl;           /* Domain login - used by "use Windows password" feature */
#endif

  /* Must have ADMIN privleges to access this page
  */
  login_check_credentials();
  if( !g.okAdmin ){ login_needed(); return; }

  /* Check to see if an ADMIN user is trying to edit a SETUP account.
  ** Don't allow that.
  */
  zId = P("id");
  if( zId && !g.okSetup ){
    char *zOldCaps;
    zOldCaps = db_short_query(
       "SELECT capabilities FROM user WHERE id='%q'",zId);
    higherUser = zOldCaps && strchr(zOldCaps,'s');
  }

  if( !higherUser ){
    if( P("delete") ){
      common_add_action_item("userlist", "Cancel");
      common_header("Are You Sure?");
      @ <form action="userlist" method="POST">
      @ <p>You are about to delete the user <strong>%h(zId)</strong> from
      @ the database.  This is an irreversible operation.</p>
      @
      login_output_csrf_token();
      @ <input type="hidden" name="id" value="%h(zId)">
      @ <input type="hidden" name="nm" value="">
      @ <input type="hidden" name="em" value="">
      @ <input type="hidden" name="pw" value="">
      @ <input type="submit" name="delete2" value="Delete The User">
      @ <input type="submit" name="can" value="Cancel">
      @ </form>
      common_footer();
      return;
    }else if( P("can") ){
      cgi_redirect("userlist");
      return;
    }
    /*

          the checkin code goes here


    */
    if(P("default_account23")){
      common_add_action_item("userlist", "Cancel");
      common_header("check-in association with a ticket");
      @ <form action="useredit?applyEntryAccount23=1" method="POST">
      @ <tr>
      @   <td align="right" class="nowrap">ticketNumber:</td>
      @   <td><input type="text" name="tick_number" value=""></td>
      @ </tr>
       @ <tr>
    @    <td>&nbsp;</td>
    @    <td><input type="submit" name="createEntry" value="Apply" >
    @    &nbsp;&nbsp;&nbsp;
    @ </tr>
    return;

    }
    if(P("applyEntryAccount23")){
      const char* trial23 = P("tick_number");
      xref_add_checkin_comment(6496, trial23);
      cgi_redirect("http://localhost:7600/rptview?rn=4&Type=ALL&Status=ALL&Subsys=ALL&Group=ALL&Visibility=ALL&Created_By=battula&Assigned_To=ALL");
      return;
    }
    if(P("default_account")){

      /*initializing and declaring variables*/
        
        
        
        
        
     /*initializing and declaring variables*/

      common_add_action_item("userlist", "Cancel");
      common_header("Open An Entry Account");
      
      login_output_csrf_token();
     @ <form action="useredit?applyEntryAccount=1" method="POST">
      @ <table align="left" style="margin: 10px;">
      @ <tr>
      @   <td align="right" class="nowrap">User ID:</td>
      if( zId ){
      @   <td>%h(zId) <input type="hidden" name="userId" value="%h(zId)"></td>
      }else{
      @   <td><input type="text" name="userId" size=10></td>
    }
      @ </tr>

      @ <tr>
      @   <td align="right" class="nowrap">Password:</td>
      @   <td><input type="password" name="passwordz" value=""></td>
      @ </tr>
      @ <tr>
      @   <td align="right" class="nowrap">Full Name:</td>
      @   <td><input type="text" name="namez" value=""></td>
      @ </tr>
      @ <tr>
      @   <td align="right" class="nowrap">E-Mail:</td>
      @   <td><input type="text" name="emailz" value=""></td>
      @ </tr>
       



    @ <tr>
    @    <td>&nbsp;</td>
    @    <td><input type="submit" name="createEntry" value="Apply" >
    @    &nbsp;&nbsp;&nbsp;
    @ </tr>
    @</table>
    
   common_footer();
    
      return;
    }
   /* int bool=0;
    if(strcmp(P("userId"),"")!=0 && strcmp(P("namez"),"")!=0 && strcmp(P("emailz"), "")!=0 && strcmp(P("passwordz"), "")!=0 && 
        cgi_all("namez","emailz","passwordz")){
      bool =1;
    }*/
    if(P("applyEntryAccount")/* && bool==1*/){
      char zCap1[20];
      int i1 = 0;
      zCap1[i1++] = 'j';
      zCap1[i1++] = 'r';
      zCap1[i1++] = 'p';
      zCap1[i1++] = 'q';
      zCap1[i1++] = 'n';
     /* const char* trial = P("tick_number");
      
      xref_add_checkin_comment(6486, trial);*/
      db_execute("DELETE FROM user WHERE id='%q'", P("userId"));
      //@ <p><b>UserId: %s(P("userId")) full name: %s(P("namez")) email id: %s(P("emailz")) </b></p>
      if(strcmp(P("userId"),"")!=0 && strcmp(P("namez"),"")!=0 && strcmp(P("emailz"), "")!=0 && strcmp(P("passwordz"), "")!=0 && 
        cgi_all("namez","emailz","passwordz")/* && (checkDup==0)*/){
       // @<p> user id: %s(P("userId")) </p>
       
        
     
          db_execute(
            "INSERT INTO user(id,name,email,passwd,capabilities)" 
           "VALUES('%q','%q','%q','%q','%s')",
             P("userId"), P("namez"), P("emailz"), P("passwordz"), zCap1
          );



       cgi_redirect("userlist");
        return;
    }
    else{
         //if( g.scm.pxUserWrite ) g.scm.pxUserWrite(P("delete2")!=0 ? zId : 0);
      common_add_action_item("userlist", "Cancel");
      common_header("Open An Entry Account");
         db_execute( "DELETE FROM config WHERE "
          "  name='assignto' AND value='%q'",P("userId") );

        // @<button onclick="goBack()">Go Back</button>
          //@<p>this is a trial %s(trial)</p>
        @<script>
       
        @window.history.back();
       
        @</script>
         
         return;

      
    }
      
      return;
    }
  }

  /* If we have all the necessary information, write the new or
  ** modified user record.  After writing the user record, redirect
  ** to the page that displays a list of users.
  */
  doWrite = zId && zId[0] && cgi_all("nm","em","pw") && !higherUser;
  if( doWrite ){
    const char *zOldPw;
    char zCap[20];
    int i = 0;
#ifdef CVSTRAC_WINDOWS
    int dl = P("dl")!=0;
#endif
    int aa = P("aa")!=0;
    int ad = P("ad")!=0;
    int ai = P("ai")!=0;
    int aj = P("aj")!=0;
    int ak = P("ak")!=0;
    int an = P("an")!=0;
    int ao = P("ao")!=0;
    int ap = P("ap")!=0;
    int aq = P("aq")!=0;
    int ar = P("ar")!=0;
    int as = g.okSetup && P("as")!=0;
    int aw = P("aw")!=0;
    zOldPw = db_short_query("SELECT passwd FROM user WHERE id='%q'", zId);
    if( as ) aa = 1;
#ifdef CVSTRAC_WINDOWS
    /* If the admin is using external password auth
    ** don't let password change automatically
    */
    if( !dl && aa ) ai = aw = ap = 1;
    else
#endif
    if( aa ) ai = aw = 1;
    if( aw ) an = ar = 1;
    if( ai ) ao = 1;
    if( ak ) aj = 1;
    if( aa ){ zCap[i++] = 'a'; }
    if( ad ){ zCap[i++] = 'd'; }
    if( ai ){ zCap[i++] = 'i'; }
    if( aj ){ zCap[i++] = 'j'; }
    if( ak ){ zCap[i++] = 'k'; }
    if( an ){ zCap[i++] = 'n'; }
    if( ao ){ zCap[i++] = 'o'; }
    if( ap ){ zCap[i++] = 'p'; }
    if( aq ){ zCap[i++] = 'q'; }
    if( ar ){ zCap[i++] = 'r'; }
    if( as ){ zCap[i++] = 's'; }
    if( aw ){ zCap[i++] = 'w'; }

    login_check_csrf_token();

    zCap[i] = 0;
    db_execute("DELETE FROM user WHERE id='%q'", zId);
    if( !P("delete2") ){
      const char *zPw = P("pw");
      char zBuf[3];
      if( zOldPw==0 ){
        char zSeed[100];
        const char *z;
        bprintf(zSeed,sizeof(zSeed),"%d%.20s",getpid(),zId);
        z = crypt(zSeed, "aa");
        zBuf[0] = z[2];
        zBuf[1] = z[3];
        zBuf[2] = 0;
        zOldPw = zBuf;
      }
      db_execute(
         "INSERT INTO user(id,name,email,passwd,capabilities) "
         "VALUES('%q','%q','%q','%q','%s')",
         zId, P("nm"), P("em"), OS_VAL(0, dl) ? "*" : zPw[0] ? crypt(zPw, zOldPw) : zOldPw, zCap
      );
    }else{
      /* User may have been default assigned user id. Remove the default
      ** if that was the case.
      */
      db_execute( "DELETE FROM config WHERE "
          "  name='assignto' AND value='%q'", zId);
    }

    /*
    ** The SCM subsystem may be able to replicate the user db somewhere...
    */
    if( g.scm.pxUserWrite ) g.scm.pxUserWrite(P("delete2")!=0 ? zId : 0);

    cgi_redirect("userlist");
    return;
  }

  /* Load the existing information about the user, if any
  */
  zName = "";
  zEMail = "";
  zCap = "";
  oaa = oad = oai = oaj = oak = oan = oao = oap = oaq = oar = oas = oaw = "";
#ifdef CVSTRAC_WINDOWS
  odl = "";
#endif
  if( zId ){
#ifdef CVSTRAC_WINDOWS
    /* "use Windows password" shall be checked when password is set to "*" */
    const char *zOldPw = db_short_query("SELECT passwd FROM user WHERE id='%q'", zId);
    if(zOldPw != 0 && zOldPw[0] == '*' && zOldPw[1] == 0) odl = " checked";
#endif
    azResult = db_query(
      "SELECT name, email, capabilities FROM user WHERE id='%q'", zId
    );
    if( azResult && azResult[0] ){
      zName = azResult[0];
      zEMail = azResult[1];
      zCap = azResult[2];
      if( strchr(zCap, 'a') ) oaa = " checked";
      if( strchr(zCap, 'd') ) oad = " checked";
      if( strchr(zCap, 'i') ) oai = " checked";
      if( strchr(zCap, 'j') ) oaj = " checked";
      if( strchr(zCap, 'k') ) oak = " checked";
      if( strchr(zCap, 'n') ) oan = " checked";
      if( strchr(zCap, 'o') ) oao = " checked";
      if( strchr(zCap, 'p') ) oap = " checked";
      if( strchr(zCap, 'q') ) oaq = " checked";
      if( strchr(zCap, 'r') ) oar = " checked";
      if( strchr(zCap, 's') ) oas = " checked";
      if( strchr(zCap, 'w') ) oaw = " checked";
    }else{
      zId = 0;
    }
  }

  /* Begin generating the page
  */
  common_standard_menu(0,0);
  common_add_action_item(mprintf("useredit?default_account23=1"), "checkin->check");
  common_add_action_item(mprintf("useredit?default_account=1"), "default account");
  common_add_help_item("CvstracAdminUsers");
  common_add_action_item("userlist", "Cancel");
  common_add_action_item(mprintf("useredit?delete=1&id=%t",zId), "Delete");
  if( zId ){
    common_header("Edit User %s", zId);
  }else{
    common_header("Add New User");
  }
  @ <form action="%s(g.zPath)" method="POST">
  login_output_csrf_token();
  @ <table align="left" style="margin: 10px;">
  @ <tr>
  @   <td align="right" class="nowrap">User ID:</td>
  if( zId ){
    @   <td>%h(zId) <input type="hidden" name="id" value="%h(zId)"></td>
  }else{
    @   <td><input type="text" name="id" size=10></td>
  }
  @ </tr>
  @ <tr>
  @   <td align="right" class="nowrap">Full Name:</td>
  @   <td><input type="text" name="nm" value="%h(zName)"></td>
  @ </tr>
  @ <tr>
  @   <td align="right" class="nowrap">E-Mail:</td>
  @   <td><input type="text" name="em" value="%h(zEMail)"></td>
  @ </tr>
  @ <tr>
  @   <td align="right" valign="top">Capabilities:</td>
  @   <td>
  @     <input type="checkbox" name="aa" id="aa"%s(oaa)><label for="aa">Admin</label><br>
  @     <input type="checkbox" name="ad" id="ad"%s(oad)><label for="ad">Delete</label><br>
  @     <input type="checkbox" name="ai" id="ai"%s(oai)><label for="ai">Check-In</label><br>
  @     <input type="checkbox" name="aj" id="aj"%s(oaj)><label for="aj">Read Wiki</label><br>
  @     <input type="checkbox" name="ak" id="ak"%s(oak)><label for="ak">Write Wiki</label><br>
  @     <input type="checkbox" name="an" id="an"%s(oan)><label for="an">New Tkt</label><br>
  @     <input type="checkbox" name="ao" id="ao"%s(oao)><label for="ao">Check-Out</label><br>
  @     <input type="checkbox" name="ap" id="ap"%s(oap)><label for="ap">Password</label><br>
  @     <input type="checkbox" name="aq" id="aq"%s(oaq)><label for="aq">Query</label><br>
  @     <input type="checkbox" name="ar" id="ar"%s(oar)><label for="ar">Read</label><br>
  if( g.okSetup ){
    @     <input type="checkbox" name="as" id="as"%s(oas)><label for="as">Setup</label><br>
  }
  @     <input type="checkbox" name="aw" id="aw"%s(oaw)><label for="aw">Write</label>
  @   </td>
  @ </tr>
  @ <tr>
  @   <td align="right">Password:</td>
  @   <td><input type="password" name="pw" value=""></td>
  @ </tr>
#ifdef CVSTRAC_WINDOWS
  @ <tr>
  @   <td></td>
  @   <td><input type="checkbox" name="dl" id="dl"%s(odl)><label for="dl">Use Windows Password</label><br></td>
  @ </tr>
#endif
  if( !higherUser ){
    @ <tr>
    @   <td>&nbsp;</td>
    @   <td><input type="submit" name="submit" value="Apply Changes">
    @       &nbsp;&nbsp;&nbsp;
    @       <input type="submit" name="delete" value="Delete User"></td>
    @ </tr>
  }
  @ </table>
  @ <table border="0"><tr><td>
  @ <p><b>Notes:</b></p>
  @ <ol>
  if( higherUser ){
    @ <li><p>
    @ User %h(zId) has Setup privileges and you only have Admin privileges
    @ so you are not permitted to make changes to %h(zId).
    @ </p></li>
    @
  }
  if( g.scm.pxUserWrite!=0
        && !strcmp("yes",db_config("write_cvs_passwd","yes")) ){
    @ <li><p>
    @ If the <b>Check-out</b> capability is specified then
    @ the password entered here will be used to regenerate the
    @ <b>CVSROOT/passwd</b> file and will thus become the CVS password
    @ as well as the password for this server.
    @ </p></li>
    @
    @ <li><p>
    @ The <b>Check-in</b> capability means that the user ID will be written
    @ into the <b>CVSROOT/writers</b> file and thus allow write access to
    @ the CVS repository.
    @ </p></li>
    @
  }else{
    @ <li><p>
    @ If the <b>Check-out</b> capability is specified then the user will be able
    @ to browse the %s(g.scm.zName) repository.
    @ </p></li>
    @
    @ <li><p>
    @ The <b>Check-in</b> capability means the user has submitted a signed Contributors 
	@ License Agreement (CLA) to the project, and gives the user the ability to edit check-in
    @ messages.
    @ </p></li>
    @
  }
  @ <li><p>
  @ The <b>Read</b> and <b>Write</b> privileges give the user the ability
  @ to read and write tickets.  The <b>New Tkt</b> capability means that
  @ the user is able to create new tickets.
  @ </p></li>
  @
  @ <li><p>
  @ The <b>Delete</b> privilege give the user the ability to erase
  @ wiki, tickets, and atttachments that have been added by anonymous
  @ users.  This capability is intended for deletion of spam.
  @ </p></li>
  @
  @ <li><p>
  @ The <b>Query</b> privilege allows the user to create or edit
  @ report formats by specifying appropriate SQL.  Users can run 
  @ existing reports without the Query privilege.
  @ </p></li>
  @
  @ <li><p>
  @ An <b>Admin</b> user can add other users, create new ticket report
  @ formats, and change system defaults.  But only the <b>Setup</b> user
  @ is able to change the %h(g.scm.zName) repository to
  @ which this program is linked.
  @ </p></li>
  @
#ifdef CVSTRAC_WINDOWS
  @ <li><p>
  @ The <b>Use Windows Password</b> option enables linking CVSTrac password
  @ with Windows domain (computer) one using existing username.
  @ <p>Nevertheless giving user also <b>Password</b> privilege enables user
  @ to override CVSTrac password making it separate from the Windows one.
  @ </p></li>
  @
#endif
  if( zId==0 || strcmp(zId,"anonymous")==0 ){
    @ <li><p>
    @ No login is required for user "<b>anonymous</b>".  The capabilities
    @ of this user are available to anyone without supplying a username or
    @ password.  To disable anonymous access, make sure there is no user
    @ with an ID of <b>anonymous</b>.
    @ </p></li>
    @
    @ <li><p>
    @ The password for the "<b>anonymous</b>" user is used for anonymous
    @ %h(g.scm.zName) access.  The recommended value for the anonymous password
    @ is "anonymous".
    @ </p></li>
  }
  @ </ol>
  @ </td></tr></table>
  @ </form>
  common_footer();
}

/*
** Remove the newline from the end of a string.
*/
void remove_newline(char *z){
  while( *z && *z!='\n' && *z!='\r' ){ z++; }
  if( *z ){ *z = 0; }
}
