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
** This file contains code used to read the CVSROOT/history file from
** the CVS archive and update the CHNG and FILECHNG tables according to
** the content of the history file. All the other CVS-specific stuff should also
** be found here.
*/
#include "config.h"
#include <time.h>
#include <sys/times.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <assert.h>
#include <sys/types.h>
#include <errno.h>
#include <limits.h>  /* for PATH_MAX */
#include "git.h"

static void err_pipe(const char* zMsg,const char* zCmd){
  int nErr = 0;
  error_init(&nErr);
  @ <b class="error">%h(zMsg)</b>
  @ <li><p>Unable to execute the following command:
  @ <blockquote><pre>
  @ %h(zCmd)
  @ </pre></blockquote></p></li>
  @ <b>%h(strerror(errno))</b>
  error_finish(nErr);
}

static int next_cnum(){
  char *zResult = db_short_query("SELECT max(cn) FROM chng");
  int next_cnum = zResult ? atoi(zResult)+1 : 0;
  if(zResult) free(zResult);
  return next_cnum;
}

/*
** If *nDate==0, it's usually because the commit wasn't correctly read. A NULL
** return code just means that the commit could be the root object.
*/
static char **git_read_commit(
  const char *zGitDir,
  const char *zObject, /* git sha1 object */
  char **pzAuthor,       /* at least 100 bytes */
  int *nDate,
  char **pzComment
){
  char *zCmd;
  FILE *in;
  char zLine[PATH_MAX*2];
  int bInMsg = 0;
  char **azParents = 0;
  int nParent = 0;
  int nMaxParent = 0;
  int nComment = 0;
  char zCommitter[100];
  char zAuthor[100];
  char zComment[10000];

  assert(nDate);

  *pzAuthor = 0;
  *pzComment = 0;

  zCmd = mprintf("GIT_DIR='%s' git cat-file commit '%s' 2>&1",
                 zGitDir, zObject);
  if( zCmd==0 ) return 0;

  in = popen(zCmd, "r");
  if( in==0 ){
    err_pipe("Reading commit",zCmd);
    free(zCmd);
    return 0;
  }
  free(zCmd);

  zAuthor[0] = 0;
  zComment[0] = 0;
  zCommitter[0] = 0;
  *nDate = 0;

  while( !feof(in) && !ferror(in) ){
    if( 0==fgets(zLine,sizeof(zLine),in) ) break;

    /* you'll get this if it was some other kind of object */
    if( !strncmp(zLine,"error:",6) ) break;

    if( bInMsg==0 ){
      if( zLine[0]=='\n' ){
        bInMsg = 1;
      }else if( 0==strncmp(zLine,"parent ",7) ){
        char zParent[100];
        if( nParent+2 >= nMaxParent ){
          nMaxParent = (nParent+2) * 2;
          azParents = realloc(azParents, sizeof(char*)*nMaxParent);
          if( azParents==0 ) common_err("%s",strerror(errno));
        }

        sscanf(&zLine[7],"%50[0-9a-fA-F]",zParent);
        azParents[nParent++] = strdup(zParent);
        azParents[nParent] = 0;

      }else if( 0==strncmp(zLine,"author ",7) ){
        sscanf(&zLine[7],"%90[^<]%*[^>]>",zAuthor);
      }else if( 0==strncmp(zLine,"committer ",10) ){
        sscanf(&zLine[10],"%90[^<]%*[^>]> %d",zCommitter,nDate);
      }
    }else{
      int len = strlen(zLine);
      if( len+nComment >= sizeof(zComment) ) break;
      strcpy(&zComment[nComment], zLine);
      nComment += len;
    }
  }
  pclose(in);

  if( *nDate==0 ){
    if( azParents ) db_query_free(azParents);
    return NULL;
  }

  if( zComment[0]==0 && bInMsg ){
    strncpy(zComment,"Empty log message",sizeof(zComment));
    nComment = strlen(zComment);
  }

  if( zCommitter[0] ){
    /* If the author and committer aren't the same, include the committer
     * in the message.
     */
    if( strcmp(zAuthor, zCommitter) ) {
      char *zMsg = mprintf( "\n\nCommitter: %s", zCommitter);
      int len = strlen(zLine);
      if( len+nComment < sizeof(zComment) ){
        strcpy(&zComment[nComment], zMsg);
        nComment += len;
      }
      if( zAuthor[0]==0 ){
        /* apparently GIT commits don't always have an author */
        strcpy(zAuthor, zCommitter);
      }
    }
  }

  if( zAuthor[0] ) *pzAuthor = strdup(zAuthor);
  *pzComment = strdup(zComment);

  return azParents;
}

static void git_ingest_commit_chng(
  const char *zGitDir,
  int cn,
  const char *zCommit,
  time_t nDate,
  const char *zAuthor,
  const char *zComment,
  const char *zPrevVers,
  int skipInsertFile
){
  FILE *in = 0;
  char zLine[PATH_MAX*3];
  int nFiles = 0;

  if( zPrevVers==0 || zPrevVers[0]==0 ){
    /* Initial commit, hence no parent(s) to compare against. That means just a
    ** straight tree list
    */

    char *zCmd = mprintf("GIT_DIR='%s' git ls-tree -r '%s'", zGitDir, zCommit);
    in = popen(zCmd,"r");
    if( in==0 ){
      err_pipe("Reading tree",zCmd);
      return;
    }
    free(zCmd);

    while( !feof(in) && !ferror(in) ){
      char zMode[100], zType[100], zObject[100], zPath[PATH_MAX];

      if( 0==fgets(zLine,sizeof(zLine),in) ) break;
      remove_newline(zLine);

      sscanf(zLine, "%8[0-9] %90s %50[0-9a-fA-F] %[^\t]",
             zMode, zType, zObject, zPath);

      if( !strcmp(zType,"blob") ){
        int nIns = 0;
        int nDel = 0;

        nFiles ++;
        db_execute(
          "INSERT INTO filechng(cn,filename,vers,prevvers,chngtype,nins,ndel) "
          "VALUES(%d,'%q','%s','',1,%d,%d)",
          cn, zPath, zCommit, nIns, nDel);
        if( !skipInsertFile ) insert_file(zPath, cn);
      }
    }
  }else{
    /* Now get the list of changed files and turn them into FILE
    ** and FILECHNG records.  git diff-tree is disgustingly PERFECT for
    ** this. Compared to the hassles one has to go through with CVS or
    ** Subversion to find out what's in a change tree, it's just mind
    ** blowing how ideal this is.  FIXME: we're not handling renames or
    ** copies right now. When/if we do, add in the "-C -M" flags.
    */

    char *zCmd = mprintf("GIT_DIR='%s' git diff-tree -r -t '%s' '%s'",
                         zGitDir, zPrevVers, zCommit);
    in = popen(zCmd,"r");
    if( in==0 ){
      err_pipe("Reading tree",zCmd);
      return;
    }
    free(zCmd);

    while( !feof(in) && !ferror(in) ){
      char zSrcMode[100], zDstMode[100], zSrcObject[100], zDstObject[100];
      char cStatus, zPath[PATH_MAX];

      if( 0==fgets(zLine,sizeof(zLine),in) ) break;
      remove_newline(zLine);

      sscanf(zLine, "%*c%8s %8s %50[0-9a-fA-F] %50[0-9a-fA-F] %c %[^\t]",
             zSrcMode, zDstMode, zSrcObject, zDstObject, &cStatus, zPath);

      if( zSrcMode[1]=='0' || zDstMode[1]=='0' ){
        int nIns = 0;
        int nDel = 0;

        if( cStatus=='N' || cStatus=='A' ){
          if( !skipInsertFile ) insert_file(zPath, cn);
          db_execute(
            "INSERT INTO "
            "       filechng(cn,filename,vers,prevvers,chngtype,nins,ndel) "
            "VALUES(%d,'%q','%s','',1,%d,%d)",
            cn, zPath, zCommit, nIns, nDel);
          nFiles ++;
        }else if( cStatus=='D' ){
          db_execute(
            "INSERT INTO "
            "       filechng(cn,filename,vers,prevvers,chngtype,nins,ndel) "
            "VALUES(%d,'%q','%s','%s',2,%d,%d)",
            cn, zPath, zCommit, zPrevVers, nIns, nDel);
          nFiles ++;
        }else{
          db_execute(
            "INSERT INTO "
            "       filechng(cn,filename,vers,prevvers,chngtype,nins,ndel) "
            "VALUES(%d,'%q','%s','%s',0,%d,%d)",
            cn, zPath, zCommit, zPrevVers, nIns, nDel);
          nFiles ++;
        }
      }
    }
  }
  assert(in);
  pclose(in);

  /* git cvsimport doesn't seem to handle some kinds of tags (import tags,
  ** mostly) and we and up with empty commits. We don't want that.
  */
  if( nFiles>0 ){
    db_execute(
      "INSERT INTO chng(cn, date, branch, milestone, user, message) "
      "VALUES(%d,%d,'',0,'%q','%q')",
      cn, nDate, zAuthor, zComment
    );
    xref_add_checkin_comment(cn, zComment);
  }
}

static char *add_merge_to_comment( const char *zGitDir,
  char* zComment, const char *zHead, const char *zRemote
) {
  int rc;
  int nMerged = 0;
  char zBase[100];
  FILE *in;
  char *zCmd = mprintf("GIT_DIR='%s' git merge-base '%s' '%s'",
                       zGitDir, zHead, zRemote );
  in = popen(zCmd,"r");
  if( in==0 ){
    err_pipe("Reading tree",zCmd);
    return zComment;
  }
  free(zCmd);

  zBase[0]=0;
  rc = fscanf(in, "%50[a-fA-F0-9]", zBase);
  pclose(in);

  if( 1==rc ){
    char zCommit[100];

    /* Got a common base for the merge.
    ** What we do with this is get the list of object/cn pairs from
    ** zRemote to zBase's parent and tack them on to the comment.
    */
    strncpy(zCommit,zRemote,sizeof(zCommit));
    while( zCommit[0] && strcmp(zCommit,zBase) ){
      char *z;
      char **azChng = db_query("SELECT cn,prevvers FROM filechng "
                               "WHERE vers='%q' LIMIT 1", zCommit);
      if( azChng[0]==0 ) break; /* maybe pruned? */
      
      z = mprintf("[%d], %s", atoi(azChng[0]), zComment);
      if(zComment) free(zComment);
      zComment = z;

      strncpy(zCommit, azChng[1] ? azChng[1] : "", sizeof(zCommit));

      nMerged ++;
    }
  }

  if( nMerged ){
    /* Prefix the message with "Merged" */
    char *z = mprintf("Merged %s", zComment);
    if(zComment) free(zComment);
    zComment = z;
  }

  return zComment;
}

/*
** Read in any commits in the tree. To sanely deal with
** multi-parent merges, this is a recursive function. Returns the
** number of _new_ commits.
*/
static int git_ingest_commit_tree(const char *zGitDir, const char *zCommit){
  int i;
  char **azParents = 0;
  int nNew = 0;
  char *zComment = NULL;
  char *zAuthor = NULL;
  int nDate = 0;

  if( db_exists("SELECT 1 FROM filechng WHERE vers='%s'", zCommit) ){
    return 0;
  }
  
  /* Grab some information about the commit */
  azParents = git_read_commit(zGitDir,zCommit,&zAuthor,&nDate,&zComment);
  if( nDate==0 ) return 0;

  if( azParents ){
    /* Recurse into the tree. Note we do this _before_ we insert anything
    ** for the present commit.  Things look
    ** really stupid if the root has a higher cn than the leaves/heads.
    ** We also need this if we want to know what cn's are being merged,
    ** which we probably do.
    */
    for(i=0; azParents[i]; i++){
      nNew += git_ingest_commit_tree(zGitDir,azParents[i]);
    }
  }

  if( azParents && azParents[0] && azParents[1] ) {
    /* multiple parents, which means we've got a merge. CVSTrac doesn't
    ** really know anything about merges, but there's no reason we can't
    ** at least mention something in the commit message. Eventually, some
    ** sort of type flag in the CHNG schema might be useful.
    ** In any case, because we've already walked all the parent trees,
    ** we can assume the merged check-ins are all in the CHNG and FILECHNG
    ** records... Or they no longer exist (pruned, etc).
    */

    for(i=1; azParents[i]; i++){
      zComment = add_merge_to_comment( zGitDir, zComment,
                                        azParents[0], azParents[i] );
    }
  }

  /* Now insert _this_ checkin */
  git_ingest_commit_chng( zGitDir, next_cnum(), zCommit, nDate, zAuthor,
                          zComment, azParents ? azParents[0] : 0, 0 );

  if( zAuthor ) free(zAuthor);
  if( zComment ) free(zComment);
  if( azParents ) db_query_free(azParents);

  return nNew + 1;
}

/*
** Read in the git references and turn them into new CHNG records.
*/
static int git_read_refs(const char *zGitDir){
  FILE *in;
  int nCommits = 0;
  char zLine[PATH_MAX+200];
  char zObject[100];
  char zName[PATH_MAX];
  char *zCmd;
  char *zOldObject;
  const char* zFormat = "%(objecttype) %(objectname) %(*objectname) %(refname)";

  zCmd = mprintf("GIT_DIR='%s' git for-each-ref --format='%s' 2>&1",
                 zGitDir, zFormat);
  if( zCmd==0 ) return 0;

  in = popen(zCmd, "r");
  if( in==0 ){
    err_pipe("Reading refs",zCmd);
    free(zCmd);
    return 0;
  }
  free(zCmd);

  while( !feof(in) && !ferror(in) ){
    if( 0==fgets(zLine,sizeof(zLine),in) ) break;

    zObject[0] = zName[0] = 0;

	/* tannenba - only follow non-BUILD V7_ V8_ V9_ refs */
	if ( strstr(zLine,"BUILD") ) continue;
	if ( !strstr(zLine,"V7_") && 
		 !strstr(zLine,"V8_") && 
		 !strstr(zLine,"V9_") && 
		 !strstr(zLine,"master") ) continue;

    /* We don't care about the contents of tag objects. We just
    ** want the commits. But git for-each-ref can't seem to show both
    ** commits and "dereferenced" tags with the same format, hence the
    ** two objectnames and a bit of extra parsing.
    */
    if( !strncmp(zLine,"commit ", 7) ) {
      sscanf(&zLine[7], "%50[0-9a-fA-F]  %[^\n]", zObject, zName );
    } else if( !strncmp(zLine, "tag ", 4) ){
      /* The first SHA is the tag, we want the second */
      sscanf(&zLine[4], "%*[0-9a-fA-F] %50[0-9a-fA-F] %[^\n]", zObject, zName );
    } else {
      /* some kind of newfangled refs? */
      continue;
    }

    /* It'd be nice to delete refs which go away, so keep track of the
    ** ones we've seen.
    */
    db_execute("INSERT INTO seenrefs(name) VALUES('%q')", zName );

    /*
    ** We've overridden the CHNG.directory field to contain the object,
    ** and the CHNG.branch field contains the ref name.
    */
    zOldObject = db_short_query("SELECT directory FROM chng WHERE branch='%q'",
                          zName);

    if( !zOldObject || strcmp(zObject,zOldObject) ){
      /* Either new or changed reference. */

      /* note the change in the temp updaterefs table. We only want to update
      ** refs which we know have changed.
      */
      db_execute("INSERT INTO updaterefs(name,object) VALUES('%q','%q')",
                 zName, zObject );

      /* ingest the commit tree */
      nCommits += git_ingest_commit_tree(zGitDir,zObject);
    }

    if(zOldObject) free(zOldObject);
  }

  pclose(in);

  return nCommits;
}

static void git_update_refs(){
  int i;
  char **azRefs;

  /* 
  ** Note that we don't need _all_ the refs, just the ones that've seen some
  ** changes. If the milestone already exists, we want to rewrite it, so we
  ** figure out its existing cn too.
  */
  azRefs = db_query("SELECT updaterefs.name,updaterefs.object,chng.cn "
                    "FROM updaterefs "
                    "LEFT JOIN chng "
                    "ON updaterefs.name=chng.branch "
                    "ORDER by updaterefs.name");

  for( i=0; azRefs[i]; i+=3 ){
    const char *zName = azRefs[i];
    const char *zObject = azRefs[i+1];
    int cn = atoi(azRefs[i+2]);
    int chngcn = 0;
    char **azChng;

    if( cn==0 ) cn = next_cnum();

    /*
    ** Find the CHNG record for the commit. Who and when are nice, too, for
    ** the milestone, but we have to grab another table.
    */

    azChng = db_query(
        "SELECT chng.cn,date,user FROM filechng,chng "
        "WHERE vers='%s' AND chng.cn=filechng.cn LIMIT 1", zObject);

    if( azChng[0]==0 ){
      /* This shouldn't happen normally. However git cvsimport may ingest
      ** bad tags with missing/empty commits, which means there's no
      ** corresponding FILECHNG record. If we just bail out now we'll just
      ** end up dealing with the ref again, _every_ history update. Which
      ** is just brutally slow for extremely large ex-CVS repositories.
      ** So we need to ensure the milestone is created, even if it's a bit
      ** hackish.
      */
      db_execute(
        "REPLACE INTO chng(cn,branch,milestone,directory,message) "
        "VALUES(%d,'%q',2,'%q','%q, empty tag')",
        cn, zName, zObject, zName
      );
    } else {
      chngcn = atoi(azChng[0]);

      /* Create/update a milestone. The message text basically contains
      ** some information about the type of ref, the name, the commit object,
      ** and, most importantly, a reference to the actual CHNG which, at
      ** display time, should turn into a hyperlink.  Note that in practice,
      ** the milestone will appear next to the commit in the timeline. But
      ** it serves as the only way to document that the commit itself is
      ** somehow special. At some point we should be able to add some concept
      ** of tag browsing.
      ** We're also overloading other fields. "Branch" doesn't really mean
      ** anything in a SCM where _everything_ is a branch, so we store the
      ** ref filename there. We place the corresponding _object_ in the
      ** directory field. This allows us to query against both of them
      ** elsewhere.
      */
	  /* tannenba - distinguish between a branch tag and a release tag */
	  if ( zName && (strstr(zName,"branch") || strstr(zName,"master")) ) {
		  /* branch tag - use milestone type 2 */
      	db_execute(
        "REPLACE INTO chng(cn,date,branch,milestone,user,directory,message) "
        "VALUES(%d,%d,'%q',2,'%q','%q','%q, check-in [%d]')",
        cn, atoi(azChng[1]), zName, azChng[2], zObject,
        zName, chngcn
      	);
	  } else {
		  /* release tag - use milestone type 1 */
      	db_execute(
        "REPLACE INTO chng(cn,date,branch,milestone,user,directory,message) "
        "VALUES(%d,%d,'%q',1,'%q','%q','Release tag %q, check-in [%d]')",
        cn, atoi(azChng[1]), zName, azChng[2], zObject,
        zName, chngcn
      	);
	  }

      db_query_free( azChng );
    }
  }
  db_query_free(azRefs);
}

/*
** Remove deleted refs
*/
static void git_delete_refs() {
  db_execute("DELETE FROM chng "
             "WHERE milestone>0 "
             "AND branch LIKE 'refs/%%' "
             "AND branch NOT IN (SELECT name FROM seenrefs)"
            );
}

/*
** Process recent activity in the GIT repository.
**
** If any errors occur, output an error page and exit.
**
** If the "isReread" flag is set, it means that the history file is being
** reread to pick up changes that we may have missed earlier. Probably
** futile with GIT, since we can only work back from known refs and we
** pick those up automatically, anyways.
*/
static int git_history_update(int isReread){
  const char *zRoot;
  int nOldSize = 0;
  int nNewRevs;

  db_execute("BEGIN");

  /* Get the path to local repository and last revision number we have in db
   * If there's no repository defined, bail and wait until the admin sets one.
  */
  zRoot = db_config("cvsroot","");
    /* tannenba - apply fix in cvstrac #684 to commit transaction even
	 * if no repository is defined */
  /* if( zRoot[0]==0 ) return 0; */
  if( zRoot[0]==0 ) {
      db_execute("COMMIT");
      return 0;
  }

  nOldSize = atoi(db_config("historysize","0"));

  /* git has multiple "heads", each representing a different
  ** branch. We need to follow the tree from each head back to either the
  ** root or something we've already seen. We use a couple of temp tables
  ** for records keeping.
  */

  db_execute( "CREATE TEMP TABLE updaterefs(name,object);");
  db_execute( "CREATE TEMP TABLE seenrefs(name);");

  if( sqlite3_libversion_number() >= 3003008 ){
    /* Ref checks should be really quick since they happen on every update.
    ** This index improves performance by at least an order of magnitude.
    */
    db_execute("CREATE INDEX IF NOT EXISTS git_idx1 ON chng(branch,directory)");
	db_execute("CREATE INDEX IF NOT EXISTS git_idx2 ON filechng(vers)");
  }

  /* Read the refs and ingest the commit tree */
  nNewRevs = git_read_refs(zRoot);

  if( nNewRevs==0 ) {
    /* Might be a little inefficient to call this each time, but since
    ** branching/tagging operations can be done independent from commits,
    ** and we _want_ to know about branches and tags, how else can we do
    ** it?
    */
    git_update_refs();
    git_delete_refs();

    db_execute("COMMIT");
    return 0;
  }

  /* We couldn't do this before since GIT tags are basically milestones
  ** that point at other CHNG entries and we may not have had all the CHNG
  ** records.  We do heads here too. What this means is that each head is
  ** basically a moving milestone. Not sure how desirable this really is.
  */
  git_update_refs();

  /* Clean up refs which are no longer needed. We _could_ keep them around,
  ** but GIT can also prune the unclaimed leafs in a tree, so it's probably
  ** asking for problems.
  */
  git_delete_refs();
  
  /*
  ** Update the "historysize" entry. For GIT, it only matters that it's
  ** non-zero except when we need to re-read the database.
  */
  db_execute("UPDATE config SET value=%d WHERE name='historysize';",
      nOldSize + nNewRevs );
  db_config(0,0);
  
  /* We delayed populating FILE till now on initial scan */
  if( nOldSize==0 ){
    update_file_table_with_lastcn();
  }
  
  /* Commit all changes to the database
  */
  db_execute("COMMIT;");

  return 0;
}

static int git_history_reconstruct(void) {
  /* clean out refs */
  db_execute("DELETE FROM chng WHERE milestone>0 AND branch LIKE 'refs/%%'");
  return 0;
}

/*
** Diff two versions of a file, handling all exceptions.
**
** If oldVersion is NULL, then this function will output the
** text of version newVersion of the file instead of doing
** a diff.
*/
static int git_diff_versions(
  const char *oldVersion,
  const char *newVersion,
  const char *zFile
){
  char *zCmd;
  FILE *in;
  const char *azSubst[16];
  const char *zTemplate;

  /* Find the command used to compute the file difference.*/
  azSubst[0] = "F";
  azSubst[1] = zFile;
  azSubst[2] = "V1";
  azSubst[3] = oldVersion;
  azSubst[4] = "V2";
  azSubst[5] = newVersion;
  azSubst[6] = "RP";
  azSubst[7] = db_config("cvsroot", "");
  azSubst[8] = "V";
  azSubst[9] = newVersion;
  azSubst[10] = 0;
			  
  zTemplate = db_config(
    "filediff", 
    OS_VAL( "GIT_DIR='%RP' git diff --full-index "
              "-t -p -r '%V1' '%V2' -- '%F' 2>/dev/null",
	          "GIT_DIR=\"%RP\" git diff --full-index "
              "-t -p -r \"%V1\" \"%V2\" -- \"%F\" 2>NUL" )
          );
  zCmd = subst(zTemplate, azSubst);
  
  in = popen(zCmd, "r");
  free(zCmd);
  if( in==0 ) return -1;
  
  @ <div class="diff">
  output_pipe_as_html(in,0);
  @ </div>
  pclose(in);
  
  return 0;
}

static char *git_get_blob(
  const char *zGitDir,
  const char *zTreeish,
  const char* zPath
){
  FILE *in;
  char zLine[PATH_MAX*2];
  char *zCmd;

  if( zTreeish==0 || zTreeish[0]==0 || zPath==0 || zPath[0]==0 ) return 0;
    
  zCmd = mprintf("GIT_DIR='%s' git ls-tree -r '%s' '%s'", zGitDir,
                 quotable_string(zTreeish), quotable_string(zPath));
  in = popen(zCmd,"r");
  if( in==0 ){
    err_pipe("Reading tree",zCmd);
    return 0;
  }
  free(zCmd);

  while( !feof(in) && !ferror(in) ){
    char zMode[100], zType[100], zObject[100];

    if( 0==fgets(zLine,sizeof(zLine),in) ) break;

    sscanf(zLine, "%8s %90s %50[0-9a-fA-F]", zMode, zType, zObject);

    if( !strcmp(zType,"blob") ){
      return strdup(zObject);
    }
  }
  return 0;
}

static int git_dump_version(const char *zVersion, const char *zFile,int bRaw){
  int rc = -1;
  char *zCmd;
  const char *zRoot = db_config("cvsroot","");
  const char *zBlob = git_get_blob(zRoot, zVersion, zFile);
  if( zBlob==0 ) return -1;

  zCmd = mprintf("GIT_DIR='%s' git cat-file blob '%s' 2>/dev/null",
                zRoot, zBlob);
  rc = common_dumpfile( zCmd, zVersion, zFile, bRaw );
  free(zCmd);

  return rc;
}

static int git_diff_chng(int cn, int bRaw){
  char **azRev;
  char *zCmd;
  char zLine[2000];
  FILE *in;
  const char *azSubst[16];
  const char *zTemplate;
  
  azRev = db_query("SELECT vers,prevvers FROM filechng WHERE cn=%d", cn);
  if( !azRev || !azRev[0] ) return -1; /* Invalid check-in number */
  
  /* Find the command used to compute the file difference.*/
  azSubst[0] = "F";
  azSubst[1] = "";
  azSubst[2] = "V1";
  azSubst[3] = azRev[1];
  azSubst[4] = "V2";
  azSubst[5] = azRev[0];
  azSubst[6] = "RP";
  azSubst[7] = db_config("cvsroot", "");
  azSubst[8] = "V";
  azSubst[9] = azRev[0];
  azSubst[10] = 0;
		
  /* Be careful - we don't want the Patchset to include HTML from a filter */
  zTemplate =
	 OS_VAL( "GIT_DIR='%RP' git diff --full-index -t "
               "-p -r '%V1' '%V2' -- '%F' 2>/dev/null",
             "GIT_DIR=\"%RP\" git diff --full-index -t "
               "-p -r \"%V1\" \"%V2\" -- \"%F\" 2>NUL" );
  if ( !bRaw ) {
    zTemplate = db_config( "filediff", zTemplate );
  }
  zCmd = subst(zTemplate, azSubst);
  
  db_query_free(azRev);
  
  in = popen(zCmd, "r");
  free(zCmd);
  if( in==0 ) return -1;
  
  if( bRaw ){
    while( !feof(in) ){
      int amt = fread(zLine, 1, sizeof(zLine), in);
      if( amt<=0 ) break;
      cgi_append_content(zLine, amt);
    }
  }else{
    @ <div class="diff">
    output_pipe_as_html(in,0);
    @ </div>
  }
  pclose(in);
  
  return 0;
}

void init_git(void){
  g.scm.zSCM = "git";
  g.scm.zName = "GIT";
  g.scm.pxHistoryUpdate = git_history_update;
  g.scm.pxHistoryReconstructPrep = git_history_reconstruct;
  g.scm.pxDiffVersions = git_diff_versions;
  g.scm.pxDiffChng = git_diff_chng;
  g.scm.pxIsFileAvailable = 0;  /* use the database */
  g.scm.pxDumpVersion = git_dump_version;
}

