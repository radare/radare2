#include <rvc.h>
static bool copy_commits(const Rvc *repo, const char *dpath, const char *spath) {
	char *name, *commit_path;
	RListIter *iter;
	RList *files;
	files = r_sys_dir (spath);
	bool ret = true;
	if (!files) {
		eprintf ("Can't Open Files\n");
		return false;
	}
	r_list_foreach (files, iter, name) {
		if (r_str_cmp (name, "..", 2) == 0 || r_str_cmp (name, ".", 1) == 0) {
			printf ("%s", name);
			continue;
		}
		commit_path = r_str_newf ("%s" R_SYS_DIR "%s", spath, name);
		if (!commit_path) {
			ret = false;
			break;
		}
		ret = r_file_copy (commit_path, dpath);
		free (commit_path);
		if (!ret) {
			break;
		}
	}
	r_list_free (files);
	return ret;
}

static char *branch_mkdir(Rvc *repo, RvcBranch *b) {
	char *path = r_str_newf ("%s" R_SYS_DIR "branches" R_SYS_DIR "%s"
			R_SYS_DIR "commits" R_SYS_DIR,repo->path, b->name);
	r_return_val_if_fail (path, NULL);
	if (!r_sys_mkdirp (path)) {
		free (path);
		return NULL;
	}
	return path;
}

static inline char *hashtohex(const ut8 *data, size_t len) {
	char *tmp, *ret = NULL;
	int i = 0;
	for (i = 0; i < len; i++) {
		tmp = r_str_appendf (ret, "%02x", data[i]);
		if (!tmp) {
			ret= NULL;
			break;
		}
		ret = tmp;
	}
	return ret;
}

static char *find_sha256(const ut8 *block, int len) {
	char *ret;
	RHash *ctx = r_hash_new (true, R_HASH_SHA256);
	const ut8 *c = r_hash_do_sha256 (ctx, block, len);
	ret = hashtohex (c, R_HASH_SIZE_SHA256);
	r_hash_free (ctx);
	return ret;
}

static bool write_commit(Rvc *repo, RvcBranch *b, RvcCommit *commit) {
	char *commit_path, *commit_string, *tmp;
	char *prev_path;
	FILE *prev_file, *commit_file;
	RListIter *iter;
	RvcBlob *blob;
	commit_string = r_str_newf ("author:%s\ntimestamp:%ld\n----",
			commit->author, commit->timestamp);
	r_return_val_if_fail (commit_string, false);
	r_list_foreach (commit->blobs, iter, blob) {
		tmp = r_str_appendf (commit_string, "\nblob:%s:%s",
				blob->fname, blob->hash);
		if (!tmp) {
			free (commit_string);
			return false;
		}
		commit_string = tmp;
	}
	commit->hash = find_sha256 ((ut8 *) commit,
			r_str_len_utf8 (commit_string) * sizeof (char));
	if (!commit->hash) {
		free (commit);
		return false;
	}
	commit_path = r_str_newf ("%s" R_SYS_DIR "branches" R_SYS_DIR
			"%s" R_SYS_DIR "commits" R_SYS_DIR "%s",
			repo->path, b->name, commit->hash);
	if (!commit_path) {
		free (commit);
		return false;
	}
	commit_file = fopen (commit_path, "w+");
	free (commit_path);
	if (!commit_file) {
		free (commit_string);
		return false;
	}
	fprintf (commit_file, "%s", commit_string);
	free (commit_string);
	if (!commit->prev) {
		fclose (commit_file);
		return true;
	}
	prev_path = r_str_newf ("%s" R_SYS_DIR "branches" R_SYS_DIR
			"%s" R_SYS_DIR "commits" R_SYS_DIR "%s",
			repo->path, b->name, commit->prev->hash);
	if (!prev_path) {
		fclose (commit_file);
		return false;
	}
	prev_file = fopen (prev_path, "r+");
	free (prev_path);
	if (!prev_file) {
		fclose (commit_file);
		return false;
	}
	fprintf (commit_file, "\nprev:%s", commit->prev->hash);
	fclose (commit_file);
	fseek (prev_file, 0, SEEK_END);
	fprintf (prev_file, "\nnext:%s", commit->hash);
	fclose (prev_file);
	return true;
}
R_API bool rvc_commit(Rvc *repo, RvcBranch *b, RList *blobs, char *auth) {
	RvcCommit *nc = R_NEW (RvcCommit);
	if (!nc) {
		eprintf ("Failed To Allocate New Commit\n");
		return false;
	}
	nc->author = r_str_new (auth);
	if (!nc->author) {
		free (nc);
		eprintf ("Failed To Allocate New Commit\n");
		return false;
	}
	nc->timestamp = time (NULL);
	nc->prev = b->head;
	nc->blobs = blobs;
	if (!write_commit (repo, b, nc)) {
		free (nc->author);
		free (nc);
		eprintf ("Failed To Create Commit File\n");
		return false;
	}
	b->head = nc;
	return true;
}
R_API bool rvc_branch(Rvc *repo, const char *name, const RvcBranch *parent) {
	char *bpath, *ppath;
	RvcBranch *nb = R_NEW0 (RvcBranch);
	if (!nb) {
		eprintf ("Failed To Allocate Branch Struct\n");
		return false;
	}
	nb->head = NULL;
	nb->name = r_str_new (name);
	if (!nb->name) {
		eprintf ("Failed To Allocate Branch Name\n");
		free (nb);
		return false;
	}
	r_list_append (repo->branches, nb);
	bpath = branch_mkdir (repo, nb);
	if (!bpath) {
		eprintf ("Failed To Create Branch Directory\n");
		free (nb->name);
		free (nb);
		r_list_pop (repo->branches);
		return false;
	}
	if (parent) {
		nb->head = parent->head;
		ppath = r_str_newf ("%s" R_SYS_DIR "branches" R_SYS_DIR "%s"
				R_SYS_DIR "commits" R_SYS_DIR,
				repo->path, parent->name);
		if (!copy_commits (repo, bpath, ppath)) {
			eprintf ("Failed To Copy Commits From Parent\n");
			free (nb->name);
			free (nb);
			free (bpath);
			return false;
		}
	}
	free (bpath);
	return true;
}

R_API Rvc *rvc_new(const char *path) {
	Rvc *repo = R_NEW (Rvc);
	if (!repo) {
		eprintf ("Failed To Allocate Repoistory Path\n");
	}
	repo->path = r_str_newf ("%s" R_SYS_DIR ".rvc" R_SYS_DIR, path);
	if (!repo->path) {
		eprintf ("Failed To Allocate Repository Path\n");
		free (repo);
		return NULL;
	}
	if (!r_sys_mkdir (repo->path)) {
		//eprintf ("Failed To Create Repo Directory\n");
		free (repo->path);
		free (repo);
		return NULL;
	}
	repo->branches = r_list_new ();
	if (!repo->branches) {
		//eprintf ("Failed To Allocate Branches List\n");
		free (repo);
		free (repo->path);
		return NULL;
	}
	if (!rvc_branch (repo, "master", NULL)) {
		free (repo->path);
		r_list_free (repo->branches);
		free (repo);
		return NULL;
	}
	return repo;
}
