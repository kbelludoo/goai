# GoAI 0.2 — revision-checked cooperative writer (Linux)

**Scope:** Single-file replacement only. This is a deliberately bounded step
in Issue #2 and **not** a trusted, sandboxed executor or a filesystem CAS.

## Guarantees within the supported assumptions

1. Requires an absolute, cleaned path and Linux. Non-Linux builds fail closed.
2. Uses a **persistent**, adjacent `.filename.goai.commit.lock` sidecar with
   nonblocking Linux `flock`. Only tools that lock this *same sidecar* cooperate.
   Never unlink it: deleting lock files while another process holds an inode
   lock can split the coordination domain.
3. Opens the target and lock with `O_NOFOLLOW` to refuse leaf symlinks and
   checks that both are regular files. Parent-directory symlink/mount issues
   remain outside this API's security boundary.
4. Reads the current source and checks SHA-256 against the transaction's
   expected *original* revision. Stages a new file in the same directory,
   preserving ordinary permission bits and uid/gid, then `fsync`s it.
5. Immediately before rename it reopens the target and checks **both** its
   content hash and original file identity (`os.SameFile`). If the source has
   changed or been replaced by a different inode, it aborts without overwriting.
6. Calls `os.Rename` within the same filesystem. Any simultaneous reader sees
   either old or new complete file contents; it does not see a partial write.
7. All errors prior to rename preserve original file bytes, except that an
   external actor can independently modify the file at any time. Temporary
   staging files are removed on failure. Lock sidecars remain intentionally.

## Important limitations

- **Not linearizable compare-and-swap against non-cooperating external writers.**
  An IDE that does not use the sidecar `flock` can write after the final revision
  check but just before `rename`. The kernel offers no atomic primitive that
  means "replace existing path iff its SHA-256 still equals X". Hash checks
  reduce the window; they do not eliminate it.
- No containment of arbitrary filesystem paths: a trusted caller must enforce
  a workspace-root policy with safe directory resolution (e.g. dirfd-based
  APIs such as `openat2` on supported kernels) and permissions. Do not run this
  writer as root on agent-controlled paths. Parent path aliases, bind mounts,
  hard links and filesystem changes remain relevant to the security model.
- Permission bits and uid/gid are handled; ACLs, extended attributes, SELinux
  labels and hard-link semantics may differ after replacement. On systems
  requiring those guarantees, the safe policy is to reject writing until a
  more complete metadata-preserving backend is implemented.
- `fsync` is applied to the staged file, **not the directory** after rename.
  Crash/reboot durability of the rename is not claimed. There is no multi-file
  atomic commit and no Git commit.
- Source reads are currently bounded to 32 MiB; a larger file fails closed.
- The manager's public constructor still has **no trusted validator**, so it
  cannot issue real approval tokens; an in-package stub validates manager flow
  only. Existing CLI `-write` still uses the legacy engine writer; this PR
  upgrades the `TxManager.Commit` path only.

## Tests

- Normal replacement, ordinary permission preservation and tmp cleanup.
- Explicit non-cooperative change **between staging and final hash check**;
  verifies the external edit is not overwritten.
- Same-content different-inode replacement; detects identity conflict.
- Stale content hash, cooperative file-lock conflict and malicious symlink
  target/lock rejection.
- Existing manager tests cover commit token replay, expiry and stale edits.

## Follow-up

Do **not** merge as a full security boundary. Use a validated sandbox executor
for untrusted code and decide on a stronger privileged committer with explicit
worktree access control, metadata policy and durable on-disk audit before a
production deployment. Consider versioned Git worktrees and a single trusted
writer protocol to eliminate accidental conflicts with cooperating tools.
