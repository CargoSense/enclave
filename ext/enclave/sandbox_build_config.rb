MRuby::Build.new do |conf|
  conf.toolchain :clang

  # Safe standard library — no IO, no sockets, no filesystem
  conf.gembox "stdlib"
  conf.gembox "stdlib-ext"
  conf.gembox "math"
  conf.gembox "metaprog"

  # print gem gives us Kernel#print and Kernel#p (we override __printstr__ equivalent)
  # NOT included: mruby-io (File, Socket, Dir), mruby-bin-* (executables)

  # Enable debug hook for code_fetch_hook (used for timeout)
  conf.cc.defines << "MRB_USE_DEBUG_HOOK"

  # Build as static library only — we link into the Ruby C extension
  conf.cc.flags << "-fPIC"

  # --- Sandbox safety guard (H3: unpreemptable builtins + capability exclusion) ---
  #
  # The wall-clock timeout is driven by code_fetch_hook, which fires only at
  # BYTECODE-FETCH boundaries. A single opcode that enters a long-running C
  # builtin therefore runs to completion with the hook never firing — it cannot
  # be preempted. memory_limit bounds the allocation-heavy builtins (String#*,
  # Array.new, bignum **, sprintf, pack — all verified to raise before running
  # long), but a *pure-CPU* builtin is unbounded. The classic example is a
  # catastrophic-backtracking Regexp (ReDoS): one `str =~ /(a+)+$/` can spin for
  # seconds with no allocation and no fetch boundary to interrupt it.
  #
  # So this build deliberately ships WITHOUT Regexp. We also refuse host-access
  # gems (File/Socket/Dir/exec/process) — those aren't just DoS, they're outright
  # sandbox escapes. Upstream mruby's stdlib gembox happens not to pull these in
  # today, but that is an accident of gembox contents, not a guarantee.
  #
  # This turns "not added" into an ENFORCED invariant: if a gembox or gem ever
  # pulls one in (directly), the build fails loudly here instead of silently
  # shipping a ReDoS vector or an escape. (A runtime spec, "dangerous constants
  # are absent", backstops this for anything pulled in as a transitive
  # dependency after this point.)
  #
  # To build with one of these anyway — e.g. you genuinely need regex and accept
  # the ReDoS risk, or you enforce CPU bounds another way — set
  # ENCLAVE_ALLOW_UNSAFE_GEMS=1 and add the gem yourself.
  denylisted = %w[
    mruby-regexp mruby-onig-regexp mruby-hs-regexp
    mruby-io mruby-socket mruby-dir mruby-exec mruby-process
    mruby-open3 mruby-io-console mruby-pty
  ]
  unless ENV["ENCLAVE_ALLOW_UNSAFE_GEMS"]
    present = conf.gems.map(&:name) & denylisted
    unless present.empty?
      raise "enclave sandbox build refuses unsafe gem(s): #{present.join(', ')}.\n" \
            "  These add unpreemptable pure-CPU builtins (ReDoS) or host access, which\n" \
            "  the sandbox's timeout cannot bound. See ext/enclave/sandbox_build_config.rb.\n" \
            "  Set ENCLAVE_ALLOW_UNSAFE_GEMS=1 to override (and accept the risk)."
    end
  end
  # -----------------------------------------------------------------------------
end
