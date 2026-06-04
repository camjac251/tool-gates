<div class="gate-head">
  <p class="breadcrumb"><a href="../index.html">Gates</a> / basics</p>
  <h1>basics gate</h1>
  <div class="gate-meta">
    <span class="tag">priority <b>100</b></span>
    <span class="tag">unknown <b>ask</b></span>
    <span class="tag">structure <b>safe_commands</b> array</span>
    <span class="tag">~180 commands</span>
  </div>

  <p class="gate-lede">The default-safe list. Unlike other gates, basics doesn't define per-program rules: it's one big <code>safe_commands = […]</code> array of commands that are always allowed without prompting. Lowest priority (100) so other gates' specific rules win first.</p>
</div>

<div class="cmd-grid">
  <div class="cat">
    <h4>Display &amp; output</h4>
    <div class="chips-line"><span>echo</span><span>printf</span><span>cat</span><span>zcat</span><span>head</span><span>tail</span><span>less</span><span>more</span><span>bat</span><span>batcat</span></div>
  </div>
  <div class="cat">
    <h4>Listing &amp; finding</h4>
    <div class="chips-line"><span>ls</span><span>eza</span><span>lsd</span><span>tree</span><span>find</span><span>fd</span><span>locate</span><span>which</span><span>whereis</span><span>type</span></div>
  </div>
  <div class="cat">
    <h4>Text processing</h4>
    <div class="chips-line"><span>grep</span><span>rg</span><span>ripgrep</span><span>zgrep</span><span>choose</span><span>cut</span><span>sort</span><span>uniq</span><span>wc</span><span>tr</span><span>column</span><span>paste</span><span>join</span><span>comm</span><span>diff</span><span>cmp</span><span>fold</span><span>fmt</span><span>nl</span><span>rev</span><span>tac</span><span>expand</span><span>unexpand</span><span>pr</span></div>
  </div>
  <div class="cat">
    <h4>File info</h4>
    <div class="chips-line"><span>file</span><span>stat</span><span>du</span><span>df</span><span>lsof</span><span>readlink</span><span>realpath</span><span>basename</span><span>dirname</span><span>lsattr</span><span>getfacl</span></div>
  </div>
  <div class="cat">
    <h4>Process &amp; system info</h4>
    <div class="chips-line"><span>ps</span><span>top</span><span>htop</span><span>btop</span><span>procs</span><span>pgrep</span><span>pidof</span><span>uptime</span><span>w</span><span>who</span><span>whoami</span><span>id</span><span>groups</span><span>uname</span><span>hostname</span><span>hostnamectl</span><span>date</span><span>cal</span><span>free</span><span>vmstat</span><span>iostat</span><span>nproc</span><span>lscpu</span><span>lsmem</span><span>lsblk</span><span>lspci</span><span>lsusb</span><span>locale</span><span>getconf</span></div>
  </div>
  <div class="cat">
    <h4>GPU &amp; display info</h4>
    <div class="chips-line"><span>vainfo</span><span>vdpauinfo</span><span>glxinfo</span><span>clinfo</span><span>xdpyinfo</span><span>xwininfo</span></div>
  </div>
  <div class="cat">
    <h4>Network info</h4>
    <div class="chips-line"><span>ping</span><span>traceroute</span><span>tracepath</span><span>mtr</span><span>dig</span><span>nslookup</span><span>host</span><span>whois</span><span>ss</span><span>netstat</span><span>ip</span><span>ifconfig</span><span>route</span><span>arp</span></div>
  </div>
  <div class="cat">
    <h4>Archive &amp; document inspection</h4>
    <div class="chips-line"><span>zipinfo</span><span>unrar</span><span>pdftotext</span><span>pdfinfo</span></div>
  </div>
  <div class="cat">
    <h4>Dev tools (read-only)</h4>
    <div class="chips-line"><span>tokei</span><span>cloc</span><span>scc</span><span>loc</span><span>token-counter</span><span>jq</span><span>yq</span><span>gron</span><span>fx</span><span>hexdump</span><span>xxd</span><span>base64</span><span>od</span><span>hexyl</span><span>strings</span><span>delta</span><span>difft</span><span>dust</span><span>fselect</span><span>pastel</span><span>numbat</span><span>fzf</span><span>tig</span><span>glow</span><span>jc</span></div>
  </div>
  <div class="cat">
    <h4>Navigation</h4>
    <div class="chips-line"><span>z</span><span>zi</span><span>zoxide</span></div>
  </div>
  <div class="cat">
    <h4>Checksums</h4>
    <div class="chips-line"><span>sha256sum</span><span>md5sum</span><span>sha1sum</span><span>sha512sum</span><span>b2sum</span><span>cksum</span><span>b3sum</span><span>xxhsum</span><span>xxh32sum</span><span>xxh64sum</span><span>xxh128sum</span></div>
  </div>
  <div class="cat">
    <h4>Help &amp; docs</h4>
    <div class="chips-line"><span>man</span><span>info</span><span>help</span><span>tldr</span><span>tealdeer</span><span>cheat</span></div>
  </div>
  <div class="cat">
    <h4>Shell built-ins &amp; misc</h4>
    <div class="chips-line"><span>mktemp</span><span>true</span><span>false</span><span>yes</span><span>seq</span><span>expr</span><span>bc</span><span>dc</span><span>factor</span><span>sleep</span><span>wait</span><span>printenv</span><span>env</span><span>export</span><span>set</span><span>pwd</span><span>cd</span><span>pushd</span><span>popd</span><span>dirs</span><span>unalias</span><span>hash</span><span>test</span><span>[</span><span>[[</span><span>dpkg-query</span><span>read</span></div>
  </div>
</div>

<p class="note">
  <svg class="alert" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 9v4"></path><path d="M12 17h.01"></path><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"></path></svg>
  <span><b>Three custom handlers extend the list.</b> <code>check_xargs</code> allows <code>xargs</code> only when the target command is itself in <code>safe_commands</code>; otherwise asks. <code>check_shell_c</code> parses <code>bash -c '…'</code> / <code>sh -c '…'</code> / <code>zsh -c '…'</code> and checks every command in the inner script. <code>check_command_builtin</code> handles <code>command -v</code> / <code>-V</code> and evaluates other invocations through the gate engine.</span>
</p>
