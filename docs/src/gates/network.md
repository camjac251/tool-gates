<div class="gate-head">
  <p class="breadcrumb"><a href="../index.html">Gates</a> / Network & HTTP</p>
  <h1>Network & HTTP gate</h1>
  <div class="gate-meta">
    <span class="tag">priority <b>35</b></span>
    <span class="tag">unknown <b>allow</b></span>
    <span class="tag"><b>--dry-run</b> / <b>--spider</b> allow as read-only</span>
    <span class="tag">custom handlers <b>check_curl</b>, <b>check_netcat</b></span>
  </div>

  <div class="summary" aria-label="Rule counts at a glance">
    <div class="seg-bar" role="img" aria-label="19 allow, 18 ask, 1 block">
      <div class="seg allow" style="flex: 19"></div>
      <div class="seg ask"   style="flex: 18"></div>
      <div class="seg block" style="flex: 1"></div>
    </div>
    <div class="counts">
      <span class="ca"><i></i><b>19</b> allow</span>
      <span class="cas"><i></i><b>18</b> ask</span>
      <span class="cb"><i></i><b>1</b> block</span>
    </div>
  </div>

  <p class="gate-lede">Outbound network operations. GET requests and head checks pass through; everything mutating, downloading, or interactive pauses for approval. The reverse-shell variant of netcat (<code>nc -e</code>) is the one hard block this gate owns.</p>
</div>

<div class="chips" role="group" aria-label="Filter rules by decision">
  <button class="chip all"   data-filter="all"   aria-pressed="true"><i></i>All <span class="n">38</span></button>
  <button class="chip allow" data-filter="allow" aria-pressed="false"><i></i>Allow <span class="n">19</span></button>
  <button class="chip ask"   data-filter="ask"   aria-pressed="false"><i></i>Ask <span class="n">18</span></button>
  <button class="chip block" data-filter="block" aria-pressed="false"><i></i>Block <span class="n">1</span></button>
</div>

<div class="rule-card">
  <header>
    <h2>Blocked · reverse shell</h2>
    <a href="https://github.com/camjac251/tool-gates/blob/main/rules/network.toml" class="src" target="_blank" rel="noopener">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
      rules/network.toml#block
    </a>
    <span class="count">1 patterns</span>
  </header>

<div class="rule-row" data-decision="block" id="network-nc-e">
  <div class="rule-cmd"><span class="prog">nc</span> <span class="flag">-e</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">netcat <code>-e</code> blocked: connects a remote process to a shell on this host (classic reverse shell). No legitimate use in an agent workflow.</div>
</div>
</div>

<div class="rule-card">
  <header>
    <h2>Allowed · read-only requests</h2>
    <a href="https://github.com/camjac251/tool-gates/blob/main/rules/network.toml" class="src" target="_blank" rel="noopener">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
      rules/network.toml#allow
    </a>
    <span class="count">19 patterns</span>
  </header>

<div class="rule-row" data-decision="allow" id="network-curl-version">
  <div class="rule-cmd"><span class="prog">curl</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the curl version and supported protocols. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="network-curl-h">
  <div class="rule-cmd"><span class="prog">curl</span> -h</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows curl usage help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="network-curl-help">
  <div class="rule-cmd"><span class="prog">curl</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows curl usage help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="network-curl-i-head">
  <div class="rule-cmd"><span class="prog">curl</span> <span class="flag">-I</span> <span class="flag">--head</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">HEAD request. Returns response headers only, no body. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="network-http-version">
  <div class="rule-cmd"><span class="prog">http</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the HTTPie client version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="network-http-help">
  <div class="rule-cmd"><span class="prog">http</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows HTTPie usage help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="network-http-get">
  <div class="rule-cmd"><span class="prog">http</span> GET</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">HTTPie GET requests, including URL-only invocations that default to GET. <code>check_httpie</code> routes POST/PUT/DELETE/PATCH to ask.</div>
</div>
<div class="rule-row" data-decision="allow" id="network-nmap-version">
  <div class="rule-cmd"><span class="prog">nmap</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the nmap version and build info. Read-only; sends no probes.</div>
</div>
<div class="rule-row" data-decision="allow" id="network-nmap-v">
  <div class="rule-cmd"><span class="prog">nmap</span> -V</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the nmap version and build info. Read-only; sends no probes.</div>
</div>
<div class="rule-row" data-decision="allow" id="network-nmap-help">
  <div class="rule-cmd"><span class="prog">nmap</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows nmap usage help. Read-only; sends no probes.</div>
</div>
<div class="rule-row" data-decision="allow" id="network-nmap-h">
  <div class="rule-cmd"><span class="prog">nmap</span> -h</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows nmap usage help. Read-only; sends no probes.</div>
</div>
<div class="rule-row" data-decision="allow" id="network-socat-version">
  <div class="rule-cmd"><span class="prog">socat</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the socat version and feature list. Read-only; opens no connection.</div>
</div>
<div class="rule-row" data-decision="allow" id="network-socat-v">
  <div class="rule-cmd"><span class="prog">socat</span> -V</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the socat version and feature list. Read-only; opens no connection.</div>
</div>
<div class="rule-row" data-decision="allow" id="network-socat-help">
  <div class="rule-cmd"><span class="prog">socat</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows socat usage help. Read-only; opens no connection.</div>
</div>
<div class="rule-row" data-decision="allow" id="network-socat-h">
  <div class="rule-cmd"><span class="prog">socat</span> -h</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows socat usage help. Read-only; opens no connection.</div>
</div>
<div class="rule-row" data-decision="allow" id="network-wget-version">
  <div class="rule-cmd"><span class="prog">wget</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the wget version and build info. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="network-wget-h">
  <div class="rule-cmd"><span class="prog">wget</span> -h</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows wget usage help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="network-wget-help">
  <div class="rule-cmd"><span class="prog">wget</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows wget usage help. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="network-wget-spider">
  <div class="rule-cmd"><span class="prog">wget</span> <span class="flag">--spider</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Spider mode. Checks that a URL resolves; does not download. Read-only.</div>
</div>
</div>

<div class="rule-card">
  <header>
    <h2>Asks first · mutations and inbound</h2>
    <a href="https://github.com/camjac251/tool-gates/blob/main/rules/network.toml" class="src" target="_blank" rel="noopener">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
      rules/network.toml#ask
    </a>
    <span class="count">18 patterns</span>
  </header>

<div class="rule-row" data-decision="ask" id="network-http-post">
  <div class="rule-cmd"><span class="prog">http</span> POST</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Sends an HTTP POST request. Mutating method; server-side effects depend on the endpoint.</div>
</div>
<div class="rule-row" data-decision="ask" id="network-http-put">
  <div class="rule-cmd"><span class="prog">http</span> PUT</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Sends an HTTP PUT request. Typically replaces a resource at the target URL.</div>
</div>
<div class="rule-row" data-decision="ask" id="network-http-delete">
  <div class="rule-cmd"><span class="prog">http</span> DELETE</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Sends an HTTP DELETE request. Typically removes the resource at the target URL.</div>
</div>
<div class="rule-row" data-decision="ask" id="network-http-patch">
  <div class="rule-cmd"><span class="prog">http</span> PATCH</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Sends an HTTP PATCH request. Typically applies a partial update to the resource at the target URL.</div>
</div>
<div class="rule-row" data-decision="ask" id="network-nc-l">
  <div class="rule-cmd"><span class="prog">nc</span> <span class="flag">-l</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Opens a listening port. The <code>-e</code> flag (reverse shell) is blocked separately; verify firewall scope and that you intend to accept inbound connections.</div>
</div>
<div class="rule-row" data-decision="ask" id="network-nc">
  <div class="rule-cmd"><span class="prog">nc</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Opens a netcat connection to the given host/port. Sends/receives raw bytes; verify both endpoints.</div>
</div>
<div class="rule-row" data-decision="ask" id="network-nmap">
  <div class="rule-cmd"><span class="prog">nmap</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Sends port-scan probes to remote hosts. Can be slow on large ranges and is logged by most network security tools.</div>
</div>
<div class="rule-row" data-decision="ask" id="network-rsync">
  <div class="rule-cmd"><span class="prog">rsync</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Synchronizes files between source and destination. <code>--delete</code> removes files at the destination not present at source; preview with <code>-n</code> first.</div>
</div>
<div class="rule-row" data-decision="ask" id="network-scp">
  <div class="rule-cmd"><span class="prog">scp</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Copies files over SSH. Overwrites the destination by default; can transfer in either direction.</div>
</div>
<div class="rule-row" data-decision="ask" id="network-sftp">
  <div class="rule-cmd"><span class="prog">sftp</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Opens an interactive SFTP session for transferring files over SSH.</div>
</div>
<div class="rule-row" data-decision="ask" id="network-socat">
  <div class="rule-cmd"><span class="prog">socat</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">socat sets up bidirectional I/O between two endpoints (network, file, process). Confirm both endpoints; can be used to tunnel out of restricted environments.</div>
</div>
<div class="rule-row" data-decision="ask" id="network-ssh">
  <div class="rule-cmd"><span class="prog">ssh</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Opens an SSH connection. Commands executed on the remote bypass local tool-gates; treat the remote as a separate trust boundary.</div>
</div>
<div class="rule-row" data-decision="ask" id="network-telnet">
  <div class="rule-cmd"><span class="prog">telnet</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Opens a cleartext telnet session to a host/port. No encryption; credentials sent in the clear.</div>
</div>
<div class="rule-row" data-decision="ask" id="network-wget-o-output-document-p-directory-prefix">
  <div class="rule-cmd"><span class="prog">wget</span> <span class="flag">-O</span> <span class="flag">--output-document</span> <span class="flag">-P</span> <span class="flag">--directory-prefix</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Downloads a file from the given URL. Writes to disk; <code>-O</code> chooses the output name, <code>-P</code> chooses the directory.</div>
</div>
<div class="rule-row" data-decision="ask" id="network-wget-r-recursive">
  <div class="rule-cmd"><span class="prog">wget</span> <span class="flag">-r</span> <span class="flag">--recursive</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Recursively downloads pages and linked resources. Can fetch a large amount of data; control depth with <code>-l</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="network-wget-m-mirror">
  <div class="rule-cmd"><span class="prog">wget</span> <span class="flag">-m</span> <span class="flag">--mirror</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Mirrors a site to local disk. Implies infinite recursion, timestamping, and link conversion.</div>
</div>
<div class="rule-row" data-decision="ask" id="network-wget-post-data-post-file">
  <div class="rule-cmd"><span class="prog">wget</span> <span class="flag">--post-data</span> <span class="flag">--post-file</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Sends a POST request with the given body. Mutating HTTP method; server-side effects depend on the endpoint.</div>
</div>
<div class="rule-row" data-decision="ask" id="network-wget">
  <div class="rule-cmd"><span class="prog">wget</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Downloads the given URL to the current directory by default. Writes to disk.</div>
</div>
</div>

<p class="note">
  <svg class="alert" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 9v4"></path><path d="M12 17h.01"></path><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"></path></svg>
  <span><b>Pipe-to-shell lives in the pre-AST pass, not here.</b> A pattern like <code>curl https://… | bash</code> is denied before any program-level gate runs. The network gate only sees the <code>curl</code> in isolation; the shell pipe is caught upstream by the raw-string scanner.</span>
</p>
