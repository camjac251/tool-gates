<div class="gate-head">
  <p class="breadcrumb"><a href="../index.html">Gates</a> / cloud</p>
  <h1>cloud gate</h1>
  <div class="gate-meta">
    <span class="tag">priority <b>15</b></span>
    <span class="tag">unknown <b>ask</b></span>
    <span class="tag">covers <b>aws · gcloud · az · terraform · kubectl · docker · podman · helm · pulumi</b></span>
    <span class="tag"><b>action_prefix</b> matching for AWS</span>
  </div>

  <div class="summary" aria-label="Rule counts at a glance">
    <div class="seg-bar" role="img" aria-label="203 allow, 212 ask, 4 block">
      <div class="seg allow" style="flex: 203"></div>
      <div class="seg ask"   style="flex: 212"></div>
      <div class="seg block" style="flex: 4"></div>
    </div>
    <div class="counts">
      <span class="ca"><i></i><b>203</b> allow</span>
      <span class="cas"><i></i><b>212</b> ask</span>
      <span class="cb"><i></i><b>4</b> block</span>
    </div>
  </div>

  <p class="gate-lede">The largest gate. Cloud-provider CLIs and container orchestration. AWS uses an <code>action_prefix</code> pattern (every <code>describe-*</code> / <code>list-*</code> / <code>get-*</code> is allow; <code>create-*</code> / <code>delete-*</code> / <code>put-*</code> ask). kubectl, terraform, docker, podman, helm, and pulumi each have their own subcommand maps.</p>
</div>

<div class="chips" role="group" aria-label="Filter rules by decision">
  <button class="chip all"   data-filter="all"   aria-pressed="true"><i></i>All <span class="n">419</span></button>
  <button class="chip allow" data-filter="allow" aria-pressed="false"><i></i>Allow <span class="n">203</span></button>
  <button class="chip ask"   data-filter="ask"   aria-pressed="false"><i></i>Ask <span class="n">212</span></button>
  <button class="chip block" data-filter="block" aria-pressed="false"><i></i>Block <span class="n">4</span></button>
</div>

<div class="rule-card">
  <header>
    <h2>Blocked</h2>
    <a href="https://github.com/camjac251/tool-gates/blob/main/rules/cloud.toml" class="src" target="_blank" rel="noopener">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
      rules/cloud.toml#block
    </a>
    <span class="count">4 patterns</span>
  </header>

<div class="rule-row" data-decision="block" id="cloud-aws-iam-delete-user">
  <div class="rule-cmd"><span class="prog">aws</span> iam delete-user</div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Blocked: <code>aws iam delete-user</code> removes an IAM identity. Detach policies and rotate access keys via individual commands instead.</div>
</div>
<div class="rule-row" data-decision="block" id="cloud-aws-organizations-delete">
  <div class="rule-cmd"><span class="prog">aws</span> organizations delete</div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Blocked: <code>aws organizations delete-*</code> removes organization-level entities (accounts, OUs, policies). Effects span the whole org and are hard to reverse.</div>
</div>
<div class="rule-row" data-decision="block" id="cloud-kubectl-delete-namespace-kube-system">
  <div class="rule-cmd"><span class="prog">kubectl</span> delete namespace kube-system</div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Refusing to delete the <code>kube-system</code> namespace. It hosts core cluster services; deleting it breaks the cluster.</div>
</div>
<div class="rule-row" data-decision="block" id="cloud-kubectl-delete-ns-kube-system">
  <div class="rule-cmd"><span class="prog">kubectl</span> delete ns kube-system</div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Refusing to delete the <code>kube-system</code> namespace. It hosts core cluster services; deleting it breaks the cluster.</div>
</div>
</div>

<div class="rule-card">
  <header>
    <h2>Allowed · inspection</h2>
    <a href="https://github.com/camjac251/tool-gates/blob/main/rules/cloud.toml" class="src" target="_blank" rel="noopener">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
      rules/cloud.toml#allow
    </a>
    <span class="count">203 patterns</span>
  </header>

<div class="rule-row" data-decision="allow" id="cloud-aws-version">
  <div class="rule-cmd"><span class="prog">aws</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the AWS CLI version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-aws-help">
  <div class="rule-cmd"><span class="prog">aws</span> help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows AWS CLI help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-aws-s3-ls">
  <div class="rule-cmd"><span class="prog">aws</span> s3 ls</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists S3 buckets or objects under a prefix. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-aws-sts-get-caller-identity">
  <div class="rule-cmd"><span class="prog">aws</span> sts get-caller-identity</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports the IAM identity of the current credentials (account, ARN, user ID). Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-aws-sts-get-session-token">
  <div class="rule-cmd"><span class="prog">aws</span> sts get-session-token</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Returns temporary session credentials for the current identity. Read-only call; the returned token grants the same access until it expires.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-aws-configure-list">
  <div class="rule-cmd"><span class="prog">aws</span> configure list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows the resolved CLI configuration (profile, region, credential source). Read-only; values are masked.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-aws-describe">
  <div class="rule-cmd"><span class="prog">aws</span> describe-*</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">AWS describe-* operation: reads the configuration or state of a resource. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-aws-list">
  <div class="rule-cmd"><span class="prog">aws</span> list-*</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">AWS list-* operation: enumerates resources in the account/region. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-aws-get">
  <div class="rule-cmd"><span class="prog">aws</span> get-*</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">AWS get-* operation: fetches an attribute, object, or value. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-aws-head">
  <div class="rule-cmd"><span class="prog">aws</span> head-*</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">AWS head-* operation: fetches metadata only (e.g. S3 object headers) without the body. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-aws-query">
  <div class="rule-cmd"><span class="prog">aws</span> query-*</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">AWS query operation: reads items from a table or index (e.g. DynamoDB query). Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-aws-scan">
  <div class="rule-cmd"><span class="prog">aws</span> scan-*</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">AWS scan operation: reads across a whole table or index (e.g. DynamoDB scan). Read-only; can consume significant read capacity on large tables.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-aws-filter">
  <div class="rule-cmd"><span class="prog">aws</span> filter-*</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">AWS filter-* operation: reads a filtered view of events or records (e.g. CloudWatch Logs filter). Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-az-version">
  <div class="rule-cmd"><span class="prog">az</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the Azure CLI version and component versions. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-az-help">
  <div class="rule-cmd"><span class="prog">az</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows Azure CLI help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-az-h">
  <div class="rule-cmd"><span class="prog">az</span> -h</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows Azure CLI help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-ps">
  <div class="rule-cmd"><span class="prog">docker</span> ps</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker ps: lists running (or with <code>-a</code>, all) containers. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-images">
  <div class="rule-cmd"><span class="prog">docker</span> images</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker images: lists local images. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-inspect">
  <div class="rule-cmd"><span class="prog">docker</span> inspect</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker inspect: prints the low-level config of a container, image, or other object. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-logs">
  <div class="rule-cmd"><span class="prog">docker</span> logs</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker logs: prints or streams a container's stdout/stderr. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-stats">
  <div class="rule-cmd"><span class="prog">docker</span> stats</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker stats: shows live CPU/memory/IO usage per container. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-top">
  <div class="rule-cmd"><span class="prog">docker</span> top</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker top: lists the processes running inside a container. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-port">
  <div class="rule-cmd"><span class="prog">docker</span> port</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker port: shows the published port mappings for a container. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-version">
  <div class="rule-cmd"><span class="prog">docker</span> version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker version: prints client and daemon versions. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-info">
  <div class="rule-cmd"><span class="prog">docker</span> info</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker info: prints daemon-wide configuration and resource counts. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-history">
  <div class="rule-cmd"><span class="prog">docker</span> history</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker history: shows the layer history of an image. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-v">
  <div class="rule-cmd"><span class="prog">docker</span> -v</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the Docker version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-version-2">
  <div class="rule-cmd"><span class="prog">docker</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the Docker version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-h">
  <div class="rule-cmd"><span class="prog">docker</span> -h</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows Docker help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-help">
  <div class="rule-cmd"><span class="prog">docker</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows Docker help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-network-ls">
  <div class="rule-cmd"><span class="prog">docker</span> network ls</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker network ls: lists Docker networks. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-network-list">
  <div class="rule-cmd"><span class="prog">docker</span> network list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker network list: lists Docker networks. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-network-inspect">
  <div class="rule-cmd"><span class="prog">docker</span> network inspect</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker network inspect: prints a network's config and attached containers. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-volume-ls">
  <div class="rule-cmd"><span class="prog">docker</span> volume ls</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker volume ls: lists Docker volumes. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-volume-list">
  <div class="rule-cmd"><span class="prog">docker</span> volume list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker volume list: lists Docker volumes. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-volume-inspect">
  <div class="rule-cmd"><span class="prog">docker</span> volume inspect</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker volume inspect: prints a volume's config and mountpoint. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-system-df">
  <div class="rule-cmd"><span class="prog">docker</span> system df</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker system df: reports disk usage by images, containers, volumes, and cache. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-system-info">
  <div class="rule-cmd"><span class="prog">docker</span> system info</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker system info: prints daemon-wide configuration and resource counts. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-buildx-ls">
  <div class="rule-cmd"><span class="prog">docker</span> buildx ls</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker buildx ls: lists builder instances and their nodes. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-buildx-inspect">
  <div class="rule-cmd"><span class="prog">docker</span> buildx inspect</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker buildx inspect: prints a builder's config and status. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-buildx-version">
  <div class="rule-cmd"><span class="prog">docker</span> buildx version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the buildx plugin version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-scout-quickview">
  <div class="rule-cmd"><span class="prog">docker</span> scout quickview</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker Scout quickview: prints a vulnerability summary for an image. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-scout-cves">
  <div class="rule-cmd"><span class="prog">docker</span> scout cves</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker Scout cves: lists known CVEs in an image. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-scout-recommendations">
  <div class="rule-cmd"><span class="prog">docker</span> scout recommendations</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker Scout recommendations: suggests base-image and dependency updates for an image. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-scout-compare">
  <div class="rule-cmd"><span class="prog">docker</span> scout compare</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker Scout compare: diffs the vulnerability profile of two images. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-context-ls">
  <div class="rule-cmd"><span class="prog">docker</span> context ls</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker context ls: lists Docker contexts and marks the active one. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-context-list">
  <div class="rule-cmd"><span class="prog">docker</span> context list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker context list: lists Docker contexts and marks the active one. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-context-show">
  <div class="rule-cmd"><span class="prog">docker</span> context show</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker context show: prints the name of the active context. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-context-inspect">
  <div class="rule-cmd"><span class="prog">docker</span> context inspect</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker context inspect: prints a context's endpoint config. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-manifest-inspect">
  <div class="rule-cmd"><span class="prog">docker</span> manifest inspect</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker manifest inspect: prints a manifest list or image manifest from a registry. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-image-ls">
  <div class="rule-cmd"><span class="prog">docker</span> image ls</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker image ls: lists local images. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-image-list">
  <div class="rule-cmd"><span class="prog">docker</span> image list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker image list: lists local images. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-image-inspect">
  <div class="rule-cmd"><span class="prog">docker</span> image inspect</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker image inspect: prints an image's low-level config. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-image-history">
  <div class="rule-cmd"><span class="prog">docker</span> image history</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker image history: shows the layer history of an image. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-container-ls">
  <div class="rule-cmd"><span class="prog">docker</span> container ls</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker container ls: lists running (or with <code>-a</code>, all) containers. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-container-list">
  <div class="rule-cmd"><span class="prog">docker</span> container list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker container list: lists running (or with <code>-a</code>, all) containers. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-container-inspect">
  <div class="rule-cmd"><span class="prog">docker</span> container inspect</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker container inspect: prints a container's low-level config. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-container-logs">
  <div class="rule-cmd"><span class="prog">docker</span> container logs</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker container logs: prints or streams a container's stdout/stderr. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-container-top">
  <div class="rule-cmd"><span class="prog">docker</span> container top</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker container top: lists the processes running inside a container. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-container-stats">
  <div class="rule-cmd"><span class="prog">docker</span> container stats</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Docker container stats: shows live CPU/memory/IO usage per container. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-compose-ps">
  <div class="rule-cmd"><span class="prog">docker</span> compose ps</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Compose ps: lists the containers for the current compose project. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-compose-logs">
  <div class="rule-cmd"><span class="prog">docker</span> compose logs</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Compose logs: prints or streams logs from the project's service containers. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-compose-config">
  <div class="rule-cmd"><span class="prog">docker</span> compose config</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Compose config: renders the fully-resolved compose file to stdout. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-compose-images">
  <div class="rule-cmd"><span class="prog">docker</span> compose images</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Compose images: lists the images used by the project's services. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-compose-ls">
  <div class="rule-cmd"><span class="prog">docker</span> compose ls</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Compose ls: lists running compose projects. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-compose-version">
  <div class="rule-cmd"><span class="prog">docker</span> compose version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the Compose plugin version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-compose-top">
  <div class="rule-cmd"><span class="prog">docker</span> compose top</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Compose top: lists the processes running in the project's service containers. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-compose-ps-2">
  <div class="rule-cmd"><span class="prog">docker-compose</span> ps</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Compose ps: lists the containers for the current compose project. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-compose-logs-2">
  <div class="rule-cmd"><span class="prog">docker-compose</span> logs</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Compose logs: prints or streams logs from the project's service containers. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-compose-config-2">
  <div class="rule-cmd"><span class="prog">docker-compose</span> config</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Compose config: renders the fully-resolved compose file to stdout. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-compose-images-2">
  <div class="rule-cmd"><span class="prog">docker-compose</span> images</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Compose images: lists the images used by the project's services. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-compose-ls-2">
  <div class="rule-cmd"><span class="prog">docker-compose</span> ls</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Compose ls: lists running compose projects. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-compose-version-2">
  <div class="rule-cmd"><span class="prog">docker-compose</span> version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the Compose version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-compose-h">
  <div class="rule-cmd"><span class="prog">docker-compose</span> -h</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows Compose help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-docker-compose-help">
  <div class="rule-cmd"><span class="prog">docker-compose</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows Compose help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-gcloud-config-list">
  <div class="rule-cmd"><span class="prog">gcloud</span> config list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows the active gcloud configuration (account, project, region/zone). Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-gcloud-config-get-value">
  <div class="rule-cmd"><span class="prog">gcloud</span> config get-value</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints a single gcloud config value (e.g. <code>project</code>, <code>account</code>). Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-gcloud-auth-list">
  <div class="rule-cmd"><span class="prog">gcloud</span> auth list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists credentialed accounts and marks the active one. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-gcloud-auth-describe">
  <div class="rule-cmd"><span class="prog">gcloud</span> auth describe</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows details of a credentialed account (token status, scopes). Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-gcloud-projects-list">
  <div class="rule-cmd"><span class="prog">gcloud</span> projects list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists GCP projects the active account can see. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-gcloud-projects-describe">
  <div class="rule-cmd"><span class="prog">gcloud</span> projects describe</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows metadata for a project (number, state, labels). Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-gcloud-compute-instances-list">
  <div class="rule-cmd"><span class="prog">gcloud</span> compute instances list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists Compute Engine VMs in the project. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-gcloud-compute-instances-describe">
  <div class="rule-cmd"><span class="prog">gcloud</span> compute instances describe</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows the configuration and status of a VM. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-gcloud-compute-zones-list">
  <div class="rule-cmd"><span class="prog">gcloud</span> compute zones list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists available Compute Engine zones. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-gcloud-compute-regions-list">
  <div class="rule-cmd"><span class="prog">gcloud</span> compute regions list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists available Compute Engine regions and quotas. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-gcloud-compute-machine-types-list">
  <div class="rule-cmd"><span class="prog">gcloud</span> compute machine-types list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists available machine types per zone. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-gcloud-container-clusters-list">
  <div class="rule-cmd"><span class="prog">gcloud</span> container clusters list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists GKE clusters in the project. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-gcloud-container-clusters-describe">
  <div class="rule-cmd"><span class="prog">gcloud</span> container clusters describe</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows the configuration and status of a GKE cluster. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-gcloud-storage-ls">
  <div class="rule-cmd"><span class="prog">gcloud</span> storage ls</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists Cloud Storage buckets or objects under a prefix. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-gcloud-storage-cat">
  <div class="rule-cmd"><span class="prog">gcloud</span> storage cat</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Streams the contents of a Cloud Storage object to stdout. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-gcloud-functions-list">
  <div class="rule-cmd"><span class="prog">gcloud</span> functions list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists Cloud Functions in the project. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-gcloud-functions-describe">
  <div class="rule-cmd"><span class="prog">gcloud</span> functions describe</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows the configuration and status of a Cloud Function. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-gcloud-functions-logs">
  <div class="rule-cmd"><span class="prog">gcloud</span> functions logs</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reads execution logs for a Cloud Function. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-gcloud-run-services-list">
  <div class="rule-cmd"><span class="prog">gcloud</span> run services list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists Cloud Run services in the project. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-gcloud-run-services-describe">
  <div class="rule-cmd"><span class="prog">gcloud</span> run services describe</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows the configuration, revisions, and traffic split of a Cloud Run service. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-gcloud-sql-instances-list">
  <div class="rule-cmd"><span class="prog">gcloud</span> sql instances list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists Cloud SQL instances in the project. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-gcloud-sql-instances-describe">
  <div class="rule-cmd"><span class="prog">gcloud</span> sql instances describe</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows the configuration and status of a Cloud SQL instance. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-gcloud-logging-read">
  <div class="rule-cmd"><span class="prog">gcloud</span> logging read</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reads log entries from Cloud Logging. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-gcloud-iam-list">
  <div class="rule-cmd"><span class="prog">gcloud</span> iam list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists IAM resources (roles, service accounts, etc.) in the project. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-gcloud-iam-describe">
  <div class="rule-cmd"><span class="prog">gcloud</span> iam describe</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows details of an IAM resource (role, service account). Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-gcloud-secrets-list">
  <div class="rule-cmd"><span class="prog">gcloud</span> secrets list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists secrets in Secret Manager (names only, not payloads). Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-gcloud-secrets-describe">
  <div class="rule-cmd"><span class="prog">gcloud</span> secrets describe</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows metadata for a secret (replication, labels). Does not reveal the payload. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-gcloud-secrets-versions">
  <div class="rule-cmd"><span class="prog">gcloud</span> secrets versions</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists or describes versions of a secret (state, create time). Read-only; does not print payloads.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-gcloud-version">
  <div class="rule-cmd"><span class="prog">gcloud</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the gcloud CLI version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-gcloud-help">
  <div class="rule-cmd"><span class="prog">gcloud</span> help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows gcloud help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-gcloud-info">
  <div class="rule-cmd"><span class="prog">gcloud</span> info</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows gcloud environment diagnostics (SDK paths, active config, account). Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-helm-list">
  <div class="rule-cmd"><span class="prog">helm</span> list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Helm list: lists releases in the current namespace (or all with <code>-A</code>). Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-helm-ls">
  <div class="rule-cmd"><span class="prog">helm</span> ls</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Helm ls: lists releases in the current namespace (or all with <code>-A</code>). Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-helm-get">
  <div class="rule-cmd"><span class="prog">helm</span> get</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Helm get: prints details of an installed release (values, manifest, notes, hooks). Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-helm-show">
  <div class="rule-cmd"><span class="prog">helm</span> show</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Helm show: prints chart metadata, values, or README from a chart. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-helm-search">
  <div class="rule-cmd"><span class="prog">helm</span> search</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Helm search: searches repositories or the Artifact Hub for charts. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-helm-repo-list">
  <div class="rule-cmd"><span class="prog">helm</span> repo list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Helm repo list: lists configured chart repositories. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-helm-status">
  <div class="rule-cmd"><span class="prog">helm</span> status</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Helm status: prints the status of a named release. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-helm-history">
  <div class="rule-cmd"><span class="prog">helm</span> history</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Helm history: lists the revision history of a release. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-helm-version">
  <div class="rule-cmd"><span class="prog">helm</span> version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the Helm client version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-helm-h">
  <div class="rule-cmd"><span class="prog">helm</span> -h</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows Helm help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-helm-help">
  <div class="rule-cmd"><span class="prog">helm</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows Helm help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-helm-template">
  <div class="rule-cmd"><span class="prog">helm</span> template</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Helm template: renders chart templates to stdout locally. Read-only; does not contact the cluster.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-helm-lint">
  <div class="rule-cmd"><span class="prog">helm</span> lint</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Helm lint: checks a chart for issues and best-practice violations. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-helm-verify">
  <div class="rule-cmd"><span class="prog">helm</span> verify</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Helm verify: checks that a packaged chart's provenance signature is valid. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-kubectl-get">
  <div class="rule-cmd"><span class="prog">kubectl</span> get</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">kubectl get: lists or prints resources in the current context/namespace. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-kubectl-describe">
  <div class="rule-cmd"><span class="prog">kubectl</span> describe</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">kubectl describe: prints detailed state and recent events for a resource. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-kubectl-logs">
  <div class="rule-cmd"><span class="prog">kubectl</span> logs</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">kubectl logs: streams or prints container logs from a pod. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-kubectl-top">
  <div class="rule-cmd"><span class="prog">kubectl</span> top</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">kubectl top: shows CPU/memory usage for nodes or pods via the metrics API. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-kubectl-explain">
  <div class="rule-cmd"><span class="prog">kubectl</span> explain</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">kubectl explain: prints the schema/field docs for a resource kind. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-kubectl-api-resources">
  <div class="rule-cmd"><span class="prog">kubectl</span> api-resources</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">kubectl api-resources: lists the resource types the cluster serves. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-kubectl-api-versions">
  <div class="rule-cmd"><span class="prog">kubectl</span> api-versions</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">kubectl api-versions: lists the API group/versions the cluster serves. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-kubectl-cluster-info">
  <div class="rule-cmd"><span class="prog">kubectl</span> cluster-info</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">kubectl cluster-info: prints the control plane and core service endpoints. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-kubectl-version">
  <div class="rule-cmd"><span class="prog">kubectl</span> version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">kubectl version: prints client and server versions. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-kubectl-h">
  <div class="rule-cmd"><span class="prog">kubectl</span> -h</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows kubectl help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-kubectl-help">
  <div class="rule-cmd"><span class="prog">kubectl</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows kubectl help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-kubectl-config-view">
  <div class="rule-cmd"><span class="prog">kubectl</span> config view</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">kubectl config view: prints the merged kubeconfig. Read-only; secret values are redacted unless <code>--raw</code> is passed.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-kubectl-config-get-contexts">
  <div class="rule-cmd"><span class="prog">kubectl</span> config get-contexts</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">kubectl config get-contexts: lists contexts and marks the current one. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-kubectl-config-current-context">
  <div class="rule-cmd"><span class="prog">kubectl</span> config current-context</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">kubectl config current-context: prints the name of the active context. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-kubectl-config-get-clusters">
  <div class="rule-cmd"><span class="prog">kubectl</span> config get-clusters</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">kubectl config get-clusters: lists cluster entries in the kubeconfig. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-kubectl-auth-can-i">
  <div class="rule-cmd"><span class="prog">kubectl</span> auth can-i</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">kubectl auth can-i: checks whether the current user may perform an action. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-kubectl-auth-whoami">
  <div class="rule-cmd"><span class="prog">kubectl</span> auth whoami</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">kubectl auth whoami: prints the identity attributes the API server sees for the current user. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-kubectl-diff">
  <div class="rule-cmd"><span class="prog">kubectl</span> diff</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">kubectl diff: shows what <code>apply</code> would change by comparing the manifest against live state. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-kubectl-kustomize">
  <div class="rule-cmd"><span class="prog">kubectl</span> kustomize</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">kubectl kustomize: renders a kustomization to stdout. Read-only; does not contact the cluster.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-kubectl-wait">
  <div class="rule-cmd"><span class="prog">kubectl</span> wait</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">kubectl wait: blocks until a resource reaches a condition. Polls state; does not modify resources.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-podman-ps">
  <div class="rule-cmd"><span class="prog">podman</span> ps</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Podman ps: lists running (or with <code>-a</code>, all) containers. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-podman-images">
  <div class="rule-cmd"><span class="prog">podman</span> images</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Podman images: lists local images. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-podman-inspect">
  <div class="rule-cmd"><span class="prog">podman</span> inspect</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Podman inspect: prints the low-level config of a container or image. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-podman-logs">
  <div class="rule-cmd"><span class="prog">podman</span> logs</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Podman logs: prints or streams a container's stdout/stderr. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-podman-stats">
  <div class="rule-cmd"><span class="prog">podman</span> stats</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Podman stats: shows live CPU/memory/IO usage per container. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-podman-top">
  <div class="rule-cmd"><span class="prog">podman</span> top</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Podman top: lists the processes running inside a container. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-podman-port">
  <div class="rule-cmd"><span class="prog">podman</span> port</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Podman port: shows the published port mappings for a container. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-podman-version">
  <div class="rule-cmd"><span class="prog">podman</span> version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Podman version: prints client and (where applicable) service versions. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-podman-info">
  <div class="rule-cmd"><span class="prog">podman</span> info</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Podman info: prints host and storage configuration. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-podman-history">
  <div class="rule-cmd"><span class="prog">podman</span> history</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Podman history: shows the layer history of an image. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-podman-search">
  <div class="rule-cmd"><span class="prog">podman</span> search</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Podman search: queries configured registries for matching images. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-podman-healthcheck">
  <div class="rule-cmd"><span class="prog">podman</span> healthcheck</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Podman healthcheck: runs or reports a container's configured health check. Reports status; does not modify the container.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-podman-v">
  <div class="rule-cmd"><span class="prog">podman</span> -v</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the Podman version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-podman-version-2">
  <div class="rule-cmd"><span class="prog">podman</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the Podman version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-podman-h">
  <div class="rule-cmd"><span class="prog">podman</span> -h</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows Podman help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-podman-help">
  <div class="rule-cmd"><span class="prog">podman</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows Podman help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-podman-network-ls">
  <div class="rule-cmd"><span class="prog">podman</span> network ls</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Podman network ls: lists Podman networks. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-podman-network-list">
  <div class="rule-cmd"><span class="prog">podman</span> network list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Podman network list: lists Podman networks. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-podman-network-inspect">
  <div class="rule-cmd"><span class="prog">podman</span> network inspect</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Podman network inspect: prints a network's config and attached containers. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-podman-volume-ls">
  <div class="rule-cmd"><span class="prog">podman</span> volume ls</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Podman volume ls: lists Podman volumes. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-podman-volume-list">
  <div class="rule-cmd"><span class="prog">podman</span> volume list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Podman volume list: lists Podman volumes. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-podman-volume-inspect">
  <div class="rule-cmd"><span class="prog">podman</span> volume inspect</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Podman volume inspect: prints a volume's config and mountpoint. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-podman-system-df">
  <div class="rule-cmd"><span class="prog">podman</span> system df</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Podman system df: reports disk usage by images, containers, and volumes. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-podman-system-info">
  <div class="rule-cmd"><span class="prog">podman</span> system info</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Podman system info: prints host and storage configuration. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-podman-machine-info">
  <div class="rule-cmd"><span class="prog">podman</span> machine info</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Podman machine info: prints info about the Podman machine VM environment. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-podman-machine-inspect">
  <div class="rule-cmd"><span class="prog">podman</span> machine inspect</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Podman machine inspect: prints a Podman machine VM's config. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-podman-machine-list">
  <div class="rule-cmd"><span class="prog">podman</span> machine list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Podman machine list: lists Podman machine VMs and their state. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-podman-pod-ps">
  <div class="rule-cmd"><span class="prog">podman</span> pod ps</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Podman pod ps: lists pods and their state. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-podman-pod-list">
  <div class="rule-cmd"><span class="prog">podman</span> pod list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Podman pod list: lists pods and their state. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-podman-pod-inspect">
  <div class="rule-cmd"><span class="prog">podman</span> pod inspect</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Podman pod inspect: prints a pod's config and member containers. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-podman-pod-logs">
  <div class="rule-cmd"><span class="prog">podman</span> pod logs</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Podman pod logs: prints or streams logs from a pod's containers. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-podman-pod-top">
  <div class="rule-cmd"><span class="prog">podman</span> pod top</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Podman pod top: lists the processes running across a pod's containers. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-podman-pod-stats">
  <div class="rule-cmd"><span class="prog">podman</span> pod stats</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Podman pod stats: shows live resource usage for a pod's containers. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-podman-secret-ls">
  <div class="rule-cmd"><span class="prog">podman</span> secret ls</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Podman secret ls: lists secret names and metadata (not values). Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-podman-secret-list">
  <div class="rule-cmd"><span class="prog">podman</span> secret list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Podman secret list: lists secret names and metadata (not values). Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-podman-secret-inspect">
  <div class="rule-cmd"><span class="prog">podman</span> secret inspect</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Podman secret inspect: prints a secret's metadata. Does not reveal the value. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-pulumi-preview">
  <div class="rule-cmd"><span class="prog">pulumi</span> preview</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Pulumi preview: computes and prints the planned changes for the selected stack without applying them. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-pulumi-whoami">
  <div class="rule-cmd"><span class="prog">pulumi</span> whoami</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Pulumi whoami: prints the currently logged-in Pulumi identity and backend. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-pulumi-version">
  <div class="rule-cmd"><span class="prog">pulumi</span> version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the Pulumi CLI version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-pulumi-h">
  <div class="rule-cmd"><span class="prog">pulumi</span> -h</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows Pulumi help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-pulumi-help">
  <div class="rule-cmd"><span class="prog">pulumi</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows Pulumi help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-pulumi-stack-ls">
  <div class="rule-cmd"><span class="prog">pulumi</span> stack ls</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Pulumi stack ls: lists stacks for the current project and marks the active one. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-pulumi-stack-list">
  <div class="rule-cmd"><span class="prog">pulumi</span> stack list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Pulumi stack list: lists stacks for the current project and marks the active one. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-pulumi-stack-output">
  <div class="rule-cmd"><span class="prog">pulumi</span> stack output</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Pulumi stack output: prints the selected stack's outputs. Read-only; may expose sensitive outputs with <code>--show-secrets</code>.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-pulumi-stack-history">
  <div class="rule-cmd"><span class="prog">pulumi</span> stack history</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Pulumi stack history: lists past updates for the selected stack. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-pulumi-stack-export">
  <div class="rule-cmd"><span class="prog">pulumi</span> stack export</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Pulumi stack export: writes the selected stack's state deployment to stdout. Read-only; exposes full state including secrets.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-pulumi-config-get">
  <div class="rule-cmd"><span class="prog">pulumi</span> config get</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Pulumi config get: prints a single config value for the selected stack. Read-only; <code>--secret</code> values are decrypted to stdout.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-terraform-plan">
  <div class="rule-cmd"><span class="prog">terraform</span> plan</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Terraform plan: computes and prints the diff between config and state without changing infrastructure. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-terraform-show">
  <div class="rule-cmd"><span class="prog">terraform</span> show</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Terraform show: prints the current state or a saved plan in human-readable form. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-terraform-output">
  <div class="rule-cmd"><span class="prog">terraform</span> output</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Terraform output: prints the values of root module outputs from state. Read-only; may expose sensitive output values.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-terraform-validate">
  <div class="rule-cmd"><span class="prog">terraform</span> validate</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Terraform validate: checks config for syntax and internal consistency. Read-only; does not touch state or providers' APIs.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-terraform-version">
  <div class="rule-cmd"><span class="prog">terraform</span> version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the Terraform and provider versions. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-terraform-providers">
  <div class="rule-cmd"><span class="prog">terraform</span> providers</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Terraform providers: lists the providers required by the configuration. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-terraform-graph">
  <div class="rule-cmd"><span class="prog">terraform</span> graph</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Terraform graph: emits the dependency graph in DOT format. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-terraform-version-2">
  <div class="rule-cmd"><span class="prog">terraform</span> -version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the Terraform version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-terraform-version-3">
  <div class="rule-cmd"><span class="prog">terraform</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the Terraform version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-terraform-help">
  <div class="rule-cmd"><span class="prog">terraform</span> -help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows Terraform help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-terraform-help-2">
  <div class="rule-cmd"><span class="prog">terraform</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows Terraform help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-terraform-state-list">
  <div class="rule-cmd"><span class="prog">terraform</span> state list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Terraform state list: lists the resource addresses tracked in state. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-terraform-state-show">
  <div class="rule-cmd"><span class="prog">terraform</span> state show</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Terraform state show: prints the attributes of one resource from state. Read-only; may expose sensitive values.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-terraform-workspace-list">
  <div class="rule-cmd"><span class="prog">terraform</span> workspace list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Terraform workspace list: lists workspaces and marks the active one. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-terraform-workspace-show">
  <div class="rule-cmd"><span class="prog">terraform</span> workspace show</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Terraform workspace show: prints the name of the active workspace. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="cloud-terraform-fmt-check">
  <div class="rule-cmd"><span class="prog">terraform</span> fmt <span class="flag">-check</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Terraform fmt -check: reports whether <code>.tf</code> files match canonical style without rewriting them. Read-only.</div>
</div>
</div>

<div class="rule-card">
  <header>
    <h2>Asks first · mutations</h2>
    <a href="https://github.com/camjac251/tool-gates/blob/main/rules/cloud.toml" class="src" target="_blank" rel="noopener">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
      rules/cloud.toml#ask
    </a>
    <span class="count">212 patterns</span>
  </header>

<div class="rule-row" data-decision="ask" id="cloud-aws-create">
  <div class="rule-cmd"><span class="prog">aws</span> create-*</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">AWS create operation: provisions a new resource in the account. Verify region, profile, and resource type; provisioning may incur cost.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-aws-delete">
  <div class="rule-cmd"><span class="prog">aws</span> delete-*</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">AWS delete operation. Verify region, profile, and resource ID before approving; most deletions cannot be reversed.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-aws-put">
  <div class="rule-cmd"><span class="prog">aws</span> put-*</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">AWS put operation: writes or overwrites a resource (object, item, policy, parameter). Existing values are replaced; previous content may be lost.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-aws-update">
  <div class="rule-cmd"><span class="prog">aws</span> update-*</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">AWS update operation: changes the configuration of an existing resource. Effect is immediate; review the diff first.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-aws-modify">
  <div class="rule-cmd"><span class="prog">aws</span> modify-*</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">AWS modify operation: changes attributes of a running resource (instance type, security group, parameter). May restart or interrupt the resource.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-aws-remove">
  <div class="rule-cmd"><span class="prog">aws</span> remove-*</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">AWS remove operation: removes attached items (tags, permissions, members). Effect is immediate.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-aws-run">
  <div class="rule-cmd"><span class="prog">aws</span> run-*</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">AWS run operation: launches resources such as EC2 instances or task definitions. Billing starts when they reach running state.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-aws-start">
  <div class="rule-cmd"><span class="prog">aws</span> start-*</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">AWS start operation: starts a stopped resource (instance, DB, pipeline). Billing typically resumes once running.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-aws-stop">
  <div class="rule-cmd"><span class="prog">aws</span> stop-*</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">AWS stop operation: halts a running resource. Connected clients drop; storage bills usually continue.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-aws-terminate">
  <div class="rule-cmd"><span class="prog">aws</span> terminate-*</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">AWS terminate operation: permanently destroys the resource (instance, workflow execution). Attached ephemeral storage is lost.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-aws-reboot">
  <div class="rule-cmd"><span class="prog">aws</span> reboot-*</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">AWS reboot operation: restarts a running resource (instance, cache cluster, DB). Causes downtime during the reboot window.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-aws-attach">
  <div class="rule-cmd"><span class="prog">aws</span> attach-*</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">AWS attach operation: connects one resource to another (volume to instance, policy to role, gateway to VPC). Live traffic/state may shift.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-aws-detach">
  <div class="rule-cmd"><span class="prog">aws</span> detach-*</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">AWS detach operation: disconnects an attached resource (volume, policy, network interface). The detached side loses that access.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-aws-associate">
  <div class="rule-cmd"><span class="prog">aws</span> associate-*</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">AWS associate operation: links resources (route table to subnet, address to instance, IAM identity to provider). May reroute live traffic.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-aws-disassociate">
  <div class="rule-cmd"><span class="prog">aws</span> disassociate-*</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">AWS disassociate operation: unlinks resources (address from instance, route table from subnet). May break in-flight traffic.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-aws-enable">
  <div class="rule-cmd"><span class="prog">aws</span> enable-*</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">AWS enable operation: turns on a feature or service (logging, MFA, region, security control). Effect is immediate.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-aws-disable">
  <div class="rule-cmd"><span class="prog">aws</span> disable-*</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">AWS disable operation: turns off a feature or service (logging, MFA, security control). Coverage drops immediately.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-aws-register">
  <div class="rule-cmd"><span class="prog">aws</span> register-*</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">AWS register operation: registers a target with a service (task definition, target with load balancer, domain). Becomes live to that service.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-aws-deregister">
  <div class="rule-cmd"><span class="prog">aws</span> deregister-*</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">AWS deregister operation: removes a registered target (from load balancer, task definition). The target stops receiving traffic.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-aws-invoke">
  <div class="rule-cmd"><span class="prog">aws</span> invoke-*</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">AWS invoke operation: executes a function or state machine (Lambda, Step Functions). Side effects run in the cloud and may incur cost.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-aws-publish">
  <div class="rule-cmd"><span class="prog">aws</span> publish-*</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">AWS publish operation: publishes a message, version, or layer (SNS, Lambda version, layer version). Subscribers/consumers see it immediately.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-aws-send">
  <div class="rule-cmd"><span class="prog">aws</span> send-*</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">AWS send operation: dispatches a message or signal (SQS, SES, command to instance). Delivery is real-time and may cost per message.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-aws-tag">
  <div class="rule-cmd"><span class="prog">aws</span> tag-*</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">AWS tag operation: adds tags to a resource. Tags can drive billing allocation and IAM conditions; pick keys/values intentionally.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-aws-untag">
  <div class="rule-cmd"><span class="prog">aws</span> untag-*</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">AWS untag operation: removes tags from a resource. Tag-based IAM policies and cost allocation depending on those tags will stop applying.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-buildx-build">
  <div class="rule-cmd"><span class="prog">docker</span> buildx build</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker buildx build: builds an image (optionally multi-arch). Pulls base images and may push if <code>--push</code> is set.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-buildx-create">
  <div class="rule-cmd"><span class="prog">docker</span> buildx create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker buildx create: creates a new builder instance (may spin up a container or remote driver). Subsequent builds use it.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-buildx-rm">
  <div class="rule-cmd"><span class="prog">docker</span> buildx rm</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker buildx rm: removes a builder instance and its cache. In-progress builds against it fail.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-buildx-use">
  <div class="rule-cmd"><span class="prog">docker</span> buildx use</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker buildx use: sets the active builder. Subsequent <code>docker buildx build</code> calls use the selected builder.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-buildx-stop">
  <div class="rule-cmd"><span class="prog">docker</span> buildx stop</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker buildx stop: stops a running builder instance. In-progress builds on it are interrupted.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-buildx-prune">
  <div class="rule-cmd"><span class="prog">docker</span> buildx prune</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker buildx prune: deletes unused build cache. Frees disk; next builds are slower until cache rewarms.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-scout-enroll">
  <div class="rule-cmd"><span class="prog">docker</span> scout enroll</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker Scout enroll: opts the organization into Docker Scout vulnerability scanning. Image data is uploaded to Docker's service.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-context-create">
  <div class="rule-cmd"><span class="prog">docker</span> context create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker context create: registers a new daemon endpoint in the Docker config. Subsequent commands can target it.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-context-rm">
  <div class="rule-cmd"><span class="prog">docker</span> context rm</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker context rm: removes a context from the Docker config. If it was active, the default context becomes active.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-context-use">
  <div class="rule-cmd"><span class="prog">docker</span> context use</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker context use: switches the active daemon endpoint. Subsequent docker commands target the new daemon (potentially remote).</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-manifest-create">
  <div class="rule-cmd"><span class="prog">docker</span> manifest create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker manifest create: builds a local multi-arch manifest list referencing existing image digests. Not yet pushed to a registry.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-manifest-push">
  <div class="rule-cmd"><span class="prog">docker</span> manifest push</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker manifest push: publishes the manifest list to the registry. Consumers of that tag will pull the new manifest immediately.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-manifest-annotate">
  <div class="rule-cmd"><span class="prog">docker</span> manifest annotate</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker manifest annotate: edits a local manifest list (os/arch/variant). Push is a separate step.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-image-rm">
  <div class="rule-cmd"><span class="prog">docker</span> image rm</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker image rm: removes a local image (and its layers if unreferenced). Containers using that image still run.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-image-prune">
  <div class="rule-cmd"><span class="prog">docker</span> image prune</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker image prune: deletes dangling (or with <code>-a</code>, all unused) local images. Reclaims disk; can be expensive to repull.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-image-tag">
  <div class="rule-cmd"><span class="prog">docker</span> image tag</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker image tag: creates a new ref pointing at an existing image. Local-only until pushed.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-image-push">
  <div class="rule-cmd"><span class="prog">docker</span> image push</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker image push: uploads the image (and layers) to the registry under the given ref. Overwrites the tag for everyone consuming it.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-image-pull">
  <div class="rule-cmd"><span class="prog">docker</span> image pull</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker image pull: downloads an image from a registry. Network/disk usage; verify the ref is the intended source.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-container-rm">
  <div class="rule-cmd"><span class="prog">docker</span> container rm</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker container rm: removes a stopped container (with <code>-f</code>, also force-kills a running one). Anonymous volumes are removed only with <code>-v</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-container-start">
  <div class="rule-cmd"><span class="prog">docker</span> container start</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker container start: starts an existing stopped container. Bound ports and volumes from the original <code>run</code> reapply.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-container-stop">
  <div class="rule-cmd"><span class="prog">docker</span> container stop</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker container stop: sends SIGTERM then SIGKILL after the grace period. In-flight requests to the container drop.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-container-kill">
  <div class="rule-cmd"><span class="prog">docker</span> container kill</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker container kill: sends a signal (SIGKILL by default) directly. No graceful shutdown; in-flight work is lost.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-container-prune">
  <div class="rule-cmd"><span class="prog">docker</span> container prune</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker container prune: deletes all stopped containers. Their writable layers and anonymous state are gone.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-compose-up">
  <div class="rule-cmd"><span class="prog">docker</span> compose up</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Compose up: starts the services in the current compose file. Builds/pulls images as needed; with <code>-d</code> runs detached.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-compose-down">
  <div class="rule-cmd"><span class="prog">docker</span> compose down</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Compose down: stops and removes containers, networks, and (with <code>-v</code>) volumes for the project. Persistent state in named volumes survives unless <code>-v</code> is set.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-compose-start">
  <div class="rule-cmd"><span class="prog">docker</span> compose start</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Compose start: starts already-created service containers. Does not create or rebuild.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-compose-stop">
  <div class="rule-cmd"><span class="prog">docker</span> compose stop</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Compose stop: stops running service containers but leaves them in place. In-flight requests drop.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-compose-restart">
  <div class="rule-cmd"><span class="prog">docker</span> compose restart</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Compose restart: restarts service containers without recreating them. Brief downtime per service.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-compose-build">
  <div class="rule-cmd"><span class="prog">docker</span> compose build</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Compose build: builds (or rebuilds) the services' images per the compose file. Local-only until pushed.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-compose-pull">
  <div class="rule-cmd"><span class="prog">docker</span> compose pull</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Compose pull: pulls the service images from their registries. Disk/network usage.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-compose-push">
  <div class="rule-cmd"><span class="prog">docker</span> compose push</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Compose push: pushes the service images to their registries. Overwrites the tags for anyone consuming them.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-compose-exec">
  <div class="rule-cmd"><span class="prog">docker</span> compose exec</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Compose exec: runs a command inside a running service container. Side effects (writes, signals) happen in that live container.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-compose-run">
  <div class="rule-cmd"><span class="prog">docker</span> compose run</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Compose run: spins up a one-off service container with the given command. Leaves a stopped container behind unless <code>--rm</code> is set.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-compose-rm">
  <div class="rule-cmd"><span class="prog">docker</span> compose rm</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Compose rm: removes stopped service containers (with <code>-s</code> it also stops them first). Anonymous volumes go with <code>-v</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-compose-create">
  <div class="rule-cmd"><span class="prog">docker</span> compose create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Compose create: creates service containers without starting them. Useful before a separate <code>start</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-compose-kill">
  <div class="rule-cmd"><span class="prog">docker</span> compose kill</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Compose kill: sends SIGKILL to running service containers. No graceful shutdown.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-compose-pause">
  <div class="rule-cmd"><span class="prog">docker</span> compose pause</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Compose pause: freezes all processes in the service containers via cgroups. Connections hang until unpaused.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-compose-unpause">
  <div class="rule-cmd"><span class="prog">docker</span> compose unpause</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Compose unpause: resumes previously-paused service containers.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-run">
  <div class="rule-cmd"><span class="prog">docker</span> run</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker run: creates and starts a new container from an image. Honours <code>-v</code> mounts, port publishes, and <code>--privileged</code>; verify those before approving.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-exec">
  <div class="rule-cmd"><span class="prog">docker</span> exec</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker exec: runs a command inside an already-running container. Side effects happen in that live container.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-build">
  <div class="rule-cmd"><span class="prog">docker</span> build</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker build: builds an image from a Dockerfile. Pulls base images; local-only until pushed.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-push">
  <div class="rule-cmd"><span class="prog">docker</span> push</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker push: uploads an image to the registry under the given ref. Overwrites the tag for everyone consuming it.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-pull">
  <div class="rule-cmd"><span class="prog">docker</span> pull</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker pull: downloads an image from a registry. Network/disk usage; verify the ref.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-rm">
  <div class="rule-cmd"><span class="prog">docker</span> rm</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker rm: removes a stopped container (with <code>-f</code>, also force-kills a running one). Anonymous volumes go with <code>-v</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-rmi">
  <div class="rule-cmd"><span class="prog">docker</span> rmi</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker rmi: removes a local image. Containers using it still run; layers go when no ref remains.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-kill">
  <div class="rule-cmd"><span class="prog">docker</span> kill</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker kill: sends a signal (SIGKILL by default) directly to the container PID 1. No graceful shutdown.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-stop">
  <div class="rule-cmd"><span class="prog">docker</span> stop</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker stop: sends SIGTERM then SIGKILL after the grace period. In-flight requests drop.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-start">
  <div class="rule-cmd"><span class="prog">docker</span> start</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker start: starts an existing stopped container. Original <code>run</code> config (ports, mounts) reapplies.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-restart">
  <div class="rule-cmd"><span class="prog">docker</span> restart</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker restart: stops and starts the container. Brief downtime; existing config reapplies.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-pause">
  <div class="rule-cmd"><span class="prog">docker</span> pause</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker pause: freezes all processes in the container via cgroups. Connections hang until unpaused.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-unpause">
  <div class="rule-cmd"><span class="prog">docker</span> unpause</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker unpause: resumes a previously-paused container.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-tag">
  <div class="rule-cmd"><span class="prog">docker</span> tag</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker tag: creates a new ref pointing at an existing image. Local-only until pushed.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-commit">
  <div class="rule-cmd"><span class="prog">docker</span> commit</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker commit: creates a new image from a container's writable layer. Image is not reproducible from a Dockerfile.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-cp">
  <div class="rule-cmd"><span class="prog">docker</span> cp</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker cp: copies files between the local FS and a container. Overwrites destination paths.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-login">
  <div class="rule-cmd"><span class="prog">docker</span> login</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker login: writes registry credentials to <code>~/.docker/config.json</code> (or the configured credential helper). Anyone with read access to the file gets those credentials.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-logout">
  <div class="rule-cmd"><span class="prog">docker</span> logout</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker logout: removes registry credentials from the Docker config. Subsequent pulls/pushes to that registry need to re-auth.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-network-create">
  <div class="rule-cmd"><span class="prog">docker</span> network create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker network create: creates a user-defined network. Containers can be attached and discover each other by name.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-network-rm">
  <div class="rule-cmd"><span class="prog">docker</span> network rm</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker network rm: removes a network. Fails if containers are still attached; otherwise their inter-container DNS breaks.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-network-connect">
  <div class="rule-cmd"><span class="prog">docker</span> network connect</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker network connect: attaches a running container to an additional network. Gives it new addresses and DNS visibility.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-network-disconnect">
  <div class="rule-cmd"><span class="prog">docker</span> network disconnect</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker network disconnect: detaches a container from a network. Existing connections on that network drop.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-volume-create">
  <div class="rule-cmd"><span class="prog">docker</span> volume create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker volume create: creates a named volume managed by the engine. Persists across container recreates.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-volume-rm">
  <div class="rule-cmd"><span class="prog">docker</span> volume rm</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker volume rm: removes a named volume and its data. Fails if a container still references it; otherwise the data is gone.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-system-prune">
  <div class="rule-cmd"><span class="prog">docker</span> system prune</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Docker system prune: deletes stopped containers, unused networks, dangling images, and build cache (with <code>-a --volumes</code> also more). Reclaims disk; can be expensive to rebuild.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-compose-up-2">
  <div class="rule-cmd"><span class="prog">docker-compose</span> up</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Compose up: starts the services in the current compose file. Builds/pulls images as needed; with <code>-d</code> runs detached.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-compose-down-2">
  <div class="rule-cmd"><span class="prog">docker-compose</span> down</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Compose down: stops and removes containers, networks, and (with <code>-v</code>) volumes for the project. Named-volume data survives unless <code>-v</code> is set.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-compose-start-2">
  <div class="rule-cmd"><span class="prog">docker-compose</span> start</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Compose start: starts already-created service containers. Does not create or rebuild.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-compose-stop-2">
  <div class="rule-cmd"><span class="prog">docker-compose</span> stop</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Compose stop: stops running service containers but leaves them in place. In-flight requests drop.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-compose-restart-2">
  <div class="rule-cmd"><span class="prog">docker-compose</span> restart</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Compose restart: restarts service containers without recreating them. Brief downtime per service.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-compose-pause-2">
  <div class="rule-cmd"><span class="prog">docker-compose</span> pause</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Compose pause: freezes all processes in the service containers via cgroups. Connections hang until unpaused.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-compose-unpause-2">
  <div class="rule-cmd"><span class="prog">docker-compose</span> unpause</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Compose unpause: resumes previously-paused service containers.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-compose-build-2">
  <div class="rule-cmd"><span class="prog">docker-compose</span> build</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Compose build: builds (or rebuilds) the services' images per the compose file. Local-only until pushed.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-compose-push-2">
  <div class="rule-cmd"><span class="prog">docker-compose</span> push</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Compose push: pushes the service images to their registries. Overwrites the tags for consumers.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-compose-pull-2">
  <div class="rule-cmd"><span class="prog">docker-compose</span> pull</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Compose pull: pulls the service images from their registries. Disk/network usage.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-compose-rm-2">
  <div class="rule-cmd"><span class="prog">docker-compose</span> rm</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Compose rm: removes stopped service containers (with <code>-s</code> it also stops them first). Anonymous volumes go with <code>-v</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-compose-kill-2">
  <div class="rule-cmd"><span class="prog">docker-compose</span> kill</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Compose kill: sends SIGKILL to running service containers. No graceful shutdown.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-compose-exec-2">
  <div class="rule-cmd"><span class="prog">docker-compose</span> exec</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Compose exec: runs a command inside a running service container. Side effects happen in that live container.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-compose-run-2">
  <div class="rule-cmd"><span class="prog">docker-compose</span> run</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Compose run: spins up a one-off service container with the given command. Leaves a stopped container behind unless <code>--rm</code> is set.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-docker-compose-create-2">
  <div class="rule-cmd"><span class="prog">docker-compose</span> create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Compose create: creates service containers without starting them. Useful before a separate <code>start</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-gcloud-container-clusters-get-credentials">
  <div class="rule-cmd"><span class="prog">gcloud</span> container clusters get-credentials</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Fetches GKE cluster credentials and writes a context entry to <code>~/.kube/config</code>. Subsequent kubectl commands target that cluster.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-gcloud-compute-instances-create">
  <div class="rule-cmd"><span class="prog">gcloud</span> compute instances create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">GCE create: provisions a new VM in the project. Billing starts when it boots; verify zone, machine type, and network.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-gcloud-compute-instances-delete">
  <div class="rule-cmd"><span class="prog">gcloud</span> compute instances delete</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">GCE compute delete: terminates the VM. Persistent disks may or may not be deleted depending on flags.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-gcloud-compute-instances-start">
  <div class="rule-cmd"><span class="prog">gcloud</span> compute instances start</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">GCE start: boots a stopped VM. Compute billing resumes once the instance is running.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-gcloud-compute-instances-stop">
  <div class="rule-cmd"><span class="prog">gcloud</span> compute instances stop</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">GCE stop: shuts the VM down. Connections drop; persistent disks still bill while stopped.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-gcloud-compute-instances-reset">
  <div class="rule-cmd"><span class="prog">gcloud</span> compute instances reset</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">GCE reset: hard-reboots the VM without a clean shutdown. In-memory state and unflushed disk writes are lost.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-gcloud-container-clusters-create">
  <div class="rule-cmd"><span class="prog">gcloud</span> container clusters create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">GKE create: provisions a new Kubernetes cluster. Control plane and node pools begin billing immediately.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-gcloud-container-clusters-delete">
  <div class="rule-cmd"><span class="prog">gcloud</span> container clusters delete</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">GKE delete: tears down the cluster including all workloads. Cannot be reversed.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-gcloud-container-clusters-resize">
  <div class="rule-cmd"><span class="prog">gcloud</span> container clusters resize</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">GKE resize: changes node pool size. Scaling down evicts pods from removed nodes; scaling up adds nodes that begin billing.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-gcloud-container-clusters-upgrade">
  <div class="rule-cmd"><span class="prog">gcloud</span> container clusters upgrade</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">GKE upgrade: upgrades the control plane or node pool version. Workloads get rescheduled during node rollouts; cannot be downgraded mid-flight.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-gcloud-storage-cp">
  <div class="rule-cmd"><span class="prog">gcloud</span> storage cp</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">GCS copy: writes objects into a bucket. May overwrite existing objects at the same key.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-gcloud-storage-mv">
  <div class="rule-cmd"><span class="prog">gcloud</span> storage mv</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">GCS move: copies then deletes the source. Failure mid-operation can leave partial state at the destination.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-gcloud-storage-rm">
  <div class="rule-cmd"><span class="prog">gcloud</span> storage rm</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">GCS delete: removes objects from a bucket. Recursive (<code>-r</code>) on a prefix deletes every matching object; recovery requires object versioning.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-gcloud-functions-deploy">
  <div class="rule-cmd"><span class="prog">gcloud</span> functions deploy</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Cloud Functions deploy: uploads source and publishes a new revision. Traffic shifts to the new version once deployment succeeds.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-gcloud-functions-delete">
  <div class="rule-cmd"><span class="prog">gcloud</span> functions delete</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Cloud Functions delete: removes the function. Triggers stop firing immediately; callers get errors until recreated.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-gcloud-run-deploy">
  <div class="rule-cmd"><span class="prog">gcloud</span> run deploy</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Cloud Run deploy: builds/pulls the image and rolls out a new revision. Traffic shifts to it per the service's traffic policy.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-gcloud-run-services-delete">
  <div class="rule-cmd"><span class="prog">gcloud</span> run services delete</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Cloud Run delete: removes the service. Live traffic returns 404 until redeploy.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-gcloud-sql-instances-create">
  <div class="rule-cmd"><span class="prog">gcloud</span> sql instances create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Cloud SQL create: provisions a managed database instance. Billing starts at create time; tier and storage choices are sticky.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-gcloud-sql-instances-delete">
  <div class="rule-cmd"><span class="prog">gcloud</span> sql instances delete</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Cloud SQL delete: removes the database instance and its data. Restore requires a prior backup; otherwise data is gone.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-gcloud-sql-instances-patch">
  <div class="rule-cmd"><span class="prog">gcloud</span> sql instances patch</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Cloud SQL patch: changes instance settings (tier, flags, maintenance, network). Some changes restart the instance.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-gcloud-secrets-create">
  <div class="rule-cmd"><span class="prog">gcloud</span> secrets create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Secret Manager create: creates a new secret container. Initial payload value (if provided) lands in Cloud audit logs at IAM read.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-gcloud-secrets-delete">
  <div class="rule-cmd"><span class="prog">gcloud</span> secrets delete</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Secret Manager delete: removes the secret and all its versions. Consumers that read it will start failing immediately.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-gcloud-projects-create">
  <div class="rule-cmd"><span class="prog">gcloud</span> projects create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">GCP project create: provisions a new project under your org/billing. Project IDs are globally unique and cannot be reused.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-gcloud-projects-delete">
  <div class="rule-cmd"><span class="prog">gcloud</span> projects delete</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">GCP project delete: schedules the project for deletion (30-day grace). All resources go offline immediately.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-helm-repo-add">
  <div class="rule-cmd"><span class="prog">helm</span> repo add</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Helm repo add: registers a chart repository in the local Helm config. Subsequent installs can pull charts from it.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-helm-repo-remove">
  <div class="rule-cmd"><span class="prog">helm</span> repo remove</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Helm repo remove: removes a chart repository from the local Helm config. Existing releases keep running.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-helm-repo-update">
  <div class="rule-cmd"><span class="prog">helm</span> repo update</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Helm repo update: refreshes the local index for all repos. Read-only on clusters; updates local cache files.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-helm-install">
  <div class="rule-cmd"><span class="prog">helm</span> install</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Helm install: deploys a chart as a new release into the current kube context/namespace. Creates the resources defined in the chart.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-helm-upgrade">
  <div class="rule-cmd"><span class="prog">helm</span> upgrade</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Helm upgrade: applies a new chart version or values to an existing release. Workloads may roll; use <code>--atomic</code> to auto-rollback on failure.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-helm-uninstall">
  <div class="rule-cmd"><span class="prog">helm</span> uninstall</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Helm uninstall: removes a release and all its Kubernetes resources from the cluster. Persistent volumes may be retained per chart settings.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-helm-rollback">
  <div class="rule-cmd"><span class="prog">helm</span> rollback</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Helm rollback: rolls a release back to a previous revision. Workloads roll to match the earlier manifests.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-helm-delete">
  <div class="rule-cmd"><span class="prog">helm</span> delete</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Helm delete: removes a release (alias for uninstall in Helm 3). The release's Kubernetes resources are deleted.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-helm-push">
  <div class="rule-cmd"><span class="prog">helm</span> push</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Helm push: uploads a packaged chart to an OCI registry. Overwrites the chart version for consumers of that ref.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-helm-package">
  <div class="rule-cmd"><span class="prog">helm</span> package</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Helm package: bundles a chart directory into a <code>.tgz</code>. Local-only until pushed.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-kubectl-debug">
  <div class="rule-cmd"><span class="prog">kubectl</span> debug</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">kubectl debug: attaches an ephemeral debug container to a running pod or node. The debug container runs with the target's namespace and may have elevated access.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-kubectl-apply">
  <div class="rule-cmd"><span class="prog">kubectl</span> apply</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">kubectl apply: creates or updates resources from a manifest in the current context/namespace. Drift between cluster and file is reconciled toward the file.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-kubectl-create">
  <div class="rule-cmd"><span class="prog">kubectl</span> create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">kubectl create: imperatively creates a resource in the current context/namespace. Fails if the resource already exists.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-kubectl-delete">
  <div class="rule-cmd"><span class="prog">kubectl</span> delete</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">kubectl delete: removes the resource from the cluster. Verify namespace/context; many resources cascade-delete dependents.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-kubectl-edit">
  <div class="rule-cmd"><span class="prog">kubectl</span> edit</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">kubectl edit: opens the live resource in $EDITOR and applies on save. Changes go straight to the cluster; no diff review.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-kubectl-patch">
  <div class="rule-cmd"><span class="prog">kubectl</span> patch</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">kubectl patch: applies a strategic/JSON/merge patch to a live resource. Effect is immediate; rolling updates can trigger pod restarts.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-kubectl-replace">
  <div class="rule-cmd"><span class="prog">kubectl</span> replace</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">kubectl replace: replaces a live resource entirely with the manifest. Fields absent from the file are dropped; <code>--force</code> deletes and recreates.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-kubectl-scale">
  <div class="rule-cmd"><span class="prog">kubectl</span> scale</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">kubectl scale: changes the replica count on a Deployment/StatefulSet/ReplicaSet. Scaling to 0 stops the workload.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-kubectl-rollout">
  <div class="rule-cmd"><span class="prog">kubectl</span> rollout</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">kubectl rollout: triggers, pauses, resumes, undoes, or restarts a Deployment/DaemonSet/StatefulSet rollout. Pods get replaced per the strategy.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-kubectl-expose">
  <div class="rule-cmd"><span class="prog">kubectl</span> expose</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">kubectl expose: creates a Service in front of a workload. With type=LoadBalancer it provisions a cloud LB; type=NodePort opens a node port.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-kubectl-run">
  <div class="rule-cmd"><span class="prog">kubectl</span> run</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">kubectl run: creates a pod in the current namespace from an image. Useful for one-off shells/jobs; leaves a pod behind unless <code>--rm</code> is set.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-kubectl-exec">
  <div class="rule-cmd"><span class="prog">kubectl</span> exec</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">kubectl exec: runs a command inside a running container. Side effects (writes, signals) happen in the live pod.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-kubectl-cp">
  <div class="rule-cmd"><span class="prog">kubectl</span> cp</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">kubectl cp: copies files between local FS and a pod via <code>tar</code> in the container. Requires <code>tar</code> in the container image.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-kubectl-port-forward">
  <div class="rule-cmd"><span class="prog">kubectl</span> port-forward</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">kubectl port-forward: tunnels a local port to a pod/service. Anyone on the local host can reach the forwarded target while running.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-kubectl-label">
  <div class="rule-cmd"><span class="prog">kubectl</span> label</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">kubectl label: adds, updates, or removes labels on a resource. Labels drive selectors (Services, NetworkPolicies, scheduling); changes can shift routing.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-kubectl-annotate">
  <div class="rule-cmd"><span class="prog">kubectl</span> annotate</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">kubectl annotate: adds, updates, or removes annotations on a resource. Annotations can configure controllers (ingress, autoscaler, sidecars).</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-kubectl-taint">
  <div class="rule-cmd"><span class="prog">kubectl</span> taint</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">kubectl taint: adds a taint to a node so non-tolerating pods avoid it. With <code>NoExecute</code>, existing non-tolerating pods are evicted.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-kubectl-drain">
  <div class="rule-cmd"><span class="prog">kubectl</span> drain</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">kubectl drain: cordons the node and evicts its pods to other nodes. Confirm replicas/replacements exist before approving.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-kubectl-cordon">
  <div class="rule-cmd"><span class="prog">kubectl</span> cordon</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">kubectl cordon: marks a node unschedulable. Existing pods stay; new pods land elsewhere.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-kubectl-uncordon">
  <div class="rule-cmd"><span class="prog">kubectl</span> uncordon</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">kubectl uncordon: marks a node schedulable again. The scheduler resumes placing new pods on it.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-kubectl-config-set-context">
  <div class="rule-cmd"><span class="prog">kubectl</span> config set-context</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">kubectl config set-context: writes a context entry to <code>~/.kube/config</code>. Sets cluster, user, and default namespace for that context.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-kubectl-config-use-context">
  <div class="rule-cmd"><span class="prog">kubectl</span> config use-context</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">kubectl config use-context: switches the current context in <code>~/.kube/config</code>. Subsequent kubectl commands target the new cluster/namespace.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-kubectl-config-set-cluster">
  <div class="rule-cmd"><span class="prog">kubectl</span> config set-cluster</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">kubectl config set-cluster: writes a cluster entry (server URL, CA data) to <code>~/.kube/config</code>. Misconfigured CA bypasses TLS verification.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-kubectl-config-set-credentials">
  <div class="rule-cmd"><span class="prog">kubectl</span> config set-credentials</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">kubectl config set-credentials: writes auth data (token, cert, exec plugin) to <code>~/.kube/config</code>. Anyone with read access to the file gets those credentials.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-kubectl-config-delete-context">
  <div class="rule-cmd"><span class="prog">kubectl</span> config delete-context</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">kubectl config delete-context: removes a context from <code>~/.kube/config</code>. The cluster and user entries it referenced are left intact.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-kubectl-config-delete-cluster">
  <div class="rule-cmd"><span class="prog">kubectl</span> config delete-cluster</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">kubectl config delete-cluster: removes a cluster entry from <code>~/.kube/config</code>. Contexts that referenced it stop working.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-podman-run">
  <div class="rule-cmd"><span class="prog">podman</span> run</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Podman run: creates and starts a new container from an image. Honours <code>-v</code> mounts and port publishes; verify those before approving.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-podman-exec">
  <div class="rule-cmd"><span class="prog">podman</span> exec</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Podman exec: runs a command inside an already-running container. Side effects happen in that live container.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-podman-build">
  <div class="rule-cmd"><span class="prog">podman</span> build</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Podman build: builds an image from a Containerfile/Dockerfile. Pulls base images; local-only until pushed.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-podman-push">
  <div class="rule-cmd"><span class="prog">podman</span> push</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Podman push: uploads an image to the registry under the given ref. Overwrites the tag for consumers.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-podman-pull">
  <div class="rule-cmd"><span class="prog">podman</span> pull</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Podman pull: downloads an image from a registry. Network/disk usage; verify the ref.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-podman-rm">
  <div class="rule-cmd"><span class="prog">podman</span> rm</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Podman rm: removes a stopped container (with <code>-f</code>, also force-kills a running one). Anonymous volumes go with <code>-v</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-podman-rmi">
  <div class="rule-cmd"><span class="prog">podman</span> rmi</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Podman rmi: removes a local image. Containers using it still run; layers go when no ref remains.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-podman-kill">
  <div class="rule-cmd"><span class="prog">podman</span> kill</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Podman kill: sends a signal (SIGKILL by default) to the container PID 1. No graceful shutdown.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-podman-stop">
  <div class="rule-cmd"><span class="prog">podman</span> stop</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Podman stop: sends SIGTERM then SIGKILL after the grace period. In-flight requests drop.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-podman-start">
  <div class="rule-cmd"><span class="prog">podman</span> start</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Podman start: starts an existing stopped container. Original <code>run</code> config (ports, mounts) reapplies.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-podman-restart">
  <div class="rule-cmd"><span class="prog">podman</span> restart</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Podman restart: stops and starts the container. Brief downtime; existing config reapplies.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-podman-pause">
  <div class="rule-cmd"><span class="prog">podman</span> pause</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Podman pause: freezes all processes in the container via cgroups. Connections hang until unpaused.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-podman-unpause">
  <div class="rule-cmd"><span class="prog">podman</span> unpause</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Podman unpause: resumes a previously-paused container.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-podman-tag">
  <div class="rule-cmd"><span class="prog">podman</span> tag</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Podman tag: creates a new ref pointing at an existing image. Local-only until pushed.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-podman-commit">
  <div class="rule-cmd"><span class="prog">podman</span> commit</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Podman commit: creates a new image from a container's writable layer. Image is not reproducible from a Containerfile.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-podman-cp">
  <div class="rule-cmd"><span class="prog">podman</span> cp</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Podman cp: copies files between the local FS and a container. Overwrites destination paths.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-podman-login">
  <div class="rule-cmd"><span class="prog">podman</span> login</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Podman login: writes registry credentials to the auth store. Anyone with read access to the file gets those credentials.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-podman-logout">
  <div class="rule-cmd"><span class="prog">podman</span> logout</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Podman logout: removes registry credentials from the auth store. Subsequent pulls/pushes need to re-auth.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-podman-create">
  <div class="rule-cmd"><span class="prog">podman</span> create</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Podman create: creates a container without starting it. Useful before a separate <code>start</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-podman-pod">
  <div class="rule-cmd"><span class="prog">podman</span> pod</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Podman pod: pod-level operation (create/start/stop/rm). Affects all containers in the pod at once.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-podman-generate">
  <div class="rule-cmd"><span class="prog">podman</span> generate</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Podman generate: emits Kubernetes/systemd config from existing containers or pods to stdout (or a file). May write to disk depending on flags.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-podman-play">
  <div class="rule-cmd"><span class="prog">podman</span> play</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Podman play: creates pods and containers from a Kubernetes YAML manifest. Pulls images and starts workloads locally.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-pulumi-up">
  <div class="rule-cmd"><span class="prog">pulumi</span> up</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Pulumi up: applies the current program to the selected stack, creating/updating/deleting cloud resources. Run <code>pulumi preview</code> first.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-pulumi-destroy">
  <div class="rule-cmd"><span class="prog">pulumi</span> destroy</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Pulumi destroy: tears down every resource tracked by the selected stack. Cannot be undone without recreating from code.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-pulumi-refresh">
  <div class="rule-cmd"><span class="prog">pulumi</span> refresh</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Pulumi refresh: reconciles state with the real cloud, updating the state file to match what is actually deployed.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-pulumi-import">
  <div class="rule-cmd"><span class="prog">pulumi</span> import</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Pulumi import: brings an existing cloud resource under Pulumi management and emits code for it. Verify the resource address matches the program.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-pulumi-cancel">
  <div class="rule-cmd"><span class="prog">pulumi</span> cancel</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Pulumi cancel: forcibly cancels an in-progress update on the stack. Partial state on the cloud side may not match the state file.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-pulumi-new">
  <div class="rule-cmd"><span class="prog">pulumi</span> new</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Pulumi new: scaffolds a new project (and stack) in the current directory. Writes program files and <code>Pulumi.yaml</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-pulumi-stack-init">
  <div class="rule-cmd"><span class="prog">pulumi</span> stack init</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Pulumi stack init: creates a new stack under the current project. The stack starts empty until <code>pulumi up</code> runs.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-pulumi-stack-rm">
  <div class="rule-cmd"><span class="prog">pulumi</span> stack rm</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Pulumi stack rm: removes the stack's state and config. Use <code>--force</code> only after <code>pulumi destroy</code>; otherwise cloud resources are orphaned.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-pulumi-stack-select">
  <div class="rule-cmd"><span class="prog">pulumi</span> stack select</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Pulumi stack select: switches the active stack. Subsequent <code>up</code>/<code>destroy</code>/<code>config</code> commands target the selected stack.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-pulumi-config-set">
  <div class="rule-cmd"><span class="prog">pulumi</span> config set</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Pulumi config set: writes a config value (optionally encrypted with <code>--secret</code>) into the stack's config file.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-pulumi-config-rm">
  <div class="rule-cmd"><span class="prog">pulumi</span> config rm</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Pulumi config rm: removes a config key from the stack. Programs that read it will fall back to defaults or error.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-terraform-test">
  <div class="rule-cmd"><span class="prog">terraform</span> test</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Terraform test: runs <code>.tftest.hcl</code> cases. With <code>command = apply</code> (default), test cases create real infrastructure for the duration of the run.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-terraform-console">
  <div class="rule-cmd"><span class="prog">terraform</span> console</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Terraform console: interactive REPL against the current state. Evaluates expressions only, but reads state from the configured backend.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-terraform-force-unlock">
  <div class="rule-cmd"><span class="prog">terraform</span> force-unlock</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Terraform force-unlock removes a stuck state lock. Confirm no other apply is in progress; concurrent applies corrupt state.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-terraform-apply">
  <div class="rule-cmd"><span class="prog">terraform</span> apply</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Terraform apply: applies planned changes to real infrastructure. Run <code>terraform plan</code> first and review the diff.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-terraform-destroy">
  <div class="rule-cmd"><span class="prog">terraform</span> destroy</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Terraform destroy: tears down resources tracked by this state. Use <code>-target</code> to scope; cannot be undone.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-terraform-import">
  <div class="rule-cmd"><span class="prog">terraform</span> import</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Terraform import: brings an existing real resource under terraform management. Verify the address matches your config.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-terraform-taint">
  <div class="rule-cmd"><span class="prog">terraform</span> taint</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Terraform taint: marks a resource for replacement on the next apply. The next <code>apply</code> will destroy and recreate it.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-terraform-untaint">
  <div class="rule-cmd"><span class="prog">terraform</span> untaint</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Terraform untaint: clears the tainted mark from a resource so the next apply does not replace it.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-terraform-init">
  <div class="rule-cmd"><span class="prog">terraform</span> init</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Terraform init: downloads providers/modules and configures the backend. Writes <code>.terraform/</code> and <code>.terraform.lock.hcl</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-terraform-fmt">
  <div class="rule-cmd"><span class="prog">terraform</span> fmt</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Terraform fmt: rewrites <code>.tf</code> files in place to canonical style. Use <code>-check</code> to verify without modifying.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-terraform-state-mv">
  <div class="rule-cmd"><span class="prog">terraform</span> state mv</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Terraform state mv: renames or reparents resources in state. Validate addresses; mistakes leave resources orphaned.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-terraform-state-rm">
  <div class="rule-cmd"><span class="prog">terraform</span> state rm</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Terraform state rm: drops a resource from state without destroying it in the cloud. The resource becomes unmanaged.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-terraform-state-push">
  <div class="rule-cmd"><span class="prog">terraform</span> state push</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Terraform state push: overwrites remote state with local. Take a backup of remote state first.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-terraform-state-pull">
  <div class="rule-cmd"><span class="prog">terraform</span> state pull</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Terraform state pull: downloads the current remote state to stdout. Read-only on remote state, but exposes sensitive values.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-terraform-workspace-new">
  <div class="rule-cmd"><span class="prog">terraform</span> workspace new</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Terraform workspace new: creates a new workspace with its own state file. Subsequent commands run against it until switched.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-terraform-workspace-delete">
  <div class="rule-cmd"><span class="prog">terraform</span> workspace delete</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Terraform workspace delete: removes the workspace and its state file. State cannot be recovered after deletion.</div>
</div>
<div class="rule-row" data-decision="ask" id="cloud-terraform-workspace-select">
  <div class="rule-cmd"><span class="prog">terraform</span> workspace select</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Terraform workspace select: switches the active workspace. Subsequent plan/apply runs target the selected workspace's state.</div>
</div>
</div>

<p class="note">
  <svg class="alert" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 9v4"></path><path d="M12 17h.01"></path><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"></path></svg>
  <span><b>Custom handlers do the heavy lifting.</b> <code>check_gcloud</code> handles 3-word patterns (<code>gcloud compute instances create</code>). <code>check_docker</code> handles <code>docker compose</code> with flags between the subcommand. The action-prefix machinery for AWS is declarative in TOML but enforced in Rust at parse time.</span>
</p>
