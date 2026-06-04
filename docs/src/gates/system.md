<div class="gate-head">
  <p class="breadcrumb"><a href="../index.html">Gates</a> / system</p>
  <h1>system gate</h1>
  <div class="gate-meta">
    <span class="tag">priority <b>40</b></span>
    <span class="tag">unknown <b>block</b></span>
    <span class="tag">covers <b>databases · build tools · sudo · systemctl · OS package managers · crypto</b></span>
    <span class="tag">heavy block floor</span>
  </div>

  <div class="summary" aria-label="Rule counts at a glance">
    <div class="seg-bar" role="img" aria-label="273 allow, 188 ask, 36 block">
      <div class="seg allow" style="flex: 273"></div>
      <div class="seg ask"   style="flex: 188"></div>
      <div class="seg block" style="flex: 36"></div>
    </div>
    <div class="counts">
      <span class="ca"><i></i><b>273</b> allow</span>
      <span class="cas"><i></i><b>188</b> ask</span>
      <span class="cb"><i></i><b>36</b> block</span>
    </div>
  </div>

  <p class="gate-lede">OS-level operations: power, disk, kernel modules, firewall, users, plus database clients and crypto. This gate owns the largest block floor of any gate (30+ patterns). See the <a href="../security-floor.html">Security floor</a> for the full block list.</p>
</div>

<div class="chips" role="group" aria-label="Filter rules by decision">
  <button class="chip all"   data-filter="all"   aria-pressed="true"><i></i>All <span class="n">497</span></button>
  <button class="chip allow" data-filter="allow" aria-pressed="false"><i></i>Allow <span class="n">273</span></button>
  <button class="chip ask"   data-filter="ask"   aria-pressed="false"><i></i>Ask <span class="n">188</span></button>
  <button class="chip block" data-filter="block" aria-pressed="false"><i></i>Block <span class="n">36</span></button>
</div>

<div class="rule-card">
  <header>
    <h2>Blocked · destructive OS operations</h2>
    <a href="https://github.com/camjac251/tool-gates/blob/main/rules/system.toml" class="src" target="_blank" rel="noopener">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
      rules/system.toml#block
    </a>
    <span class="count">36 patterns</span>
  </header>

<div class="rule-row" data-decision="block" id="system-chattr">
  <div class="rule-cmd"><span class="prog">chattr</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">File attribute change blocked: agent has no authority to change extended file attributes. Misconfigured attributes can render files unmodifiable. Ask the user to run chattr themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-chsh">
  <div class="rule-cmd"><span class="prog">chsh</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Shell change blocked: agent has no authority to change a user's login shell. Ask the user to run chsh themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-dd">
  <div class="rule-cmd"><span class="prog">dd</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Low-level disk operation blocked: agent has no authority to run raw block-device writes. The wrong destination overwrites a disk without warning. Ask the user to run dd themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-fdisk">
  <div class="rule-cmd"><span class="prog">fdisk</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Disk partitioning blocked: agent has no authority to repartition disks. Mistakes here destroy data permanently. Ask the user to run partitioning themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-firewall-cmd">
  <div class="rule-cmd"><span class="prog">firewall-cmd</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Firewall modification blocked: agent has no authority to modify firewall rules. Misconfigured rules can lock the user out of the system. Ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-gdisk">
  <div class="rule-cmd"><span class="prog">gdisk</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Disk partitioning blocked: agent has no authority to repartition disks. Mistakes here destroy data permanently. Ask the user to run partitioning themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-grub-install">
  <div class="rule-cmd"><span class="prog">grub-install</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Bootloader modification blocked: agent has no authority to modify the bootloader. A bad bootloader leaves the system unbootable. Ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-halt">
  <div class="rule-cmd"><span class="prog">halt</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">System power command blocked: agent has no authority to shut down or reboot the machine. If genuinely needed, ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-hdparm">
  <div class="rule-cmd"><span class="prog">hdparm</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Disk parameters blocked: agent has no authority to change disk-firmware parameters. Wrong values can brick drives. Ask the user to run hdparm themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-init">
  <div class="rule-cmd"><span class="prog">init</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">System power command blocked: agent has no authority to shut down or reboot the machine. If genuinely needed, ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-insmod">
  <div class="rule-cmd"><span class="prog">insmod</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Kernel module loading blocked: agent has no authority to load kernel modules. Module changes affect the entire running kernel. Ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-iptables">
  <div class="rule-cmd"><span class="prog">iptables</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Firewall modification blocked: agent has no authority to modify firewall rules. Misconfigured rules can lock the user out of the system. Ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-lvremove">
  <div class="rule-cmd"><span class="prog">lvremove</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">LVM management blocked: agent has no authority to remove physical volumes, volume groups, or logical volumes. Removal is irreversible and can destroy mounted filesystems on top of the LVM stack. Ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-mke2fs">
  <div class="rule-cmd"><span class="prog">mke2fs</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Filesystem creation blocked: agent has no authority to format filesystems. The wrong target erases data permanently. Ask the user to run mke2fs themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-mkfs">
  <div class="rule-cmd"><span class="prog">mkfs</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Disk partitioning blocked: agent has no authority to repartition disks. Mistakes here destroy data permanently. Ask the user to run partitioning themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-mkswap">
  <div class="rule-cmd"><span class="prog">mkswap</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Swap creation blocked: agent has no authority to create swap areas on devices. The wrong target overwrites a device. Ask the user to run mkswap themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-modprobe">
  <div class="rule-cmd"><span class="prog">modprobe</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Kernel module loading blocked: agent has no authority to load kernel modules. Module changes affect the entire running kernel. Ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-parted">
  <div class="rule-cmd"><span class="prog">parted</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Disk partitioning blocked: agent has no authority to repartition disks. Mistakes here destroy data permanently. Ask the user to run partitioning themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-passwd">
  <div class="rule-cmd"><span class="prog">passwd</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Password change blocked: agent has no authority to change account passwords. Ask the user to run passwd themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-poweroff">
  <div class="rule-cmd"><span class="prog">poweroff</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">System power command blocked: agent has no authority to shut down or reboot the machine. If genuinely needed, ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-pvremove">
  <div class="rule-cmd"><span class="prog">pvremove</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">LVM management blocked: agent has no authority to remove physical volumes, volume groups, or logical volumes. Removal is irreversible and can destroy mounted filesystems on top of the LVM stack. Ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-reboot">
  <div class="rule-cmd"><span class="prog">reboot</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">System power command blocked: agent has no authority to shut down or reboot the machine. If genuinely needed, ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-rmmod">
  <div class="rule-cmd"><span class="prog">rmmod</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Kernel module removal blocked: agent has no authority to unload kernel modules. Removal can destabilize the running kernel. Ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-shred">
  <div class="rule-cmd"><span class="prog">shred</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Secure delete blocked: agent has no authority to wipe files irreversibly. Ask the user to run shred themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-shutdown">
  <div class="rule-cmd"><span class="prog">shutdown</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">System power command blocked: agent has no authority to shut down or reboot the machine. If genuinely needed, ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-swapoff">
  <div class="rule-cmd"><span class="prog">swapoff</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Swap management blocked: agent has no authority to enable or disable swap. Changes affect virtual memory behavior system-wide and can trigger OOM kills if swap is removed under load. Ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-swapon">
  <div class="rule-cmd"><span class="prog">swapon</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Swap management blocked: agent has no authority to enable or disable swap. Changes affect virtual memory behavior system-wide and can trigger OOM kills if swap is removed under load. Ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-ufw">
  <div class="rule-cmd"><span class="prog">ufw</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Firewall modification blocked: agent has no authority to modify firewall rules. Misconfigured rules can lock the user out of the system. Ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-umount">
  <div class="rule-cmd"><span class="prog">umount</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Unmounting blocked: agent has no authority to unmount filesystems. Could disrupt running processes or system services depending on what's mounted. Ask the user to run umount themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-update-grub">
  <div class="rule-cmd"><span class="prog">update-grub</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Bootloader modification blocked: agent has no authority to modify the bootloader. A bad bootloader leaves the system unbootable. Ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-useradd">
  <div class="rule-cmd"><span class="prog">useradd</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">User management blocked: agent has no authority to create, delete, or modify user accounts. Account changes affect login and file ownership system-wide. Ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-userdel">
  <div class="rule-cmd"><span class="prog">userdel</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">User management blocked: agent has no authority to create, delete, or modify user accounts. Account changes affect login and file ownership system-wide. Ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-usermod">
  <div class="rule-cmd"><span class="prog">usermod</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">User management blocked: agent has no authority to create, delete, or modify user accounts. Account changes affect login and file ownership system-wide. Ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-vgremove">
  <div class="rule-cmd"><span class="prog">vgremove</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">LVM management blocked: agent has no authority to remove physical volumes, volume groups, or logical volumes. Removal is irreversible and can destroy mounted filesystems on top of the LVM stack. Ask the user to run this themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-wipe">
  <div class="rule-cmd"><span class="prog">wipe</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Secure wipe blocked: agent has no authority to wipe devices irreversibly. Ask the user to run wipe themselves.</div>
</div>
<div class="rule-row" data-decision="block" id="system-wipefs">
  <div class="rule-cmd"><span class="prog">wipefs</span></div>
  <div><span class="pill block"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>Block</span></div>
  <div class="rule-reason">Filesystem wipe blocked: agent has no authority to wipe filesystem signatures. The wrong target destroys the partition table. Ask the user to run wipefs themselves.</div>
</div>
</div>

<div class="rule-card">
  <header>
    <h2>Allowed · inspection</h2>
    <a href="https://github.com/camjac251/tool-gates/blob/main/rules/system.toml" class="src" target="_blank" rel="noopener">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
      rules/system.toml#allow
    </a>
    <span class="count">273 patterns</span>
  </header>

<div class="rule-row" data-decision="allow" id="system-age-version">
  <div class="rule-cmd"><span class="prog">age</span> <span class="flag">--version</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the age version string. Read-only; encrypts or decrypts nothing.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-alembic-history">
  <div class="rule-cmd"><span class="prog">alembic</span> history</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists the Alembic migration history. Read-only; runs no migrations.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-alembic-current">
  <div class="rule-cmd"><span class="prog">alembic</span> current</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows the current Alembic revision recorded in the database. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-alembic-heads">
  <div class="rule-cmd"><span class="prog">alembic</span> heads</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows the head revision(s) of the Alembic migration tree. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-alembic-branches">
  <div class="rule-cmd"><span class="prog">alembic</span> branches</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows branch points in the Alembic migration tree. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-alembic-show">
  <div class="rule-cmd"><span class="prog">alembic</span> show</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Displays details of a specific Alembic revision. Read-only; applies nothing.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-ansible-version">
  <div class="rule-cmd"><span class="prog">ansible</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the Ansible version and config paths. Read-only; runs no play.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-ansible-help">
  <div class="rule-cmd"><span class="prog">ansible</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints Ansible help text. Read-only; runs no play.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-ansible-list-hosts">
  <div class="rule-cmd"><span class="prog">ansible</span> --list-hosts</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists the hosts a playbook would target. Read-only; runs no task.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-ansible-list-tasks">
  <div class="rule-cmd"><span class="prog">ansible</span> --list-tasks</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists the tasks a playbook would run. Read-only; runs no task.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-ansible-syntax-check">
  <div class="rule-cmd"><span class="prog">ansible</span> --syntax-check</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Parses a playbook to check its syntax. Read-only; runs no task.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apk-info">
  <div class="rule-cmd"><span class="prog">apk</span> info</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints apk package details. Read-only; installs or removes nothing.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apk-list">
  <div class="rule-cmd"><span class="prog">apk</span> list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists packages known to apk. Read-only; installs or removes nothing.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apk-search">
  <div class="rule-cmd"><span class="prog">apk</span> search</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Searches apk for packages matching a term. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apk-dot">
  <div class="rule-cmd"><span class="prog">apk</span> dot</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Emits an apk package dependency graph in dot format. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apk-policy">
  <div class="rule-cmd"><span class="prog">apk</span> policy</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints apk install candidates and version priorities. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apk-stats">
  <div class="rule-cmd"><span class="prog">apk</span> stats</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints apk package cache statistics. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apk-audit">
  <div class="rule-cmd"><span class="prog">apk</span> audit</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports apk packages with known security advisories. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apk-version">
  <div class="rule-cmd"><span class="prog">apk</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the apk version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apk-v">
  <div class="rule-cmd"><span class="prog">apk</span> -V</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the apk version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apk-help">
  <div class="rule-cmd"><span class="prog">apk</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints apk help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apk-h">
  <div class="rule-cmd"><span class="prog">apk</span> -h</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints apk help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apt-list">
  <div class="rule-cmd"><span class="prog">apt</span> list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists packages known to apt. Read-only; installs or removes nothing.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apt-search">
  <div class="rule-cmd"><span class="prog">apt</span> search</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Searches apt for packages matching a term. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apt-show">
  <div class="rule-cmd"><span class="prog">apt</span> show</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints apt package details. Read-only; installs or removes nothing.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apt-showpkg">
  <div class="rule-cmd"><span class="prog">apt</span> showpkg</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints low-level apt package records. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apt-depends">
  <div class="rule-cmd"><span class="prog">apt</span> depends</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints an apt package's dependencies. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apt-rdepends">
  <div class="rule-cmd"><span class="prog">apt</span> rdepends</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints packages that depend on an apt package. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apt-policy">
  <div class="rule-cmd"><span class="prog">apt</span> policy</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints apt install candidates and version priorities. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apt-madison">
  <div class="rule-cmd"><span class="prog">apt</span> madison</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints available apt package versions and their sources. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apt-pkgnames">
  <div class="rule-cmd"><span class="prog">apt</span> pkgnames</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists apt package names matching a prefix. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apt-dotty">
  <div class="rule-cmd"><span class="prog">apt</span> dotty</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Emits an apt package dependency graph in dot format. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apt-xvcg">
  <div class="rule-cmd"><span class="prog">apt</span> xvcg</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Emits an apt package dependency graph in xvcg format. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apt-stats">
  <div class="rule-cmd"><span class="prog">apt</span> stats</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints apt package cache statistics. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apt-dump">
  <div class="rule-cmd"><span class="prog">apt</span> dump</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Dumps the full apt package cache. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apt-dumpavail">
  <div class="rule-cmd"><span class="prog">apt</span> dumpavail</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Dumps the apt available-packages list. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apt-showsrc">
  <div class="rule-cmd"><span class="prog">apt</span> showsrc</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints apt source-package records. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apt-changelog">
  <div class="rule-cmd"><span class="prog">apt</span> changelog</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints an apt package's changelog. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apt-version">
  <div class="rule-cmd"><span class="prog">apt</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the apt version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apt-v">
  <div class="rule-cmd"><span class="prog">apt</span> -v</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the apt version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apt-help">
  <div class="rule-cmd"><span class="prog">apt</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints apt help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apt-h">
  <div class="rule-cmd"><span class="prog">apt</span> -h</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints apt help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apt-cache">
  <div class="rule-cmd"><span class="prog">apt-cache</span> <span class="sub-note">(all subcommands)</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Queries the APT package cache (search, show, policy). Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apt-mark-showmanual">
  <div class="rule-cmd"><span class="prog">apt-mark</span> showmanual</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists packages apt has marked as manually installed. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apt-mark-showauto">
  <div class="rule-cmd"><span class="prog">apt-mark</span> showauto</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists packages apt has marked as automatically installed. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apt-mark-showhold">
  <div class="rule-cmd"><span class="prog">apt-mark</span> showhold</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists packages apt is holding at their current version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apt-mark-showinstall">
  <div class="rule-cmd"><span class="prog">apt-mark</span> showinstall</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists packages marked for installation. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apt-mark-showremove">
  <div class="rule-cmd"><span class="prog">apt-mark</span> showremove</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists packages marked for removal. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apt-mark-showpurge">
  <div class="rule-cmd"><span class="prog">apt-mark</span> showpurge</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists packages marked for purge. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-apt-mark-help">
  <div class="rule-cmd"><span class="prog">apt-mark</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints apt-mark help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-bazel-info">
  <div class="rule-cmd"><span class="prog">bazel</span> info</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints Bazel workspace and configuration info. Read-only; builds nothing.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-bazel-query">
  <div class="rule-cmd"><span class="prog">bazel</span> query</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Queries the Bazel target graph. Read-only; builds nothing.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-bazel-cquery">
  <div class="rule-cmd"><span class="prog">bazel</span> cquery</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Queries the Bazel configured-target graph. Read-only; builds nothing.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-bazel-aquery">
  <div class="rule-cmd"><span class="prog">bazel</span> aquery</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Queries the Bazel action graph. Read-only; builds nothing.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-bazel-build">
  <div class="rule-cmd"><span class="prog">bazel</span> build</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Builds the requested Bazel targets. Produces build outputs; runs no target.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-bazel-test">
  <div class="rule-cmd"><span class="prog">bazel</span> test</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Builds and runs the requested Bazel test targets.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-bazel-coverage">
  <div class="rule-cmd"><span class="prog">bazel</span> coverage</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Builds and runs Bazel test targets while collecting coverage data.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-bazel-version">
  <div class="rule-cmd"><span class="prog">bazel</span> version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the Bazel version. Read-only; builds nothing.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-bazel-help">
  <div class="rule-cmd"><span class="prog">bazel</span> help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints Bazel help text. Read-only; builds nothing.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-brew-list">
  <div class="rule-cmd"><span class="prog">brew</span> list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists packages known to Homebrew. Read-only; installs or removes nothing.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-brew-ls">
  <div class="rule-cmd"><span class="prog">brew</span> ls</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists packages or repositories known to Homebrew. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-brew-search">
  <div class="rule-cmd"><span class="prog">brew</span> search</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Searches Homebrew for packages matching a term. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-brew-info">
  <div class="rule-cmd"><span class="prog">brew</span> info</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints Homebrew package details. Read-only; installs or removes nothing.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-brew-home">
  <div class="rule-cmd"><span class="prog">brew</span> home</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Opens or prints a Homebrew package's homepage URL. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-brew-homepage">
  <div class="rule-cmd"><span class="prog">brew</span> homepage</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Opens or prints a Homebrew package's homepage URL. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-brew-deps">
  <div class="rule-cmd"><span class="prog">brew</span> deps</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists a Homebrew package's dependencies. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-brew-uses">
  <div class="rule-cmd"><span class="prog">brew</span> uses</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists Homebrew packages that depend on a given formula. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-brew-leaves">
  <div class="rule-cmd"><span class="prog">brew</span> leaves</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists Homebrew packages installed on their own, not as dependencies. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-brew-outdated">
  <div class="rule-cmd"><span class="prog">brew</span> outdated</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists installed Homebrew packages with newer versions available. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-brew-config">
  <div class="rule-cmd"><span class="prog">brew</span> config</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the Homebrew configuration. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-brew-doctor">
  <div class="rule-cmd"><span class="prog">brew</span> doctor</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs Homebrew self-diagnostic checks and reports issues. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-brew-commands">
  <div class="rule-cmd"><span class="prog">brew</span> commands</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists available Homebrew commands. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-brew-desc">
  <div class="rule-cmd"><span class="prog">brew</span> desc</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints a Homebrew package description. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-brew-version">
  <div class="rule-cmd"><span class="prog">brew</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the Homebrew version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-brew-v">
  <div class="rule-cmd"><span class="prog">brew</span> -v</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the Homebrew version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-brew-help">
  <div class="rule-cmd"><span class="prog">brew</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints Homebrew help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-brew-h">
  <div class="rule-cmd"><span class="prog">brew</span> -h</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints Homebrew help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-brew-cat">
  <div class="rule-cmd"><span class="prog">brew</span> cat</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the source of a Homebrew package definition. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-brew-formula">
  <div class="rule-cmd"><span class="prog">brew</span> formula</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints Homebrew formula information. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-brew-cask">
  <div class="rule-cmd"><span class="prog">brew</span> cask</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints Homebrew cask information. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-cmake-version">
  <div class="rule-cmd"><span class="prog">cmake</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the CMake version. Read-only; configures or builds nothing.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-cmake-help">
  <div class="rule-cmd"><span class="prog">cmake</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints CMake help text. Read-only; configures or builds nothing.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-crontab-l">
  <div class="rule-cmd"><span class="prog">crontab</span> <span class="flag">-l</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists the current user's scheduled cron jobs. Read-only; does not change the crontab.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-dnf-list">
  <div class="rule-cmd"><span class="prog">dnf</span> list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists packages known to dnf. Read-only; installs or removes nothing.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-dnf-info">
  <div class="rule-cmd"><span class="prog">dnf</span> info</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints dnf package details. Read-only; installs or removes nothing.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-dnf-search">
  <div class="rule-cmd"><span class="prog">dnf</span> search</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Searches dnf for packages matching a term. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-dnf-provides">
  <div class="rule-cmd"><span class="prog">dnf</span> provides</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports which dnf package provides a given capability or file. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-dnf-whatprovides">
  <div class="rule-cmd"><span class="prog">dnf</span> whatprovides</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports which dnf package provides a given capability or file. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-dnf-repolist">
  <div class="rule-cmd"><span class="prog">dnf</span> repolist</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists configured dnf repositories. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-dnf-repoinfo">
  <div class="rule-cmd"><span class="prog">dnf</span> repoinfo</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints details of configured dnf repositories. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-dnf-repoquery">
  <div class="rule-cmd"><span class="prog">dnf</span> repoquery</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Queries dnf repository metadata for packages. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-dnf-deplist">
  <div class="rule-cmd"><span class="prog">dnf</span> deplist</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints a dnf package's dependency list. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-dnf-check">
  <div class="rule-cmd"><span class="prog">dnf</span> check</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Checks the dnf package database for problems. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-dnf-check-update">
  <div class="rule-cmd"><span class="prog">dnf</span> check-update</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Checks for available dnf package updates without installing them. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-dnf-history">
  <div class="rule-cmd"><span class="prog">dnf</span> history</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the dnf transaction history. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-dnf-alias">
  <div class="rule-cmd"><span class="prog">dnf</span> alias</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists or prints configured dnf command aliases. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-dnf-version">
  <div class="rule-cmd"><span class="prog">dnf</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the dnf version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-dnf-v">
  <div class="rule-cmd"><span class="prog">dnf</span> -v</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the dnf version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-dnf-help">
  <div class="rule-cmd"><span class="prog">dnf</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints dnf help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-dnf-h">
  <div class="rule-cmd"><span class="prog">dnf</span> -h</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints dnf help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-dpkg-l-list-l-listfiles-s-search-s-status-p-print-avail">
  <div class="rule-cmd"><span class="prog">dpkg</span> <span class="flag">-l</span> <span class="flag">--list</span> <span class="flag">-L</span> <span class="flag">--listfiles</span> <span class="flag">-S</span> <span class="flag">--search</span> <span class="flag">-s</span> <span class="flag">--status</span> <span class="flag">-p</span> <span class="flag">--print-avail</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Queries the dpkg database (list, list files, search, status, or print package info). Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-dpkg-get-selections-print-architecture-print-foreign-architectures">
  <div class="rule-cmd"><span class="prog">dpkg</span> <span class="flag">--get-selections</span> <span class="flag">--print-architecture</span> <span class="flag">--print-foreign-architectures</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints dpkg selections or the configured architectures. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-dpkg-audit-c-yet-to-unpack-compare-versions-verify-v">
  <div class="rule-cmd"><span class="prog">dpkg</span> <span class="flag">--audit</span> <span class="flag">-C</span> <span class="flag">--yet-to-unpack</span> <span class="flag">--compare-versions</span> <span class="flag">--verify</span> <span class="flag">-V</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Audits or verifies dpkg package state, or compares versions. Read-only; changes no package.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-dpkg-version-help">
  <div class="rule-cmd"><span class="prog">dpkg</span> <span class="flag">--version</span> <span class="flag">--help</span> <span class="flag">-?</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the dpkg version or help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-flatpak-list">
  <div class="rule-cmd"><span class="prog">flatpak</span> list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists installed Flatpak applications and runtimes. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-flatpak-info">
  <div class="rule-cmd"><span class="prog">flatpak</span> info</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints details of an installed Flatpak application. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-flatpak-search">
  <div class="rule-cmd"><span class="prog">flatpak</span> search</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Searches configured Flatpak remotes for applications. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-flatpak-remote-ls">
  <div class="rule-cmd"><span class="prog">flatpak</span> remote-ls</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists applications available from a Flatpak remote. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-flatpak-remotes">
  <div class="rule-cmd"><span class="prog">flatpak</span> remotes</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists configured Flatpak remotes. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-flatpak-history">
  <div class="rule-cmd"><span class="prog">flatpak</span> history</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the Flatpak installation history. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-flatpak-version">
  <div class="rule-cmd"><span class="prog">flatpak</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the Flatpak version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-flatpak-help">
  <div class="rule-cmd"><span class="prog">flatpak</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints Flatpak help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-gpg-list-keys-k-list-secret-keys-k">
  <div class="rule-cmd"><span class="prog">gpg</span> <span class="flag">--list-keys</span> <span class="flag">-k</span> <span class="flag">--list-secret-keys</span> <span class="flag">-K</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists keys in the local GPG keyring. Read-only; the keyring is not modified.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-gpg-fingerprint">
  <div class="rule-cmd"><span class="prog">gpg</span> <span class="flag">--fingerprint</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints key fingerprints from the local GPG keyring. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-gpg-verify">
  <div class="rule-cmd"><span class="prog">gpg</span> <span class="flag">--verify</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Verifies a GPG signature against a message. Read-only; imports nothing.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-gpg-list-packets">
  <div class="rule-cmd"><span class="prog">gpg</span> <span class="flag">--list-packets</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Dumps the low-level packet structure of GPG input. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-gpg-version">
  <div class="rule-cmd"><span class="prog">gpg</span> <span class="flag">--version</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the GPG version and supported algorithms. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-gpg-help-h">
  <div class="rule-cmd"><span class="prog">gpg</span> <span class="flag">--help</span> <span class="flag">-h</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints GPG help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-gradle-tasks">
  <div class="rule-cmd"><span class="prog">gradle</span> tasks</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists the available Gradle tasks for the project. Read-only; runs no task.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-gradle-help">
  <div class="rule-cmd"><span class="prog">gradle</span> help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints Gradle help for the project or a task. Read-only; runs no task.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-gradle-dependencies">
  <div class="rule-cmd"><span class="prog">gradle</span> dependencies</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the project's resolved Gradle dependency tree. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-gradle-properties">
  <div class="rule-cmd"><span class="prog">gradle</span> properties</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the project's Gradle properties. Read-only; changes nothing.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-gradle-build">
  <div class="rule-cmd"><span class="prog">gradle</span> build</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the Gradle <code>build</code> task. Compiles, tests, and assembles project outputs.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-gradle-test">
  <div class="rule-cmd"><span class="prog">gradle</span> test</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the Gradle <code>test</code> task. Executes the project's test suite.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-gradle-check">
  <div class="rule-cmd"><span class="prog">gradle</span> check</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the Gradle <code>check</code> task. Runs verification tasks such as tests and linters.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-gradle-clean">
  <div class="rule-cmd"><span class="prog">gradle</span> clean</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the Gradle <code>clean</code> task. Deletes the project's build directory.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-hyperfine-version">
  <div class="rule-cmd"><span class="prog">hyperfine</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the hyperfine version. Read-only; runs no benchmark.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-hyperfine-help">
  <div class="rule-cmd"><span class="prog">hyperfine</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints hyperfine help text. Read-only; runs no benchmark.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-just-list">
  <div class="rule-cmd"><span class="prog">just</span> --list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists the recipes defined in the <code>justfile</code>. Read-only; runs no recipe.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-just-summary">
  <div class="rule-cmd"><span class="prog">just</span> --summary</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints a one-line summary of <code>justfile</code> recipe names. Read-only; runs no recipe.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-just-dump">
  <div class="rule-cmd"><span class="prog">just</span> --dump</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Dumps the parsed <code>justfile</code> back out. Read-only; runs no recipe.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-just-evaluate">
  <div class="rule-cmd"><span class="prog">just</span> --evaluate</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Evaluates and prints <code>justfile</code> variables. Read-only; runs no recipe.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-kill-0">
  <div class="rule-cmd"><span class="prog">kill</span> <span class="flag">-0</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Checks whether a PID exists without sending a signal. Read-only probe; the process is not affected.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-make-test">
  <div class="rule-cmd"><span class="prog">make</span> test</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the project's <code>test</code> make target. Conventionally runs the test suite.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-make-tests">
  <div class="rule-cmd"><span class="prog">make</span> tests</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the project's <code>tests</code> make target. Conventionally runs the test suite.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-make-check">
  <div class="rule-cmd"><span class="prog">make</span> check</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the project's <code>check</code> make target. Conventionally runs tests or lint checks.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-make-lint">
  <div class="rule-cmd"><span class="prog">make</span> lint</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the project's <code>lint</code> make target. Conventionally runs linters over the source.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-make-build">
  <div class="rule-cmd"><span class="prog">make</span> build</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the project's <code>build</code> make target. Compiles or assembles build outputs.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-make-all">
  <div class="rule-cmd"><span class="prog">make</span> all</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the project's default <code>all</code> make target. Builds the standard set of outputs.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-make-clean">
  <div class="rule-cmd"><span class="prog">make</span> clean</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the project's <code>clean</code> make target. Removes build artifacts in the working tree.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-make-format">
  <div class="rule-cmd"><span class="prog">make</span> format</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the project's <code>format</code> make target. Reformats source files in place.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-make-fmt">
  <div class="rule-cmd"><span class="prog">make</span> fmt</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the project's <code>fmt</code> make target. Reformats source files in place.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-make-typecheck">
  <div class="rule-cmd"><span class="prog">make</span> typecheck</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the project's <code>typecheck</code> make target. Conventionally runs a static type checker.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-make-dev">
  <div class="rule-cmd"><span class="prog">make</span> dev</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the project's <code>dev</code> make target. Conventionally starts a local development task.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-make-run">
  <div class="rule-cmd"><span class="prog">make</span> run</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the project's <code>run</code> make target. Executes the project's configured run command.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-make-help">
  <div class="rule-cmd"><span class="prog">make</span> help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the project's <code>help</code> make target. Conventionally prints available targets.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-meson-introspect">
  <div class="rule-cmd"><span class="prog">meson</span> introspect</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints build-system metadata for a Meson project. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-meson-configure">
  <div class="rule-cmd"><span class="prog">meson</span> configure</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows or changes Meson build options. Without options, reports the current configuration.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-meson-version">
  <div class="rule-cmd"><span class="prog">meson</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the Meson version. Read-only; configures or builds nothing.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-meson-help">
  <div class="rule-cmd"><span class="prog">meson</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints Meson help text. Read-only; configures or builds nothing.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-mount-version-help-h-v">
  <div class="rule-cmd"><span class="prog">mount</span> <span class="flag">--version</span> <span class="flag">--help</span> <span class="flag">-h</span> <span class="flag">-V</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the mount version or help text. Read-only; takes no action on filesystems.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-mvn-help">
  <div class="rule-cmd"><span class="prog">mvn</span> help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the Maven help plugin. Read-only; prints plugin or goal information.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-mvn-validate">
  <div class="rule-cmd"><span class="prog">mvn</span> validate</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the Maven <code>validate</code> phase. Checks the project is correct; produces no artifacts.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-mvn-compile">
  <div class="rule-cmd"><span class="prog">mvn</span> compile</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the Maven <code>compile</code> phase. Compiles the project's main sources.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-mvn-test">
  <div class="rule-cmd"><span class="prog">mvn</span> test</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the Maven <code>test</code> phase. Compiles and executes the project's unit tests.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-mvn-package">
  <div class="rule-cmd"><span class="prog">mvn</span> package</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the Maven <code>package</code> phase. Builds the project artifact into <code>target/</code>.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-mvn-verify">
  <div class="rule-cmd"><span class="prog">mvn</span> verify</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the Maven <code>verify</code> phase. Runs integration tests and verification checks.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-mvn-clean">
  <div class="rule-cmd"><span class="prog">mvn</span> clean</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs the Maven <code>clean</code> phase. Deletes the <code>target/</code> build directory.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-mvn-dependency-tree">
  <div class="rule-cmd"><span class="prog">mvn</span> dependency:tree</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the project's resolved Maven dependency tree. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-mvn-dependency-analyze">
  <div class="rule-cmd"><span class="prog">mvn</span> dependency:analyze</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Analyzes declared vs used Maven dependencies and reports findings. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-ninja-t">
  <div class="rule-cmd"><span class="prog">ninja</span> -t</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs a Ninja subtool (<code>-t query</code>, <code>-t graph</code>, etc.). Inspection only; does not build targets.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-nix-search">
  <div class="rule-cmd"><span class="prog">nix</span> search</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Searches Nixpkgs (or a flake) for packages. Read-only; builds nothing.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-nix-show">
  <div class="rule-cmd"><span class="prog">nix</span> show</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows package or flake-output metadata. Read-only; builds nothing.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-nix-eval">
  <div class="rule-cmd"><span class="prog">nix</span> eval</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Evaluates a Nix expression and prints the result. Read-only; builds nothing.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-nix-repl">
  <div class="rule-cmd"><span class="prog">nix</span> repl</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Opens a read-only Nix evaluation REPL. Builds nothing.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-nix-flake">
  <div class="rule-cmd"><span class="prog">nix</span> flake</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Inspects a Nix flake (<code>show</code>, <code>metadata</code>, etc.). Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-nix-path-info">
  <div class="rule-cmd"><span class="prog">nix</span> path-info</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints metadata about Nix store paths. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-nix-derivation">
  <div class="rule-cmd"><span class="prog">nix</span> derivation</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows or manipulates a Nix derivation in read contexts. Inspection only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-nix-store">
  <div class="rule-cmd"><span class="prog">nix</span> store</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Runs a read-oriented Nix store query subcommand. Inspection only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-nix-log">
  <div class="rule-cmd"><span class="prog">nix</span> log</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the build log for a Nix store path. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-nix-why-depends">
  <div class="rule-cmd"><span class="prog">nix</span> why-depends</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Explains why one Nix path depends on another. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-nix-version">
  <div class="rule-cmd"><span class="prog">nix</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the Nix version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-nix-help">
  <div class="rule-cmd"><span class="prog">nix</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints Nix help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-nix-env-q">
  <div class="rule-cmd"><span class="prog">nix-env</span> -q</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Queries installed or available Nix packages. Read-only; the profile is not modified.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-nix-env-query">
  <div class="rule-cmd"><span class="prog">nix-env</span> --query</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Queries installed or available Nix packages. Read-only; the profile is not modified.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-openssl-version">
  <div class="rule-cmd"><span class="prog">openssl</span> version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the OpenSSL version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-openssl-x509">
  <div class="rule-cmd"><span class="prog">openssl</span> x509</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Inspects an X.509 certificate (without <code>-req</code>). Read-only; prints fields, signs nothing.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-openssl-s-client">
  <div class="rule-cmd"><span class="prog">openssl</span> s_client</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Opens a debug TLS client connection to inspect a server's certificate and handshake. Read-only locally.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-openssl-dgst">
  <div class="rule-cmd"><span class="prog">openssl</span> dgst</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Computes a message digest of the input. Read-only; writes no key material.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-openssl-md5">
  <div class="rule-cmd"><span class="prog">openssl</span> md5</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Computes an MD5 digest of the input. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-openssl-sha1">
  <div class="rule-cmd"><span class="prog">openssl</span> sha1</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Computes a SHA-1 digest of the input. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-openssl-sha256">
  <div class="rule-cmd"><span class="prog">openssl</span> sha256</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Computes a SHA-256 digest of the input. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-openssl-sha512">
  <div class="rule-cmd"><span class="prog">openssl</span> sha512</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Computes a SHA-512 digest of the input. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-openssl-verify">
  <div class="rule-cmd"><span class="prog">openssl</span> verify</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Verifies a certificate chain against trusted roots. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-openssl-ciphers">
  <div class="rule-cmd"><span class="prog">openssl</span> ciphers</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists the cipher suites matching a selection string. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-openssl-list">
  <div class="rule-cmd"><span class="prog">openssl</span> list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists OpenSSL algorithms, digests, or other capabilities. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-openssl-asn1parse">
  <div class="rule-cmd"><span class="prog">openssl</span> asn1parse</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Parses and prints the ASN.1 structure of the input. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-openssl-speed">
  <div class="rule-cmd"><span class="prog">openssl</span> speed</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Benchmarks OpenSSL algorithm throughput. Read-only; writes no key material.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-openssl-prime">
  <div class="rule-cmd"><span class="prog">openssl</span> prime</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Tests whether a number is prime or generates one to stdout. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-openssl-rand">
  <div class="rule-cmd"><span class="prog">openssl</span> rand</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Generates random bytes to stdout (without <code>-out</code>). Writes no file.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-pacman-q">
  <div class="rule-cmd"><span class="prog">pacman</span> -Q</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Queries installed pacman packages. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-pacman-query">
  <div class="rule-cmd"><span class="prog">pacman</span> --query</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Queries installed pacman packages. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-pacman-qs">
  <div class="rule-cmd"><span class="prog">pacman</span> -Qs</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Searches installed pacman packages by pattern. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-pacman-qi">
  <div class="rule-cmd"><span class="prog">pacman</span> -Qi</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints details of an installed pacman package. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-pacman-ql">
  <div class="rule-cmd"><span class="prog">pacman</span> -Ql</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists the files owned by an installed pacman package. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-pacman-qo">
  <div class="rule-cmd"><span class="prog">pacman</span> -Qo</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports which pacman package owns a given file. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-pacman-ss">
  <div class="rule-cmd"><span class="prog">pacman</span> -Ss</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Searches sync repositories for pacman packages. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-pacman-si">
  <div class="rule-cmd"><span class="prog">pacman</span> -Si</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints details of a pacman package in the sync repos. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-pacman-sl">
  <div class="rule-cmd"><span class="prog">pacman</span> -Sl</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists packages available in a sync repository. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-pacman-sg">
  <div class="rule-cmd"><span class="prog">pacman</span> -Sg</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists the members of a pacman package group. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-pacman-f">
  <div class="rule-cmd"><span class="prog">pacman</span> -F</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Searches the pacman files database for a file. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-pacman-files">
  <div class="rule-cmd"><span class="prog">pacman</span> --files</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Searches the pacman files database for a file. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-pacman-v">
  <div class="rule-cmd"><span class="prog">pacman</span> -V</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the pacman version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-pacman-version">
  <div class="rule-cmd"><span class="prog">pacman</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the pacman version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-pacman-h">
  <div class="rule-cmd"><span class="prog">pacman</span> -h</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints pacman help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-pacman-help">
  <div class="rule-cmd"><span class="prog">pacman</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints pacman help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-pactl-list">
  <div class="rule-cmd"><span class="prog">pactl</span> list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists PulseAudio objects (sinks, sources, modules, etc.). Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-pactl-info">
  <div class="rule-cmd"><span class="prog">pactl</span> info</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints PulseAudio server information. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-pactl-stat">
  <div class="rule-cmd"><span class="prog">pactl</span> stat</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints PulseAudio memory-block statistics. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-pactl-get-default-sink">
  <div class="rule-cmd"><span class="prog">pactl</span> get-default-sink</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the default PulseAudio output sink. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-pactl-get-default-source">
  <div class="rule-cmd"><span class="prog">pactl</span> get-default-source</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the default PulseAudio input source. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-pactl-get-sink-volume">
  <div class="rule-cmd"><span class="prog">pactl</span> get-sink-volume</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the volume of a PulseAudio sink. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-pactl-get-source-volume">
  <div class="rule-cmd"><span class="prog">pactl</span> get-source-volume</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the volume of a PulseAudio source. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-pactl-get-sink-mute">
  <div class="rule-cmd"><span class="prog">pactl</span> get-sink-mute</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the mute state of a PulseAudio sink. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-pactl-get-source-mute">
  <div class="rule-cmd"><span class="prog">pactl</span> get-source-mute</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the mute state of a PulseAudio source. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-pactl-subscribe">
  <div class="rule-cmd"><span class="prog">pactl</span> subscribe</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Streams PulseAudio server events as they occur. Read-only; changes nothing.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-pactl-version">
  <div class="rule-cmd"><span class="prog">pactl</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the pactl version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-pactl-help">
  <div class="rule-cmd"><span class="prog">pactl</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints pactl help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-pg-dump">
  <div class="rule-cmd"><span class="prog">pg_dump</span> <span class="sub-note">(all subcommands)</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Exports a PostgreSQL database to a SQL or archive dump. Read-only on the database; writes the dump to stdout or a file.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-psql-l-list">
  <div class="rule-cmd"><span class="prog">psql</span> <span class="flag">-l</span> <span class="flag">--list</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists the databases on the PostgreSQL server. Read-only; runs no queries against the data.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-service-status-all">
  <div class="rule-cmd"><span class="prog">service</span> <span class="flag">--status-all</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports the status of all init services. Read-only; starts or stops nothing.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-sqlite3-readonly">
  <div class="rule-cmd"><span class="prog">sqlite3</span> <span class="flag">-readonly</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Opens a SQLite database in read-only mode. Writes are rejected; queries only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-ssh-keygen-l-lf-lv">
  <div class="rule-cmd"><span class="prog">ssh-keygen</span> <span class="flag">-l</span> <span class="flag">-lf</span> <span class="flag">-lv</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the fingerprint of a key file. Read-only; generates no key.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-ssh-keygen-f">
  <div class="rule-cmd"><span class="prog">ssh-keygen</span> <span class="flag">-F</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Searches <code>known_hosts</code> for a host. Read-only; removes nothing.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-ssh-keygen-b">
  <div class="rule-cmd"><span class="prog">ssh-keygen</span> <span class="flag">-B</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the bubblebabble digest of a key file. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-sudo-l-list">
  <div class="rule-cmd"><span class="prog">sudo</span> <span class="flag">-l</span> <span class="flag">--list</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists the commands the current user may run via sudo. Read-only; executes nothing.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-sudo-v-validate">
  <div class="rule-cmd"><span class="prog">sudo</span> <span class="flag">-v</span> <span class="flag">--validate</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Refreshes the sudo timestamp without running a command. Executes nothing.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-sudo-k-reset-timestamp">
  <div class="rule-cmd"><span class="prog">sudo</span> <span class="flag">-k</span> <span class="flag">--reset-timestamp</span></div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Invalidates the cached sudo timestamp. Executes no command.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-systemctl-status">
  <div class="rule-cmd"><span class="prog">systemctl</span> status</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows the runtime status and recent logs of a systemd unit. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-systemctl-show">
  <div class="rule-cmd"><span class="prog">systemctl</span> show</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints a systemd unit's properties as key=value pairs. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-systemctl-list-units">
  <div class="rule-cmd"><span class="prog">systemctl</span> list-units</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists systemd units currently loaded in memory. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-systemctl-list-unit-files">
  <div class="rule-cmd"><span class="prog">systemctl</span> list-unit-files</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists installed systemd unit files and their enablement state. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-systemctl-list-sockets">
  <div class="rule-cmd"><span class="prog">systemctl</span> list-sockets</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists systemd socket units and what they activate. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-systemctl-list-timers">
  <div class="rule-cmd"><span class="prog">systemctl</span> list-timers</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists systemd timer units and their next elapse. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-systemctl-list-jobs">
  <div class="rule-cmd"><span class="prog">systemctl</span> list-jobs</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists systemd jobs currently in progress. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-systemctl-list-dependencies">
  <div class="rule-cmd"><span class="prog">systemctl</span> list-dependencies</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Shows the dependency tree of a systemd unit. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-systemctl-is-active">
  <div class="rule-cmd"><span class="prog">systemctl</span> is-active</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports whether a systemd unit is active. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-systemctl-is-enabled">
  <div class="rule-cmd"><span class="prog">systemctl</span> is-enabled</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports whether a systemd unit is enabled at boot. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-systemctl-is-failed">
  <div class="rule-cmd"><span class="prog">systemctl</span> is-failed</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports whether a systemd unit is in the failed state. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-systemctl-is-system-running">
  <div class="rule-cmd"><span class="prog">systemctl</span> is-system-running</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports the overall systemd system state. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-systemctl-cat">
  <div class="rule-cmd"><span class="prog">systemctl</span> cat</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the on-disk contents of a systemd unit file. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-systemctl-help">
  <div class="rule-cmd"><span class="prog">systemctl</span> help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Opens help for a systemd unit. Read-only; changes no unit.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-systemctl-version">
  <div class="rule-cmd"><span class="prog">systemctl</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the systemd version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-systemctl-h">
  <div class="rule-cmd"><span class="prog">systemctl</span> -h</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints systemctl help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-systemctl-help-2">
  <div class="rule-cmd"><span class="prog">systemctl</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints systemctl help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-task-list">
  <div class="rule-cmd"><span class="prog">task</span> --list</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists the Taskfile tasks that have a description. Read-only; runs no task.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-task-list-all">
  <div class="rule-cmd"><span class="prog">task</span> --list-all</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists all Taskfile tasks, including undocumented ones. Read-only; runs no task.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-vagrant-status">
  <div class="rule-cmd"><span class="prog">vagrant</span> status</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports the state of the Vagrant machines for this project. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-vagrant-global-status">
  <div class="rule-cmd"><span class="prog">vagrant</span> global-status</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Reports the state of all known Vagrant machines on the host. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-vagrant-ssh-config">
  <div class="rule-cmd"><span class="prog">vagrant</span> ssh-config</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the SSH config for connecting to the Vagrant VM. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-vagrant-port">
  <div class="rule-cmd"><span class="prog">vagrant</span> port</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists the forwarded ports for the Vagrant VM. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-vagrant-version">
  <div class="rule-cmd"><span class="prog">vagrant</span> version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the installed and latest Vagrant version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-vagrant-help">
  <div class="rule-cmd"><span class="prog">vagrant</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints Vagrant help text. Read-only; changes no VM.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-zypper-search">
  <div class="rule-cmd"><span class="prog">zypper</span> search</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Searches zypper for packages matching a term. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-zypper-se">
  <div class="rule-cmd"><span class="prog">zypper</span> se</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Searches zypper for packages matching a term. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-zypper-info">
  <div class="rule-cmd"><span class="prog">zypper</span> info</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints zypper package details. Read-only; installs or removes nothing.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-zypper-if">
  <div class="rule-cmd"><span class="prog">zypper</span> if</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints zypper package details. Read-only; installs or removes nothing.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-zypper-list-updates">
  <div class="rule-cmd"><span class="prog">zypper</span> list-updates</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists available zypper package updates without installing them. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-zypper-lu">
  <div class="rule-cmd"><span class="prog">zypper</span> lu</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists available zypper package updates without installing them. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-zypper-packages">
  <div class="rule-cmd"><span class="prog">zypper</span> packages</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists packages known to zypper. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-zypper-pa">
  <div class="rule-cmd"><span class="prog">zypper</span> pa</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists packages known to zypper. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-zypper-patterns">
  <div class="rule-cmd"><span class="prog">zypper</span> patterns</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists zypper installation patterns. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-zypper-pt">
  <div class="rule-cmd"><span class="prog">zypper</span> pt</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists zypper installation patterns. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-zypper-products">
  <div class="rule-cmd"><span class="prog">zypper</span> products</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists zypper products. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-zypper-pd">
  <div class="rule-cmd"><span class="prog">zypper</span> pd</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists zypper products. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-zypper-repos">
  <div class="rule-cmd"><span class="prog">zypper</span> repos</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists configured zypper repositories. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-zypper-lr">
  <div class="rule-cmd"><span class="prog">zypper</span> lr</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists configured zypper repositories. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-zypper-services">
  <div class="rule-cmd"><span class="prog">zypper</span> services</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists configured zypper services. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-zypper-ls">
  <div class="rule-cmd"><span class="prog">zypper</span> ls</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Lists packages or repositories known to zypper. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-zypper-version">
  <div class="rule-cmd"><span class="prog">zypper</span> --version</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the zypper version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-zypper-v">
  <div class="rule-cmd"><span class="prog">zypper</span> -V</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints the zypper version. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-zypper-help">
  <div class="rule-cmd"><span class="prog">zypper</span> --help</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints zypper help text. Read-only.</div>
</div>
<div class="rule-row" data-decision="allow" id="system-zypper-h">
  <div class="rule-cmd"><span class="prog">zypper</span> -h</div>
  <div><span class="pill allow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Allow</span></div>
  <div class="rule-reason">Prints zypper help text. Read-only.</div>
</div>
</div>

<div class="rule-card">
  <header>
    <h2>Asks first · mutations</h2>
    <a href="https://github.com/camjac251/tool-gates/blob/main/rules/system.toml" class="src" target="_blank" rel="noopener">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
      rules/system.toml#ask
    </a>
    <span class="count">188 patterns</span>
  </header>

<div class="rule-row" data-decision="ask" id="system-age">
  <div class="rule-cmd"><span class="prog">age</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Encrypts or decrypts a file with age. Use <code>-i &lt;key&gt;</code> for identity files; output replaces or writes alongside the input.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-alembic-upgrade">
  <div class="rule-cmd"><span class="prog">alembic</span> upgrade</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Applies pending Alembic migrations to the database. Schema/data changes are not auto-reversible.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-alembic-downgrade">
  <div class="rule-cmd"><span class="prog">alembic</span> downgrade</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Reverts Alembic migrations. Can drop columns/tables; review the down() body before approving.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-alembic-revision">
  <div class="rule-cmd"><span class="prog">alembic</span> revision</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Generates a new Alembic migration file in the <code>versions/</code> directory.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-alembic-stamp">
  <div class="rule-cmd"><span class="prog">alembic</span> stamp</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Sets the recorded Alembic version without running migrations. Mismatches with actual schema state can corrupt later migrations.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-ansible">
  <div class="rule-cmd"><span class="prog">ansible</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Runs an Ansible playbook against the inventory. Applies configuration changes to target hosts.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-apk-add">
  <div class="rule-cmd"><span class="prog">apk</span> add</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installs apk packages.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-apk-del">
  <div class="rule-cmd"><span class="prog">apk</span> del</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes installed apk packages.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-apk-update">
  <div class="rule-cmd"><span class="prog">apk</span> update</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Refreshes the apk package index from configured repositories.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-apk-upgrade">
  <div class="rule-cmd"><span class="prog">apk</span> upgrade</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Upgrades installed apk packages to newer versions.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-apk-fix">
  <div class="rule-cmd"><span class="prog">apk</span> fix</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Repairs an installed apk package whose files have been altered or removed.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-apk-cache">
  <div class="rule-cmd"><span class="prog">apk</span> cache</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Manages the apk package cache (clean, sync, download).</div>
</div>
<div class="rule-row" data-decision="ask" id="system-apk-fetch">
  <div class="rule-cmd"><span class="prog">apk</span> fetch</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Downloads apk packages to the current directory without installing.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-apt-download">
  <div class="rule-cmd"><span class="prog">apt</span> download</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Downloads <code>.deb</code> package files to the current directory without installing.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-apt-install">
  <div class="rule-cmd"><span class="prog">apt</span> install</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installs packages and their dependencies system-wide. Network operation; pulls from the configured apt repositories.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-apt-remove">
  <div class="rule-cmd"><span class="prog">apt</span> remove</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes packages but keeps their config files. Use <code>purge</code> to also remove configs.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-apt-purge">
  <div class="rule-cmd"><span class="prog">apt</span> purge</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes packages and their config files. Stronger than <code>remove</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-apt-update">
  <div class="rule-cmd"><span class="prog">apt</span> update</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Refreshes the apt package index from the configured repositories. Does not upgrade installed packages.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-apt-upgrade">
  <div class="rule-cmd"><span class="prog">apt</span> upgrade</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Upgrades installed packages to newer versions from the configured sources.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-apt-full-upgrade">
  <div class="rule-cmd"><span class="prog">apt</span> full-upgrade</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Upgrades packages and can remove others to resolve dependencies. Heavier than plain <code>upgrade</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-apt-dist-upgrade">
  <div class="rule-cmd"><span class="prog">apt</span> dist-upgrade</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Distribution upgrade can install/remove many packages, including kernel and base packages. Review proposed changes before approving.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-apt-autoremove">
  <div class="rule-cmd"><span class="prog">apt</span> autoremove</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes packages installed as dependencies that are no longer needed.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-apt-autoclean">
  <div class="rule-cmd"><span class="prog">apt</span> autoclean</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes obsolete <code>.deb</code> files from the apt download cache.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-apt-clean">
  <div class="rule-cmd"><span class="prog">apt</span> clean</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes all cached <code>.deb</code> files from the apt download cache.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-apt-build-dep">
  <div class="rule-cmd"><span class="prog">apt</span> build-dep</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installs the build dependencies of the named source package.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-apt-source">
  <div class="rule-cmd"><span class="prog">apt</span> source</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Downloads the source <code>.tar.*</code> and <code>.dsc</code> for a package into the current directory.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-apt-edit-sources">
  <div class="rule-cmd"><span class="prog">apt</span> edit-sources</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Opens <code>/etc/apt/sources.list</code> in <code>$EDITOR</code>. Interactive; affects which repositories apt trusts.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-apt-satisfy">
  <div class="rule-cmd"><span class="prog">apt</span> satisfy</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installs/removes packages as needed to satisfy a given dependency expression.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-apt-mark-manual">
  <div class="rule-cmd"><span class="prog">apt-mark</span> manual</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Marks packages as manually installed so apt's autoremove will not remove them.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-apt-mark-auto">
  <div class="rule-cmd"><span class="prog">apt-mark</span> auto</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Marks packages as automatically installed so apt's autoremove can remove them when unused.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-apt-mark-hold">
  <div class="rule-cmd"><span class="prog">apt-mark</span> hold</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Pins a package at its current version. apt upgrade/install will refuse to change it.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-apt-mark-unhold">
  <div class="rule-cmd"><span class="prog">apt-mark</span> unhold</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Releases a hold so the package can be upgraded again.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-apt-mark-minimize-manual">
  <div class="rule-cmd"><span class="prog">apt-mark</span> minimize-manual</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Marks as auto any manually-installed packages that are dependencies of other manually-installed packages.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-bazel-clean">
  <div class="rule-cmd"><span class="prog">bazel</span> clean</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes Bazel build outputs. <code>--expunge</code> also deletes the workspace's external dependencies.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-bazel-run">
  <div class="rule-cmd"><span class="prog">bazel</span> run</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Builds and executes a Bazel target. The target runs as the current user with full filesystem access.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-brew-install">
  <div class="rule-cmd"><span class="prog">brew</span> install</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installs a Homebrew formula or cask plus its dependencies into the prefix. Network operation.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-brew-uninstall">
  <div class="rule-cmd"><span class="prog">brew</span> uninstall</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes installed Homebrew packages from the prefix.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-brew-remove">
  <div class="rule-cmd"><span class="prog">brew</span> remove</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes installed Homebrew packages (alias for <code>uninstall</code>).</div>
</div>
<div class="rule-row" data-decision="ask" id="system-brew-upgrade">
  <div class="rule-cmd"><span class="prog">brew</span> upgrade</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Upgrades installed Homebrew formulae/casks to the latest available versions.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-brew-update">
  <div class="rule-cmd"><span class="prog">brew</span> update</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Updates Homebrew's tap metadata. Does not upgrade installed packages.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-brew-reinstall">
  <div class="rule-cmd"><span class="prog">brew</span> reinstall</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes and re-installs a Homebrew formula or cask.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-brew-link">
  <div class="rule-cmd"><span class="prog">brew</span> link</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Symlinks a formula's files into the Homebrew prefix.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-brew-unlink">
  <div class="rule-cmd"><span class="prog">brew</span> unlink</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes a formula's symlinks from the Homebrew prefix without uninstalling.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-brew-pin">
  <div class="rule-cmd"><span class="prog">brew</span> pin</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Prevents a formula from being upgraded by <code>brew upgrade</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-brew-unpin">
  <div class="rule-cmd"><span class="prog">brew</span> unpin</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes a pin so a formula can be upgraded again.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-brew-tap">
  <div class="rule-cmd"><span class="prog">brew</span> tap</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Adds a third-party Homebrew tap to the list of trusted sources.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-brew-untap">
  <div class="rule-cmd"><span class="prog">brew</span> untap</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes a Homebrew tap and its formulae from the local list of sources.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-brew-cleanup">
  <div class="rule-cmd"><span class="prog">brew</span> cleanup</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes old versions of installed formulae and the download cache.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-brew-autoremove">
  <div class="rule-cmd"><span class="prog">brew</span> autoremove</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes Homebrew formulae installed as dependencies that are no longer needed.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-brew-services">
  <div class="rule-cmd"><span class="prog">brew</span> services</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Manages Homebrew background services (start/stop/run/list).</div>
</div>
<div class="rule-row" data-decision="ask" id="system-cmake">
  <div class="rule-cmd"><span class="prog">cmake</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Runs CMake to configure or build. Generates build files and may invoke the underlying compiler.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-createdb">
  <div class="rule-cmd"><span class="prog">createdb</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creates a new PostgreSQL database. Connects to the server using the configured role.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-crontab">
  <div class="rule-cmd"><span class="prog">crontab</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Modifies cron jobs. Scheduled jobs persist across logout/reboot and run as the user; verify the schedule and command body.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-dbmate">
  <div class="rule-cmd"><span class="prog">dbmate</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Runs a database migration via dbmate. Applies schema changes; review the migration files first.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-dnf-install">
  <div class="rule-cmd"><span class="prog">dnf</span> install</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installs packages and their dependencies from the enabled repos. Network operation; changes system package state.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-dnf-remove">
  <div class="rule-cmd"><span class="prog">dnf</span> remove</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes packages from the system.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-dnf-erase">
  <div class="rule-cmd"><span class="prog">dnf</span> erase</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes packages from the system (alias for <code>remove</code>).</div>
</div>
<div class="rule-row" data-decision="ask" id="system-dnf-update">
  <div class="rule-cmd"><span class="prog">dnf</span> update</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Updates installed packages to the latest version available in the enabled repos.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-dnf-upgrade">
  <div class="rule-cmd"><span class="prog">dnf</span> upgrade</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Upgrades installed packages (alias for <code>update</code>).</div>
</div>
<div class="rule-row" data-decision="ask" id="system-dnf-downgrade">
  <div class="rule-cmd"><span class="prog">dnf</span> downgrade</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Replaces installed packages with an older available version. May break dependencies.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-dnf-reinstall">
  <div class="rule-cmd"><span class="prog">dnf</span> reinstall</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Reinstalls already-installed packages, restoring overwritten files from the package payload.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-dnf-autoremove">
  <div class="rule-cmd"><span class="prog">dnf</span> autoremove</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes packages installed as dependencies that are no longer needed.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-dnf-clean">
  <div class="rule-cmd"><span class="prog">dnf</span> clean</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Cleans cached package data and metadata from the dnf cache.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-dnf-makecache">
  <div class="rule-cmd"><span class="prog">dnf</span> makecache</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Downloads and caches repository metadata for enabled repos.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-dnf-group">
  <div class="rule-cmd"><span class="prog">dnf</span> group</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installs, removes, or queries a dnf package group.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-dnf-module">
  <div class="rule-cmd"><span class="prog">dnf</span> module</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installs, removes, enables, or queries dnf modules (streams of related packages).</div>
</div>
<div class="rule-row" data-decision="ask" id="system-dnf-swap">
  <div class="rule-cmd"><span class="prog">dnf</span> swap</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Atomically removes one package and installs another in its place.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-dnf-distro-sync">
  <div class="rule-cmd"><span class="prog">dnf</span> distro-sync</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Synchronizes packages with the distribution version (can downgrade/upgrade across the repo set). Review changes before approving.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-dpkg-i-install">
  <div class="rule-cmd"><span class="prog">dpkg</span> <span class="flag">-i</span> <span class="flag">--install</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installs <code>.deb</code> package files directly via dpkg. Does not resolve dependencies; prefer <code>apt install</code> when possible.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-dpkg-r-remove-p-purge">
  <div class="rule-cmd"><span class="prog">dpkg</span> <span class="flag">-r</span> <span class="flag">--remove</span> <span class="flag">-P</span> <span class="flag">--purge</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes or purges installed packages via dpkg. <code>--purge</code> also removes config files.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-dpkg-configure-unpack">
  <div class="rule-cmd"><span class="prog">dpkg</span> <span class="flag">--configure</span> <span class="flag">--unpack</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Configures or unpacks <code>.deb</code> packages. Used in low-level package management; can leave the system in a partially-configured state if interrupted.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-dpkg-set-selections-clear-selections-add-architecture-remove-architecture">
  <div class="rule-cmd"><span class="prog">dpkg</span> <span class="flag">--set-selections</span> <span class="flag">--clear-selections</span> <span class="flag">--add-architecture</span> <span class="flag">--remove-architecture</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Modifies dpkg package state (selections or supported architectures). Affects what apt/dpkg will install or upgrade.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-dropdb">
  <div class="rule-cmd"><span class="prog">dropdb</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Drops a PostgreSQL database. Permanent; all schemas and data in the database are deleted.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-flatpak-install">
  <div class="rule-cmd"><span class="prog">flatpak</span> install</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installs a Flatpak/Snap application from a remote.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-flatpak-uninstall">
  <div class="rule-cmd"><span class="prog">flatpak</span> uninstall</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes an installed Flatpak/Snap application.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-flatpak-remove">
  <div class="rule-cmd"><span class="prog">flatpak</span> remove</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes an installed Flatpak/Snap application (alias for <code>uninstall</code>).</div>
</div>
<div class="rule-row" data-decision="ask" id="system-flatpak-update">
  <div class="rule-cmd"><span class="prog">flatpak</span> update</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Updates installed Flatpak/Snap applications.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-flatpak-upgrade">
  <div class="rule-cmd"><span class="prog">flatpak</span> upgrade</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Upgrades installed Flatpak/Snap applications (alias for <code>update</code>).</div>
</div>
<div class="rule-row" data-decision="ask" id="system-flatpak-run">
  <div class="rule-cmd"><span class="prog">flatpak</span> run</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Launches an installed Flatpak/Snap application.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-flatpak-remote-add">
  <div class="rule-cmd"><span class="prog">flatpak</span> remote-add</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Adds a new Flatpak remote to the trusted list. Future installs can pull from it.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-flatpak-remote-delete">
  <div class="rule-cmd"><span class="prog">flatpak</span> remote-delete</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes a configured Flatpak remote.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-flatpak-repair">
  <div class="rule-cmd"><span class="prog">flatpak</span> repair</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Repairs the local Flatpak installation. May re-download corrupted objects.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-flyway">
  <div class="rule-cmd"><span class="prog">flyway</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Runs a database migration via Flyway. Applies schema changes; review the migration files first.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-goose">
  <div class="rule-cmd"><span class="prog">goose</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Runs a database migration via goose. Applies schema changes; review the migration files first.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-gpg-sign-s-clearsign-detach-sign-b">
  <div class="rule-cmd"><span class="prog">gpg</span> <span class="flag">--sign</span> <span class="flag">-s</span> <span class="flag">--clearsign</span> <span class="flag">--detach-sign</span> <span class="flag">-b</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Signs data with a GPG private key. <code>--clearsign</code> keeps the message readable; <code>--detach-sign</code> writes a separate <code>.sig</code> file.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-gpg-encrypt-e-symmetric-c">
  <div class="rule-cmd"><span class="prog">gpg</span> <span class="flag">--encrypt</span> <span class="flag">-e</span> <span class="flag">--symmetric</span> <span class="flag">-c</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Encrypts data with a GPG recipient key or a passphrase (<code>--symmetric</code>).</div>
</div>
<div class="rule-row" data-decision="ask" id="system-gpg-decrypt-d">
  <div class="rule-cmd"><span class="prog">gpg</span> <span class="flag">--decrypt</span> <span class="flag">-d</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Decrypts a GPG-encrypted file using the matching private key or passphrase.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-gpg-import">
  <div class="rule-cmd"><span class="prog">gpg</span> <span class="flag">--import</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Imports a GPG public or private key into the local keyring. The imported key becomes trusted for signature verification.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-gpg-export-export-secret-keys">
  <div class="rule-cmd"><span class="prog">gpg</span> <span class="flag">--export</span> <span class="flag">--export-secret-keys</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Exports a GPG key. <code>--export-secret-keys</code> exports private key material; protect the output file.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-gpg-delete-key-delete-secret-key-delete-secret-and-public-key">
  <div class="rule-cmd"><span class="prog">gpg</span> <span class="flag">--delete-key</span> <span class="flag">--delete-secret-key</span> <span class="flag">--delete-secret-and-public-key</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Deletes a key from the local GPG keyring. <code>--delete-secret-key</code> removes private material; cannot be undone without a backup.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-gpg-gen-key-generate-key-full-gen-key-full-generate-key-quick-gen-key">
  <div class="rule-cmd"><span class="prog">gpg</span> <span class="flag">--gen-key</span> <span class="flag">--generate-key</span> <span class="flag">--full-gen-key</span> <span class="flag">--full-generate-key</span> <span class="flag">--quick-gen-key</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Generates a new GPG keypair. Writes private material to the keyring; choose a passphrase strong enough for the use case.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-gpg-edit-key">
  <div class="rule-cmd"><span class="prog">gpg</span> <span class="flag">--edit-key</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Opens an interactive GPG key editor. May block in agent contexts; modifies the local keyring.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-gradle-publish">
  <div class="rule-cmd"><span class="prog">gradle</span> publish</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Publishes Gradle artifacts to a configured repository. Network operation; affects downstream consumers.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-gradle-uploadarchives">
  <div class="rule-cmd"><span class="prog">gradle</span> uploadArchives</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Uploads built archives to a configured Gradle repository.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-hyperfine">
  <div class="rule-cmd"><span class="prog">hyperfine</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Runs the given command repeatedly to measure timing. Executes the wrapped command on each iteration.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-kill">
  <div class="rule-cmd"><span class="prog">kill</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Sends a signal to the listed PIDs (default SIGTERM). Verify the PID first; <code>-9</code> (SIGKILL) cannot be caught and can corrupt state.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-killall">
  <div class="rule-cmd"><span class="prog">killall</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Signals ALL processes with the given name. Verify which processes match (different from <code>kill &lt;pid&gt;</code>); <code>-9</code> cannot be caught.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-meson-setup">
  <div class="rule-cmd"><span class="prog">meson</span> setup</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Configures a Meson build directory. Reads <code>meson.build</code> and writes build system files.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-meson-compile">
  <div class="rule-cmd"><span class="prog">meson</span> compile</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Compiles a Meson project. Invokes the underlying build backend (ninja by default).</div>
</div>
<div class="rule-row" data-decision="ask" id="system-meson-install">
  <div class="rule-cmd"><span class="prog">meson</span> install</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installs Meson build outputs to the configured prefix. May require root depending on prefix.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-migrate">
  <div class="rule-cmd"><span class="prog">migrate</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Runs a database migration via golang-migrate. Applies schema changes; review the migration files first.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-mongosh-eval">
  <div class="rule-cmd"><span class="prog">mongosh</span> <span class="flag">--eval</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">MongoDB session with <code>--eval</code> script. The eval body runs as JS in the database context and can mutate data.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-mongosh">
  <div class="rule-cmd"><span class="prog">mongosh</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Opens a MongoDB session. Verify the connection target before running mutating queries.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-mount">
  <div class="rule-cmd"><span class="prog">mount</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Mounts a filesystem. Usually requires root in most setups; verify the source device and target mount point.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-mvn-install">
  <div class="rule-cmd"><span class="prog">mvn</span> install</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installs the built Maven artifact into the local repository (<code>~/.m2/repository</code>).</div>
</div>
<div class="rule-row" data-decision="ask" id="system-mvn-deploy">
  <div class="rule-cmd"><span class="prog">mvn</span> deploy</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Deploys Maven artifacts to a remote repository. Network operation; affects downstream consumers.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-ninja-clean">
  <div class="rule-cmd"><span class="prog">ninja</span> clean</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes Ninja build artifacts in the current build directory.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-nix-build">
  <div class="rule-cmd"><span class="prog">nix</span> build</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Builds a Nix derivation. May download from substituters or compile locally.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-nix-develop">
  <div class="rule-cmd"><span class="prog">nix</span> develop</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Enters a Nix development shell with the package's build dependencies in scope.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-nix-run">
  <div class="rule-cmd"><span class="prog">nix</span> run</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Builds and runs the given Nix package. The package executes as the current user.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-nix-shell">
  <div class="rule-cmd"><span class="prog">nix</span> shell</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Opens an interactive shell with the given Nix packages available.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-nix-profile">
  <div class="rule-cmd"><span class="prog">nix</span> profile</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installs, removes, or upgrades packages in a Nix user profile.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-nix-upgrade-nix">
  <div class="rule-cmd"><span class="prog">nix</span> upgrade-nix</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Upgrades the Nix package manager itself to the latest version.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-nix-copy">
  <div class="rule-cmd"><span class="prog">nix</span> copy</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Copies Nix store paths between stores (local, remote, or s3). Network operation.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-nix-collect-garbage">
  <div class="rule-cmd"><span class="prog">nix</span> collect-garbage</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Deletes unreachable paths from the Nix store. Frees disk; cannot be undone without rebuilding.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-nix-env-i">
  <div class="rule-cmd"><span class="prog">nix-env</span> -i</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installs a Nix package into the current user profile.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-nix-env-install">
  <div class="rule-cmd"><span class="prog">nix-env</span> --install</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installs a Nix package into the current user profile.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-nix-env-e">
  <div class="rule-cmd"><span class="prog">nix-env</span> -e</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Uninstalls a Nix package from the current user profile.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-nix-env-uninstall">
  <div class="rule-cmd"><span class="prog">nix-env</span> --uninstall</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Uninstalls a Nix package from the current user profile.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-nix-env-u">
  <div class="rule-cmd"><span class="prog">nix-env</span> -u</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Upgrades packages in the current Nix user profile.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-nix-env-upgrade">
  <div class="rule-cmd"><span class="prog">nix-env</span> --upgrade</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Upgrades packages in the current Nix user profile.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-nix-shell-2">
  <div class="rule-cmd"><span class="prog">nix-shell</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Opens a shell with the given Nix expression's dependencies available. May download or build packages.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-openssl-x509-req">
  <div class="rule-cmd"><span class="prog">openssl</span> x509 <span class="flag">-req</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Signs a certificate request (CSR) to produce an X.509 certificate. Writes the resulting cert; affects trust if installed.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-openssl-s-server">
  <div class="rule-cmd"><span class="prog">openssl</span> s_server</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Starts a debug TLS server bound to a local port. Accepts inbound connections until terminated.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-openssl-rand-out">
  <div class="rule-cmd"><span class="prog">openssl</span> rand <span class="flag">-out</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Writes the requested number of random bytes to the file given by <code>-out</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-openssl-genrsa">
  <div class="rule-cmd"><span class="prog">openssl</span> genrsa</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Generates an RSA private key. Writes a private-key file; protect with passphrase and correct permissions.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-openssl-genpkey">
  <div class="rule-cmd"><span class="prog">openssl</span> genpkey</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Generates a private key (RSA/EC/Ed25519/etc.). Writes a private-key file; protect with passphrase and correct permissions.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-openssl-req">
  <div class="rule-cmd"><span class="prog">openssl</span> req</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creates a certificate signing request (CSR) or self-signed cert. Writes to disk.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-openssl-ca">
  <div class="rule-cmd"><span class="prog">openssl</span> ca</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Acts as a minimal certificate authority: signs CSRs, revokes certs, manages the CA database.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-openssl-pkcs12">
  <div class="rule-cmd"><span class="prog">openssl</span> pkcs12</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Packs or unpacks a PKCS#12 bundle (cert + private key). Writes key material to disk.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-openssl-enc">
  <div class="rule-cmd"><span class="prog">openssl</span> enc</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Encrypts or decrypts a file with a symmetric cipher. Default cipher is weak; prefer <code>-aes-256-cbc</code> or modern alternatives.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-openssl-smime">
  <div class="rule-cmd"><span class="prog">openssl</span> smime</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">S/MIME sign, verify, encrypt, or decrypt of an email message or file.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-openssl-cms">
  <div class="rule-cmd"><span class="prog">openssl</span> cms</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Cryptographic Message Syntax operation: sign, verify, encrypt, or decrypt a CMS structure.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-openssl-rsautl">
  <div class="rule-cmd"><span class="prog">openssl</span> rsautl</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">RSA primitive operation: sign, verify, encrypt, or decrypt with an RSA key. Legacy; prefer <code>pkeyutl</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-openssl-pkeyutl">
  <div class="rule-cmd"><span class="prog">openssl</span> pkeyutl</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Generic public-key operation: sign, verify, encrypt, decrypt, or derive shared secret.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-openssl-ecparam">
  <div class="rule-cmd"><span class="prog">openssl</span> ecparam</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Generates or inspects elliptic-curve parameters. With <code>-genkey</code>, also writes an EC private key.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-pactl-set-sink-volume">
  <div class="rule-cmd"><span class="prog">pactl</span> set-sink-volume</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Changes the volume of a PulseAudio output sink.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-pactl-set-source-volume">
  <div class="rule-cmd"><span class="prog">pactl</span> set-source-volume</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Changes the volume of a PulseAudio input source.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-pactl-set-sink-mute">
  <div class="rule-cmd"><span class="prog">pactl</span> set-sink-mute</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Mutes or unmutes a PulseAudio output sink.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-pactl-set-source-mute">
  <div class="rule-cmd"><span class="prog">pactl</span> set-source-mute</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Mutes or unmutes a PulseAudio input source.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-pactl-set-default-sink">
  <div class="rule-cmd"><span class="prog">pactl</span> set-default-sink</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Changes which PulseAudio sink is the default for new streams.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-pactl-set-default-source">
  <div class="rule-cmd"><span class="prog">pactl</span> set-default-source</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Changes which PulseAudio source is the default for new captures.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-pactl-load-module">
  <div class="rule-cmd"><span class="prog">pactl</span> load-module</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Loads a PulseAudio module into the running daemon. Modules can route, filter, or expose audio.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-pactl-unload-module">
  <div class="rule-cmd"><span class="prog">pactl</span> unload-module</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Unloads a PulseAudio module from the running daemon.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-pactl-exit">
  <div class="rule-cmd"><span class="prog">pactl</span> exit</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Terminates the running PulseAudio daemon. Active audio streams will drop.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-pg-restore">
  <div class="rule-cmd"><span class="prog">pg_restore</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Restores a PostgreSQL dump into a database. Can overwrite existing objects depending on flags.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-pkill">
  <div class="rule-cmd"><span class="prog">pkill</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Signals processes matching a pattern. Run <code>pgrep &lt;pattern&gt;</code> first to verify which processes match; <code>-9</code> cannot be caught.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-sqlite3">
  <div class="rule-cmd"><span class="prog">sqlite3</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Opens a SQLite database file. Default mode allows writes; use <code>-readonly</code> to limit to queries.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-ssh-keygen-r">
  <div class="rule-cmd"><span class="prog">ssh-keygen</span> <span class="flag">-R</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes a host from the <code>known_hosts</code> file. Next connection will re-prompt for host key verification.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-ssh-keygen">
  <div class="rule-cmd"><span class="prog">ssh-keygen</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Generates or modifies an SSH key. Writes a private-key file; protect the output path and passphrase.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-systemctl-start">
  <div class="rule-cmd"><span class="prog">systemctl</span> start</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Starts a systemd unit. Side effects depend on the unit type (service, socket, timer, etc.).</div>
</div>
<div class="rule-row" data-decision="ask" id="system-systemctl-stop">
  <div class="rule-cmd"><span class="prog">systemctl</span> stop</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Stops a running systemd unit. Active connections/jobs handled by the unit may be cut off.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-systemctl-restart">
  <div class="rule-cmd"><span class="prog">systemctl</span> restart</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Stops and starts a systemd unit. Brief downtime; in-flight work in the unit may be lost.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-systemctl-reload">
  <div class="rule-cmd"><span class="prog">systemctl</span> reload</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Asks a systemd unit to reload its configuration without restarting. Unit must support SIGHUP-style reload.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-systemctl-enable">
  <div class="rule-cmd"><span class="prog">systemctl</span> enable</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Enables a systemd unit to start automatically at boot. Creates symlinks under <code>/etc/systemd/system/</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-systemctl-disable">
  <div class="rule-cmd"><span class="prog">systemctl</span> disable</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes a systemd unit's autostart symlinks. Does not stop a currently running instance.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-systemctl-mask">
  <div class="rule-cmd"><span class="prog">systemctl</span> mask</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Symlinks a systemd unit to <code>/dev/null</code> so it cannot be started, even as a dependency.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-systemctl-unmask">
  <div class="rule-cmd"><span class="prog">systemctl</span> unmask</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes a systemd mask, allowing the unit to be started again.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-systemctl-kill">
  <div class="rule-cmd"><span class="prog">systemctl</span> kill</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Sends a signal to processes of a systemd unit (default SIGTERM). <code>-s SIGKILL</code> cannot be caught.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-systemctl-reset-failed">
  <div class="rule-cmd"><span class="prog">systemctl</span> reset-failed</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Clears the failed state of a systemd unit so it can be restarted.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-systemctl-daemon-reload">
  <div class="rule-cmd"><span class="prog">systemctl</span> daemon-reload</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Reloads systemd unit files. Required after editing a unit; doesn't restart running services on its own.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-systemctl-daemon-reexec">
  <div class="rule-cmd"><span class="prog">systemctl</span> daemon-reexec</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Re-executes systemd itself. Drops PID 1 in-place and reloads its state; rarely needed.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-systemctl-set-default">
  <div class="rule-cmd"><span class="prog">systemctl</span> set-default</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Changes the default systemd target the system boots into (e.g. <code>graphical.target</code> vs <code>multi-user.target</code>).</div>
</div>
<div class="rule-row" data-decision="ask" id="system-systemctl-isolate">
  <div class="rule-cmd"><span class="prog">systemctl</span> isolate</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Switches systemd to the target unit and stops everything not required by it. Can take down unrelated services unexpectedly.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-systemctl-edit">
  <div class="rule-cmd"><span class="prog">systemctl</span> edit</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Opens a systemd unit override in <code>$EDITOR</code>. Interactive; may block in agent contexts.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-vagrant-up">
  <div class="rule-cmd"><span class="prog">vagrant</span> up</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Creates and boots the Vagrant VM defined in the local <code>Vagrantfile</code>.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-vagrant-halt">
  <div class="rule-cmd"><span class="prog">vagrant</span> halt</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Gracefully shuts down the running Vagrant VM.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-vagrant-destroy">
  <div class="rule-cmd"><span class="prog">vagrant</span> destroy</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Deletes the Vagrant VM and its disk image. Cannot be undone; data inside the VM is lost.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-vagrant-provision">
  <div class="rule-cmd"><span class="prog">vagrant</span> provision</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Re-runs Vagrant provisioners against the running VM. Can apply configuration changes.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-vagrant-ssh">
  <div class="rule-cmd"><span class="prog">vagrant</span> ssh</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Opens an SSH session into the Vagrant VM. Commands inside bypass local tool-gates.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-vagrant-reload">
  <div class="rule-cmd"><span class="prog">vagrant</span> reload</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Halts the Vagrant VM and brings it back up, re-applying Vagrantfile changes.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-xkill">
  <div class="rule-cmd"><span class="prog">xkill</span></div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Click-to-kill X11 utility. Sends a KILL signal to whatever window is clicked next.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-zypper-install">
  <div class="rule-cmd"><span class="prog">zypper</span> install</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installs packages and dependencies from the configured repositories. Network operation; changes system package state.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-zypper-in">
  <div class="rule-cmd"><span class="prog">zypper</span> in</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installing packages (alias for <code>install</code>).</div>
</div>
<div class="rule-row" data-decision="ask" id="system-zypper-remove">
  <div class="rule-cmd"><span class="prog">zypper</span> remove</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes installed zypper packages.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-zypper-rm">
  <div class="rule-cmd"><span class="prog">zypper</span> rm</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes installed zypper packages (alias for <code>remove</code>).</div>
</div>
<div class="rule-row" data-decision="ask" id="system-zypper-update">
  <div class="rule-cmd"><span class="prog">zypper</span> update</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Updates installed zypper packages to newer versions.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-zypper-up">
  <div class="rule-cmd"><span class="prog">zypper</span> up</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Updates installed zypper packages (alias for <code>update</code>).</div>
</div>
<div class="rule-row" data-decision="ask" id="system-zypper-dist-upgrade">
  <div class="rule-cmd"><span class="prog">zypper</span> dist-upgrade</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Distribution upgrade can install/remove many packages, including kernel and base packages. Review proposed changes before approving.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-zypper-dup">
  <div class="rule-cmd"><span class="prog">zypper</span> dup</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Distribution upgrade (alias for <code>dist-upgrade</code>).</div>
</div>
<div class="rule-row" data-decision="ask" id="system-zypper-patch">
  <div class="rule-cmd"><span class="prog">zypper</span> patch</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Installs official patches/errata for installed packages.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-zypper-addrepo">
  <div class="rule-cmd"><span class="prog">zypper</span> addrepo</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Adds a new zypper repository to the trusted list.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-zypper-ar">
  <div class="rule-cmd"><span class="prog">zypper</span> ar</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Adds a new zypper repository (alias for <code>addrepo</code>).</div>
</div>
<div class="rule-row" data-decision="ask" id="system-zypper-removerepo">
  <div class="rule-cmd"><span class="prog">zypper</span> removerepo</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes a configured zypper repository.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-zypper-rr">
  <div class="rule-cmd"><span class="prog">zypper</span> rr</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Removes a configured zypper repository (alias for <code>removerepo</code>).</div>
</div>
<div class="rule-row" data-decision="ask" id="system-zypper-refresh">
  <div class="rule-cmd"><span class="prog">zypper</span> refresh</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Refreshes zypper repository metadata.</div>
</div>
<div class="rule-row" data-decision="ask" id="system-zypper-ref">
  <div class="rule-cmd"><span class="prog">zypper</span> ref</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Refreshes zypper repository metadata (alias for <code>refresh</code>).</div>
</div>
<div class="rule-row" data-decision="ask" id="system-zypper-clean">
  <div class="rule-cmd"><span class="prog">zypper</span> clean</div>
  <div><span class="pill ask"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="9" y1="6" x2="9" y2="18"></line><line x1="15" y1="6" x2="15" y2="18"></line></svg>Ask</span></div>
  <div class="rule-reason">Cleans cached zypper package data and metadata.</div>
</div>
</div>
