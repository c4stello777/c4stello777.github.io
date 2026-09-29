class VirtualFS {
constructor() {
this.fs = this.buildFS();
this.cwd = '/home/user';
this.user = 'user';
this.groups = ['user'];
this.isRoot = false;
this.startTime = Date.now();
this.commandCount = 0;
this.completedLevels = new Set();
this.history = [];
this.historyIndex = -1;
}

buildFS() {
return {
'/': {
type: 'dir',
permissions: 'drwxr-xr-x',
owner: 'root',
group: 'root',
children: {
'home': {
type: 'dir',
permissions: 'drwxr-xr-x',
owner: 'root',
group: 'root',
children: {
'user': {
type: 'dir',
permissions: 'drwxr-x---',
owner: 'user',
group: 'user',
children: {
'documents': {
type: 'dir',
permissions: 'drwxr-xr-x',
owner: 'user',
group: 'user',
children: {
'notes.txt': { type: 'file', permissions: '-rw-r--r--', owner: 'user', group: 'user', content: 'Personal notes:\n- Check sudo -l for misconfigurations\n- Look for SUID binaries in /home/user/scripts\n- Cron jobs in /etc/cron.d/\n- Capabilities with getcap -r /\n' }
},
'downloads': {
type: 'dir',
permissions: 'drwxr-xr-x',
owner: 'user',
group: 'user',
children: {
'readme.txt': { type: 'file', permissions: '-rw-r--r--', owner: 'user', group: 'user', content: 'Welcome to the LPE Challenge!\n\nGoal: Escalate from user to root and read /home/user/restricted/flag.txt\n\nLevels:\n1. SUID Binary Exploitation\n2. Sudo Misconfiguration\n3. PATH Hijacking\n4. Cron Job Abuse\n5. Capabilities Abuse\n\nType "help" for commands, "hint" for current level hint.\n' }
},
'restricted': {
type: 'dir',
permissions: 'drwx------',
owner: 'root',
group: 'root',
children: {
'flag.txt': { type: 'file', permissions: '-rw-------', owner: 'root', group: 'root', content: 'flag{pr1v_3sc4l4t10n_m4st3r_2024}\n' }
}
},
'scripts': {
type: 'dir',
permissions: 'drwxr-xr-x',
owner: 'user',
group: 'user',
children: {
'vuln_binary': { type: 'file', permissions: '-rwsr-xr-x', owner: 'root', group: 'root', content: 'ELF 64-bit SUID binary', suid: true, binary: 'vuln_binary' },
'backup.sh': { type: 'file', permissions: '-rwxrwxrwx', owner: 'user', group: 'user', content: '#!/bin/bash\n# Backup script - runs as root via cron\ntar -czf /tmp/backup_$(date +%s).tar.gz /home/user/documents\n', binary: 'backup.sh' },
'custom_tool': { type: 'file', permissions: '-rwxr-xr-x', owner: 'root', group: 'root', content: 'ELF 64-bit binary with capabilities', caps: ['cap_dac_read_search+ep'], binary: 'custom_tool' },
'exploit_helper.sh': { type: 'file', permissions: '-rw-r--r--', owner: 'user', group: 'user', content: '# Helper script for PATH hijacking\necho "Create a malicious ls in current dir:\necho '\''#!/bin/bash\ncat /home/user/restricted/flag.txt'\'' > ls\nchmod +x ls\nPATH=.:$PATH ./vuln_binary\n" }
}
},
'.bash_history': { type: 'file', permissions: '-rw-r--r--', owner: 'user', group: 'user', content: 'ls -la\ncd scripts\nls -la\n./vuln_binary\nsudo -l\ngetcap -r / 2>/dev/null\ncat /etc/cron.d/backup\n' },
'.sudoers': { type: 'file', permissions: '-r--r-----', owner: 'root', group: 'root', content: '# Simulated sudoers\nuser ALL=(root) NOPASSWD: /usr/bin/vim\nuser ALL=(root) NOPASSWD: /usr/bin/find\n' }
}
}
},
'etc': {
type: 'dir',
permissions: 'drwxr-xr-x',
owner: 'root',
group: 'root',
children: {
'cron.d': {
type: 'dir',
permissions: 'drwxr-xr-x',
owner: 'root',
group: 'root',
children: {
'backup': { type: 'file', permissions: '-rw-r--r--', owner: 'root', group: 'root', content: '* * * * * root /home/user/scripts/backup.sh\n' }
},
'passwd': { type: 'file', permissions: '-rw-r--r--', owner: 'root', group: 'root', content: 'root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000:user:/home/user:/bin/bash\n' },
'sudoers': { type: 'file', permissions: '-r--r-----', owner: 'root', group: 'root', content: '# Simulated sudoers\nuser ALL=(root) NOPASSWD: /usr/bin/vim\nuser ALL=(root) NOPASSWD: /usr/bin/find\n' }
}
},
'usr': {
type: 'dir',
permissions: 'drwxr-xr-x',
owner: 'root',
group: 'root',
children: {
'bin': {
type: 'dir',
permissions: 'drwxr-xr-x',
owner: 'root',
group: 'root',
children: {
'vim': { type: 'file', permissions: '-rwxr-xr-x', owner: 'root', group: 'root', content: 'ELF vim binary', binary: 'vim' },
'find': { type: 'file', permissions: '-rwxr-xr-x', owner: 'root', group: 'root', content: 'ELF find binary', binary: 'find' },
'bash': { type: 'file', permissions: '-rwxr-xr-x', owner: 'root', group: 'root', content: 'ELF bash binary', binary: 'bash' },
'cat': { type: 'file', permissions: '-rwxr-xr-x', owner: 'root', group: 'root', content: 'ELF cat binary', binary: 'cat' },
'ls': { type: 'file', permissions: '-rwxr-xr-x', owner: 'root', group: 'root', content: 'ELF ls binary', binary: 'ls' },
'getcap': { type: 'file', permissions: '-rwxr-xr-x', owner: 'root', group: 'root', content: 'ELF getcap binary', binary: 'getcap' },
'strings': { type: 'file', permissions: '-rwxr-xr-x', owner: 'root', group: 'root', content: 'ELF strings binary', binary: 'strings' },
'which': { type: 'file', permissions: '-rwxr-xr-x', owner: 'root', group: 'root', content: 'ELF which binary', binary: 'which' },
'id': { type: 'file', permissions: '-rwxr-xr-x', owner: 'root', group: 'root', content: 'ELF id binary', binary: 'id' },
'su': { type: 'file', permissions: '-rwsr-xr-x', owner: 'root', group: 'root', content: 'ELF su binary', suid: true, binary: 'su' },
'sudo': { type: 'file', permissions: '-rwsr-xr-x', owner: 'root', group: 'root', content: 'ELF sudo binary', suid: true, binary: 'sudo' }
}
}
},
'tmp': {
type: 'dir',
permissions: 'drwxrwxrwt',
owner: 'root',
group: 'root',
children: {}
},
'root': {
type: 'dir',
permissions: 'drwx------',
owner: 'root',
group: 'root',
children: {
'root.txt': { type: 'file', permissions: '-rw-------', owner: 'root', group: 'root', content: 'flag{pr1v_3sc4l4t10n_m4st3r_2024}\n' }
}
}
};
}

resolvePath(path) {
if (!path) return this.cwd;
if (path.startsWith('/')) return path;
const parts = this.cwd.split('/').filter(Boolean);
const pathParts = path.split('/');
for (const part of pathParts) {
if (part === '..') { parts.pop(); }
else if (part === '.' || part === '') { continue; }
else { parts.push(part); }
}
return '/' + parts.join('/');
}

getNode(path) {
const resolved = this.resolvePath(path);
const parts = resolved.split('/').filter(Boolean);
let node = this.fs;
for (const part of parts) {
if (!node.children || !node.children[part]) return null;
node = node.children[part];
}
return node;
}

getParentNode(path) {
const resolved = this.resolvePath(path);
const parts = resolved.split('/').filter(Boolean);
parts.pop();
let node = this.fs;
for (const part of parts) {
if (!node.children || !node.children[part]) return null;
node = node.children[part];
}
return node;
}

canRead(node) {
if (this.isRoot) return true;
const perms = node.permissions;
if (node.owner === this.user) return perms[1] === 'r';
if (this.groups.includes(node.group)) return perms[4] === 'r';
return perms[7] === 'r';
}

canWrite(node) {
if (this.isRoot) return true;
const perms = node.permissions;
if (node.owner === this.user) return perms[2] === 'w';
if (this.groups.includes(node.group)) return perms[5] === 'w';
return perms[8] === 'w';
}

canExecute(node) {
if (this.isRoot) return true;
const perms = node.permissions;
if (node.owner === this.user) return perms[3] === 'x';
if (this.groups.includes(node.group)) return perms[6] === 'x';
return perms[9] === 'x';
}

listDir(path) {
const node = this.getNode(path);
if (!node || node.type !== 'dir') return null;
const entries = [];
for (const [name, child] of Object.entries(node.children)) {
let displayName = name;
let className = 'file';
if (child.type === 'dir') { className = 'dir'; displayName += '/'; }
else if (child.suid) { className = 'exec'; displayName += '*'; }
else if (child.caps && child.caps.length > 0) { className = 'exec'; displayName += '+'; }
else if (this.canExecute(child)) { className = 'exec'; }
if (!this.canRead(child)) { className = 'restricted'; }
entries.push({ name: displayName, rawName: name, className, permissions: child.permissions, owner: child.owner, group: child.group, size: child.content?.length || 0 });
}
return entries;
}

readFile(path) {
const node = this.getNode(path);
if (!node || node.type !== 'file') return { error: 'Not a file' };
if (!this.canRead(node)) return { error: 'Permission denied' };
return { content: node.content || '' };
}

writeFile(path, content) {
const parent = this.getParentNode(path);
const name = path.split('/').pop();
if (!parent || parent.type !== 'dir') return { error: 'Invalid path' };
if (!this.canWrite(parent)) return { error: 'Permission denied' };
if (parent.children[name] && !this.canWrite(parent.children[name])) return { error: 'Permission denied' };
parent.children[name] = { type: 'file', permissions: '-rw-r--r--', owner: this.user, group: this.user, content };
return { success: true };
}

executeBinary(name, args, env) {
const paths = (env.PATH || '/usr/bin:/bin').split(':');
for (const p of paths) {
const fullPath = p + '/' + name;
const node = this.getNode(fullPath);
if (node && node.type === 'file' && this.canExecute(node)) {
return { node, fullPath };
}
}
return { error: `command not found: ${name}` };
}

checkSudoers(cmd) {
const sudoers = this.getNode('/etc/sudoers');
if (!sudoers) return false;
const content = sudoers.content || '';
const lines = content.split('\n');
for (const line of lines) {
if (line.includes('NOPASSWD') && line.includes(cmd)) {
return true;
}
}
return false;
}

getCapabilities(path) {
const node = this.getNode(path);
if (!node || !node.caps) return [];
return node.caps;
}

getSUIDBinaries() {
const suid = [];
const findSUID = (node, path) => {
if (node.type === 'file' && node.suid) {
suid.push(path);
}
if (node.children) {
for (const [name, child] of Object.entries(node.children)) {
findSUID(child, path + '/' + name);
}
}
};
findSUID(this.fs, '');
return suid;
}

getWorldWritableCronScripts() {
const scripts = [];
const cronDir = this.getNode('/etc/cron.d');
if (cronDir && cronDir.children) {
for (const [name, file] of Object.entries(cronDir.children)) {
if (file.type === 'file' && file.content) {
const lines = file.content.split('\n');
for (const line of lines) {
const match = line.match(/^\s*\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\S+)\s+(.+)$/);
if (match) {
const scriptPath = match[2].trim();
const scriptNode = this.getNode(scriptPath);
if (scriptNode && scriptNode.type === 'file') {
const perms = scriptNode.permissions;
if (perms[8] === 'w' || perms[5] === 'w' || perms[2] === 'w') {
scripts.push({ path: scriptPath, perms, content: scriptNode.content });
}
}
}
}
}
}
}
return scripts;
}

getCapabilityBinaries() {
const caps = [];
const findCaps = (node, path) => {
if (node.type === 'file' && node.caps && node.caps.length > 0) {
caps.push({ path, caps: node.caps });
}
if (node.children) {
for (const [name, child] of Object.entries(node.children)) {
findCaps(child, path + '/' + name);
}
}
};
findCaps(this.fs, '');
return caps;
}
}

class TerminalEngine {
constructor(fs, ui) {
this.fs = fs;
this.ui = ui;
this.env = { PATH: '/usr/bin:/bin:/home/user/scripts', HOME: '/home/user', USER: 'user', SHELL: '/bin/bash' };
this.aliases = { 'll': 'ls -la', 'la': 'ls -la' };
this.builtinCommands = {
'ls': this.cmdLs.bind(this),
'cd': this.cmdCd.bind(this),
'pwd': this.cmdPwd.bind(this),
'cat': this.cmdCat.bind(this),
'find': this.cmdFind.bind(this),
'strings': this.cmdStrings.bind(this),
'which': this.cmdWhich.bind(this),
'getcap': this.cmdGetcap.bind(this),
'sudo': this.cmdSudo.bind(this),
'su': this.cmdSu.bind(this),
'id': this.cmdId.bind(this),
'export': this.cmdExport.bind(this),
'help': this.cmdHelp.bind(this),
'hint': this.cmdHint.bind(this),
'history': this.cmdHistory.bind(this),
'clear': this.cmdClear.bind(this),
'reset': this.cmdReset.bind(this),
'levels': this.cmdLevels.bind(this),
'whoami': this.cmdWhoami.bind(this),
'echo': this.cmdEcho.bind(this)
};
}

async execute(input) {
const trimmed = input.trim();
if (!trimmed) return;
this.fs.commandCount++;
this.fs.history.push(trimmed);
this.fs.historyIndex = this.fs.history.length;
this.ui.addOutput(`<span class="command">${this.ui.escapeHtml(this.getPrompt())} ${this.ui.escapeHtml(trimmed)}</span>`, 'command');

const parts = this.parseCommand(trimmed);
const cmd = parts[0];
const args = parts.slice(1);

if (this.aliases[cmd]) {
const expanded = this.aliases[cmd] + ' ' + args.join(' ');
return this.execute(expanded);
}

if (this.builtinCommands[cmd]) {
try {
await this.builtinCommands[cmd](args);
} catch (e) {
this.ui.addOutput(`<span class="error">Error: ${e.message}</span>`, 'error');
}
return;
}

const result = this.fs.executeBinary(cmd, args, this.env);
if (result.error) {
this.ui.addOutput(`<span class="error">${this.ui.escapeHtml(result.error)}</span>`, 'error');
return;
}

const { node, fullPath } = result;
await this.runBinary(node, fullPath, args);
}

parseCommand(input) {
const parts = [];
let current = '';
let inQuotes = false;
let quoteChar = '';
for (let i = 0; i < input.length; i++) {
const char = input[i];
if ((char === '"' || char === "'") && !inQuotes) { inQuotes = true; quoteChar = char; }
else if (char === quoteChar && inQuotes) { inQuotes = false; quoteChar = ''; }
else if (char === ' ' && !inQuotes) { if (current) { parts.push(current); current = ''; } }
else { current += char; }
}
if (current) parts.push(current);
return parts;
}

getPrompt() {
const user = this.fs.isRoot ? 'root' : 'user';
const host = 'ctf';
const path = this.fs.cwd.replace('/home/user', '~').replace('/root', '~');
const symbol = this.fs.isRoot ? '#' : '$';
return `${user}@${host}:${path}${symbol}`;
}

async runBinary(node, fullPath, args) {
const binary = node.binary;
switch (binary) {
case 'vuln_binary':
await this.runVulnBinary(args);
break;
case 'vim':
await this.runVim(args);
break;
case 'find':
await this.runFind(args);
break;
case 'bash':
await this.runBash(args);
break;
case 'cat':
await this.runCat(args);
break;
case 'ls':
await this.runLs(args);
break;
case 'getcap':
await this.runGetcap(args);
break;
case 'strings':
await this.runStrings(args);
break;
case 'which':
await this.runWhich(args);
break;
case 'id':
await this.runId(args);
break;
case 'su':
await this.runSu(args);
break;
case 'sudo':
await this.runSudo(args);
break;
default:
this.ui.addOutput(`<span class="info">[${binary}] executed with args: ${args.join(' ')}</span>`, 'info');
}
}

async runVulnBinary(args) {
this.ui.addOutput('<span class="system">[vuln_binary] Running security check...</span>', 'system');
await this.sleep(500);
this.ui.addOutput('<span class="system">[vuln_binary] Reading flag file via system("cat /home/user/restricted/flag.txt")...</span>', 'system');
await this.sleep(300);

const catResult = this.fs.executeBinary('cat', ['/home/user/restricted/flag.txt'], this.env);
if (catResult.error) {
this.ui.addOutput('<span class="error">[vuln_binary] Failed to read flag: cat not found in PATH</span>', 'error');
return;
}

const flagContent = this.fs.readFile('/home/user/restricted/flag.txt');
if (flagContent.error) {
this.ui.addOutput('<span class="error">[vuln_binary] Permission denied reading flag</span>', 'error');
return;
}

this.ui.addOutput(`<span class="success">[vuln_binary] Flag: ${this.ui.escapeHtml(flagContent.content.trim())}</span>`, 'success');
this.completeLevel(1);
}

async runVim(args) {
if (args.length === 0) {
this.ui.addOutput('<span class="system">VIM - Vi IMproved</span>', 'system');
this.ui.addOutput('<span class="system">Type :q to quit, :!bash to spawn shell</span>', 'system');
return;
}
const file = args[0];
if (file === '-c' && args[1] === ':!bash') {
this.ui.addOutput('<span class="success">[vim] Spawning root shell...</span>', 'success');
await this.sleep(300);
this.becomeRoot();
return;
}
const result = this.fs.readFile(this.fs.resolvePath(file));
if (result.error) {
this.ui.addOutput(`<span class="error">vim: ${result.error}</span>`, 'error');
return;
}
this.ui.addOutput(`<span class="system">[vim] Opened ${file} (readonly simulation)</span>', 'system');
this.ui.addOutput(`<span class="info">${this.ui.escapeHtml(result.content)}</span>`, 'info');
}

async runFind(args) {
const pathIdx = args.findIndex(a => !a.startsWith('-'));
const path = pathIdx >= 0 ? args[pathIdx] : '.';
const nameIdx = args.indexOf('-name');
const pattern = nameIdx >= 0 && args[nameIdx + 1] ? args[nameIdx + 1] : '*';
const permIdx = args.indexOf('-perm');
const perm = permIdx >= 0 && args[permIdx + 1] ? args[permIdx + 1] : null;

const results = [];
const search = (node, currentPath) => {
if (!node) return;
const name = currentPath.split('/').pop();
const matchName = this.matchPattern(name, pattern);
const matchPerm = perm ? this.matchPerm(node.permissions, perm) : true;
if (matchName && matchPerm) results.push(currentPath);
if (node.children) {
for (const [childName, child] of Object.entries(node.children)) {
search(child, currentPath + '/' + childName);
}
}
};
search(this.fs.getNode(this.fs.resolvePath(path)), this.fs.resolvePath(path));
for (const r of results) this.ui.addOutput(`<span class="file">${this.ui.escapeHtml(r)}</span>`, 'file');
}

async runBash(args) {
if (args.includes('-c') || args.includes('-p')) {
this.becomeRoot();
} else {
this.ui.addOutput('<span class="system">[bash] Interactive shell not simulated. Use -c or -p</span>', 'system');
}
}

async runCat(args) {
for (const arg of args) {
const result = this.fs.readFile(this.fs.resolvePath(arg));
if (result.error) { this.ui.addOutput(`<span class="error">cat: ${arg}: ${result.error}</span>`, 'error'); }
else { this.ui.addOutput(`<span class="info">${this.ui.escapeHtml(result.content)}</span>`, 'info'); }
}
}

async runLs(args) {
const path = args.find(a => !a.startsWith('-')) || '.';
const showAll = args.includes('-a') || args.includes('-la') || args.includes('-al');
const long = args.includes('-l') || args.includes('-la') || args.includes('-al');
const entries = this.fs.listDir(this.fs.resolvePath(path));
if (!entries) { this.ui.addOutput(`<span class="error">ls: cannot access '${path}': No such file or directory</span>`, 'error'); return; }
for (const e of entries) {
if (!showAll && e.rawName.startsWith('.')) continue;
if (long) {
this.ui.addOutput(`<span class="${e.className}">${e.permissions} ${e.owner} ${e.group} ${e.size.toString().padStart(6)} ${e.name}</span>`, e.className);
} else {
this.ui.addOutput(`<span class="${e.className}">${e.name}</span>`, e.className);
}
}
}

async runGetcap(args) {
if (args.includes('-r')) {
const caps = this.fs.getCapabilityBinaries();
for (const c of caps) {
this.ui.addOutput(`<span class="exec">${c.path} = ${c.caps.join(', ')}</span>`, 'exec');
}
if (caps.length === 0) this.ui.addOutput('<span class="system">No capabilities found</span>', 'system');
} else {
const path = args[0];
if (!path) { this.ui.addOutput('<span class="error">Usage: getcap [-r] [file]</span>', 'error'); return; }
const node = this.fs.getNode(this.fs.resolvePath(path));
if (node && node.caps) this.ui.addOutput(`<span class="exec">${path} = ${node.caps.join(', ')}</span>`, 'exec');
else this.ui.addOutput('<span class="system">No capabilities</span>', 'system');
}
}

async runStrings(args) {
const path = args[0];
if (!path) { this.ui.addOutput('<span class="error">Usage: strings [file]</span>', 'error'); return; }
const node = this.fs.getNode(this.fs.resolvePath(path));
if (!node || node.type !== 'file') { this.ui.addOutput('<span class="error">strings: not a file</span>', 'error'); return; }
if (node.binary) {
const strings = this.extractStrings(node.content || node.binary);
for (const s of strings) this.ui.addOutput(`<span class="info">${this.ui.escapeHtml(s)}</span>`, 'info');
} else {
this.ui.addOutput(`<span class="info">${this.ui.escapeHtml(node.content || '')}</span>`, 'info');
}
}

async runWhich(args) {
const cmd = args[0];
if (!cmd) return;
const result = this.fs.executeBinary(cmd, [], this.env);
if (result.error) this.ui.addOutput(`<span class="error">${cmd} not found</span>`, 'error');
else this.ui.addOutput(`<span class="file">${result.fullPath}</span>`, 'file');
}

async runId(args) {
const u = this.fs.isRoot ? 'root' : 'user';
const uid = this.fs.isRoot ? 0 : 1000;
this.ui.addOutput(`<span class="info">uid=${uid}(${u}) gid=${uid}(${u}) groups=${uid}(${u})</span>`, 'info');
}

async runSu(args) {
if (args.includes('-') || args.includes('-l') || args.length === 0) {
this.ui.addOutput('<span class="warning">Password: </span>', 'warning');
await this.sleep(1000);
this.ui.addOutput('<span class="error">su: Authentication failure</span>', 'error');
} else {
this.ui.addOutput('<span class="error">su: user not found</span>', 'error');
}
}

async runSudo(args) {
if (args.includes('-l')) {
this.ui.addOutput('<span class="info">Matching Defaults entries for user on ctf:</span>', 'info');
this.ui.addOutput('<span class="info">    env_reset, mail_badpass, secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin</span>', 'info');
this.ui.addOutput('<span class="success">User user may run the following commands on ctf:</span>', 'success');
this.ui.addOutput('<span class="success">    (root) NOPASSWD: /usr/bin/vim</span>', 'success');
this.ui.addOutput('<span class="success">    (root) NOPASSWD: /usr/bin/find</span>', 'success');
return;
}
if (args.length === 0) { this.ui.addOutput('<span class="error">usage: sudo -h | -K | -k | -V</span>', 'error'); return; }
const cmd = args[0];
if (this.fs.checkSudoers(cmd)) {
this.ui.addOutput(`<span class="success">[sudo] Running ${cmd} as root...</span>`, 'success');
await this.sleep(200);
const result = this.fs.executeBinary(cmd, args.slice(1), { ...this.env, PATH: '/usr/bin:/bin' });
if (result.error) { this.ui.addOutput(`<span class="error">sudo: ${result.error}</span>`, 'error'); return; }
await this.runBinary(result.node, result.fullPath, args.slice(1));
} else {
this.ui.addOutput('<span class="warning">[sudo] Password required (not available in challenge)</span>', 'warning');
}
}

async runVulnBinaryLevel3(args) {
const fakeLs = this.fs.getNode(this.fs.resolvePath('./ls'));
if (fakeLs && fakeLs.type === 'file' && this.fs.canExecute(fakeLs)) {
this.ui.addOutput('<span class="success">[PATH Hijack] Executing malicious ls from current directory!</span>', 'success');
const result = this.fs.readFile('./ls');
if (result.content && result.content.includes('cat /home/user/restricted/flag.txt')) {
this.ui.addOutput(`<span class="flag">${this.ui.escapeHtml('flag{pr1v_3sc4l4t10n_m4st3r_2024}')}</span>`, 'flag');
this.completeLevel(3);
return;
}
}
await this.runVulnBinary(args);
}

async runBackupScript() {
this.ui.addOutput('<span class="system">[cron] Executing /home/user/scripts/backup.sh as root...</span>', 'system');
await this.sleep(500);
const script = this.fs.getNode('/home/user/scripts/backup.sh');
if (script && script.content && script.content.includes('cat /home/user/restricted/flag.txt')) {
this.ui.addOutput('<span class="flag">flag{pr1v_3sc4l4t10n_m4st3r_2024}</span>', 'flag');
this.completeLevel(4);
} else {
this.ui.addOutput('<span class="system">[cron] Backup completed</span>', 'system');
}
}

async runCustomTool(args) {
const caps = this.fs.getCapabilities('/home/user/scripts/custom_tool');
if (caps.includes('cap_dac_read_search+ep')) {
this.ui.addOutput('<span class="success">[custom_tool] Using cap_dac_read_search to bypass permissions...</span>', 'success');
await this.sleep(300);
const flag = this.fs.readFile('/home/user/restricted/flag.txt');
if (!flag.error) {
this.ui.addOutput(`<span class="flag">${this.ui.escapeHtml(flag.content.trim())}</span>`, 'flag');
this.completeLevel(5);
}
} else {
this.ui.addOutput('<span class="error">[custom_tool] Missing required capabilities</span>', 'error');
}
}

extractStrings(data) {
const strings = [];
let current = '';
for (const char of data) {
if (char.charCodeAt(0) >= 32 && char.charCodeAt(0) <= 126) { current += char; }
else { if (current.length >= 4) strings.push(current); current = ''; }
}
if (current.length >= 4) strings.push(current);
return strings.filter(s => !s.match(/^[0-9\s]+$/));
}

matchPattern(name, pattern) {
if (pattern === '*') return true;
const regex = new RegExp('^' + pattern.replace(/\*/g, '.*').replace(/\?/g, '.') + '$');
return regex.test(name);
}

matchPerm(perms, target) {
if (target === '-4000') return perms[3] === 's' || perms[6] === 's';
if (target === '-2000') return perms[6] === 's';
return false;
}

becomeRoot() {
this.fs.isRoot = true;
this.fs.user = 'root';
this.fs.groups = ['root'];
this.env.USER = 'root';
this.env.HOME = '/root';
this.fs.cwd = '/root';
this.ui.updatePrompt();
this.ui.addOutput('<span class="success"># Root shell obtained!</span>', 'success');
this.completeLevel(2);
}

completeLevel(level) {
if (!this.fs.completedLevels.has(level)) {
this.fs.completedLevels.add(level);
this.ui.updateProgress();
this.ui.addOutput(`<span class="success">[LEVEL ${level} COMPLETE]</span>`, 'success');
if (this.fs.completedLevels.size === 5) {
setTimeout(() => this.ui.showWinModal(), 500);
}
}
}

sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

cmdLs(args) { return this.runLs(args); }
cmdCd(args) {
const target = args[0] || this.env.HOME;
const resolved = this.fs.resolvePath(target);
const node = this.fs.getNode(resolved);
if (!node || node.type !== 'dir') { this.ui.addOutput(`<span class="error">cd: ${target}: No such directory</span>`, 'error'); return; }
if (!this.fs.canExecute(node)) { this.ui.addOutput(`<span class="error">cd: ${target}: Permission denied</span>`, 'error'); return; }
this.fs.cwd = resolved;
}
cmdPwd() { this.ui.addOutput(`<span class="info">${this.fs.cwd}</span>`, 'info'); }
cmdCat(args) { return this.runCat(args); }
cmdFind(args) { return this.runFind(args); }
cmdStrings(args) { return this.runStrings(args); }
cmdWhich(args) { return this.runWhich(args); }
cmdGetcap(args) { return this.runGetcap(args); }
cmdSudo(args) { return this.runSudo(args); }
cmdSu(args) { return this.runSu(args); }
cmdId(args) { return this.runId(args); }
cmdExport(args) {
const arg = args.join(' ');
const match = arg.match(/^(\w+)=(.*)$/);
if (match) { this.env[match[1]] = match[2]; this.ui.addOutput(`<span class="info">export ${match[1]}="${match[2]}"</span>`, 'info'); }
else { this.ui.addOutput('<span class="error">Usage: export VAR=value</span>', 'error'); }
}
cmdHelp() { this.ui.showHelp(); }
cmdHint() { this.ui.showHint(); }
cmdHistory() {
for (let i = 0; i < this.fs.history.length; i++) {
this.ui.addOutput(`<span class="system">  ${i + 1}  ${this.ui.escapeHtml(this.fs.history[i])}</span>`, 'system');
}
}
cmdClear() { this.ui.clear(); }
cmdReset() { this.ui.reset(); }
cmdLevels() {
this.ui.addOutput('<span class="info">=== LPE Challenge Levels ===</span>', 'info');
const levels = [
{ n: 1, name: 'SUID Binary Exploitation', desc: 'Exploit vuln_binary in ~/scripts' },
{ n: 2, name: 'Sudo Misconfiguration', desc: 'Abuse NOPASSWD vim/find in sudoers' },
{ n: 3, name: 'PATH Hijacking', desc: 'Hijack PATH to trick SUID binary' },
{ n: 4, name: 'Cron Job Abuse', desc: 'Modify world-writable backup.sh' },
{ n: 5, name: 'Capabilities Abuse', desc: 'Use cap_dac_read_search on custom_tool' }
];
for (const l of levels) {
const done = this.fs.completedLevels.has(l.n) ? ' ✓' : '';
this.ui.addOutput(`<span class="${this.fs.completedLevels.has(l.n) ? 'success' : 'info'}">  ${l.n}. ${l.name}${done} - ${l.desc}</span>`, this.fs.completedLevels.has(l.n) ? 'success' : 'info');
}
}
cmdWhoami() { this.ui.addOutput(`<span class="info">${this.fs.isRoot ? 'root' : 'user'}</span>`, 'info'); }
cmdEcho(args) { this.ui.addOutput(`<span class="info">${args.join(' ')}</span>`, 'info'); }
}

if (typeof module !== 'undefined') module.exports = { VirtualFS, TerminalEngine };