'use strict';
const WebSocket = require('ws');
const http      = require('http');
const fs        = require('fs');
const path      = require('path');
const crypto    = require('crypto');
const webpush    = require('web-push');
const nodemailer = require('nodemailer');

// ── VAPID (Web Push) ────────────────────────────────────────────────────────
let vapidPublicKey  = process.env.VAPID_PUBLIC_KEY;
let vapidPrivateKey = process.env.VAPID_PRIVATE_KEY;
if (!vapidPublicKey || !vapidPrivateKey) {
    const keys = webpush.generateVAPIDKeys();
    vapidPublicKey  = keys.publicKey;
    vapidPrivateKey = keys.privateKey;
    console.warn('⚠️  VAPID keys not in env — generated for this session only.');
    console.warn('VAPID_PUBLIC_KEY=' + vapidPublicKey);
    console.warn('VAPID_PRIVATE_KEY=' + vapidPrivateKey);
}
webpush.setVapidDetails('mailto:admin@messenger.app', vapidPublicKey, vapidPrivateKey);

// ── JSON-хранилище ───────────────────────────────────────────────────────────
const DATA_DIR = process.env.DATA_DIR || __dirname;

function dbPath(name) { return path.join(DATA_DIR, name + '.json'); }

function loadJSON(name, def) {
    try { return JSON.parse(fs.readFileSync(dbPath(name), 'utf8')); }
    catch { return def; }
}

function saveJSON(name, data) {
    fs.writeFileSync(dbPath(name), JSON.stringify(data), 'utf8');
}

// Структуры данных в памяти (персистируются в JSON)
let users    = loadJSON('users', {});    // { nick: { hash, salt } }
let groups   = loadJSON('groups', {});   // { id: { id, name, members, creator, avatar? } }
let queue    = loadJSON('queue', {});    // { nick: [msg, ...] }
let pushSubs = loadJSON('pushSubs', {}); // { nick: [{ endpoint, keys... }, ...] }

// ── SMTP (nodemailer) ────────────────────────────────────────────────────────
const smtpTransport = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
});

// ── Pending registrations (in-memory) ────────────────────────────────────────
const pendingRegistrations = {}; // key = email -> { nick, email, hash, salt, code, expiresAt }
const pendingLogins = {};        // key = nick -> { code, expiresAt }

// ── Helpers ──────────────────────────────────────────────────────────────────
function hashPassword(password, saltHex) {
    return crypto.pbkdf2Sync(password, Buffer.from(saltHex, 'hex'), 100000, 64, 'sha512').toString('hex');
}

function enqueue(nick, msg) {
    if (!queue[nick]) queue[nick] = [];
    queue[nick].push(msg);
    saveJSON('queue', queue);
}

function flushQueue(nick) {
    const msgs = queue[nick] || [];
    if (msgs.length) {
        delete queue[nick];
        saveJSON('queue', queue);
    }
    return msgs;
}

async function sendPush(nick, payload) {
    const subs = pushSubs[nick] || [];
    const alive = [];
    for (const sub of subs) {
        try {
            await webpush.sendNotification(sub, JSON.stringify(payload));
            alive.push(sub);
        } catch (err) {
            if (err.statusCode !== 410 && err.statusCode !== 404) alive.push(sub);
        }
    }
    if (alive.length !== subs.length) {
        pushSubs[nick] = alive;
        saveJSON('pushSubs', pushSubs);
    }
}

function deliverToGroup(groupId, msg, senderNick) {
    const group = groups[groupId];
    if (!group) return;
    for (const member of group.members) {
        if (member === senderNick) continue;
        if (clients[member]) {
            clients[member].send(JSON.stringify(msg));
        } else {
            enqueue(member, msg);
            if (msg.type === 'groupMessage') {
                const preview = msg.text ? msg.text.slice(0, 80) : '📎 Вложение';
                sendPush(member, { title: group.name, body: senderNick + ': ' + preview, tag: groupId });
            }
        }
    }
}

// ── HTTP ─────────────────────────────────────────────────────────────────────
const server = http.createServer((req, res) => {
    if (req.url === '/vapid-public-key') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(vapidPublicKey);
        return;
    }
    if (req.url === '/push-subscribe' && req.method === 'POST') {
        let body = '';
        req.on('data', c => body += c);
        req.on('end', () => {
            try {
                const { nick, subscription } = JSON.parse(body);
                if (!nick || !subscription) { res.writeHead(400); res.end(); return; }
                if (!pushSubs[nick]) pushSubs[nick] = [];
                const idx = pushSubs[nick].findIndex(s => s.endpoint === subscription.endpoint);
                if (idx === -1) pushSubs[nick].push(subscription);
                else pushSubs[nick][idx] = subscription;
                saveJSON('pushSubs', pushSubs);
                res.writeHead(200); res.end('ok');
            } catch (e) { console.error(e); res.writeHead(500); res.end(); }
        });
        return;
    }
    let filePath = path.join(__dirname, req.url === '/' ? 'index.html' : req.url.split('?')[0]);
    if (!filePath.startsWith(__dirname)) { res.writeHead(403); res.end(); return; }
    fs.readFile(filePath, (err, content) => {
        if (err) { res.writeHead(404); res.end('Not found'); return; }
        const ext = path.extname(filePath);
        const mime = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css',
                       '.json': 'application/json', '.png': 'image/png', '.mp3': 'audio/mpeg',
                       '.webp': 'image/webp' };
        res.writeHead(200, { 'Content-Type': mime[ext] || 'application/octet-stream' });
        res.end(content);
    });
});

// ── WebSocket ────────────────────────────────────────────────────────────────
const wss = new WebSocket.Server({ server, maxPayload: 20 * 1024 * 1024 });
let clients  = {};
let lastSeen = {};

function broadcastOnline() {
    const online = {};
    for (const n in clients) online[n] = true;
    const msg = JSON.stringify({ type: 'onlineList', users: online, lastSeen });
    for (const n in clients) clients[n].send(msg);
}

wss.on('connection', ws => {
    ws.authenticated = false;

    ws.on('message', async raw => {
        let data;
        try { data = JSON.parse(raw); } catch { return; }

        // ── register (step 1: send code) ─────────────────────────────────
        if (data.type === 'register') {
            const nick  = (data.nick || '').trim();
            const pwd   = data.password || '';
            const email = (data.email || '').trim().toLowerCase();
            if (!/^[a-zA-Z0-9_]{1,32}$/.test(nick)) {
                ws.send(JSON.stringify({ type: 'authResult', success: false, error: 'Ник: 1–32 символа, только a-z A-Z 0-9 _' })); return;
            }
            if (pwd.length < 6 || pwd.length > 128) {
                ws.send(JSON.stringify({ type: 'authResult', success: false, error: 'Пароль: 6–128 символов' })); return;
            }
            if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
                ws.send(JSON.stringify({ type: 'authResult', success: false, error: 'Некорректный email' })); return;
            }
            if (users[nick]) {
                ws.send(JSON.stringify({ type: 'authResult', success: false, error: 'Ник уже занят' })); return;
            }
            // check email uniqueness
            for (const u in users) {
                if (users[u].email === email) {
                    ws.send(JSON.stringify({ type: 'authResult', success: false, error: 'Email уже используется' })); return;
                }
            }
            const salt = crypto.randomBytes(32).toString('hex');
            const code = String(Math.floor(100000 + Math.random() * 900000));
            pendingRegistrations[email] = { nick, email, hash: hashPassword(pwd, salt), salt, code, expiresAt: Date.now() + 5 * 60 * 1000 };
            try {
                await smtpTransport.sendMail({
                    from: process.env.SMTP_USER,
                    to: email,
                    subject: 'Код подтверждения регистрации',
                    text: 'Ваш код: ' + code
                });
                ws.send(JSON.stringify({ type: 'codeSent', email }));
            } catch (err) {
                console.error('SMTP error:', err);
                delete pendingRegistrations[email];
                ws.send(JSON.stringify({ type: 'authResult', success: false, error: 'Не удалось отправить письмо' }));
            }
            return;
        }

        // ── verifyCode (step 2: confirm code) ────────────────────────────
        if (data.type === 'verifyCode') {
            const email = (data.email || '').trim().toLowerCase();
            const code  = (data.code || '').trim();
            const pending = pendingRegistrations[email];
            if (!pending) {
                ws.send(JSON.stringify({ type: 'authResult', success: false, error: 'Запрос не найден. Зарегистрируйтесь заново' })); return;
            }
            if (Date.now() > pending.expiresAt) {
                delete pendingRegistrations[email];
                ws.send(JSON.stringify({ type: 'authResult', success: false, error: 'Код истёк. Зарегистрируйтесь заново' })); return;
            }
            if (pending.code !== code) {
                ws.send(JSON.stringify({ type: 'authResult', success: false, error: 'Неверный код' })); return;
            }
            // check nick still free
            if (users[pending.nick]) {
                delete pendingRegistrations[email];
                ws.send(JSON.stringify({ type: 'authResult', success: false, error: 'Ник уже занят' })); return;
            }
            users[pending.nick] = { hash: pending.hash, salt: pending.salt, email: pending.email };
            saveJSON('users', users);
            delete pendingRegistrations[email];
            ws.authenticated = true; ws.name = pending.nick; clients[pending.nick] = ws;
            broadcastOnline();
            ws.send(JSON.stringify({ type: 'authResult', success: true, nick: pending.nick }));
            return;
        }

        // ── login (step 1: verify password, send code to email) ──────────
        if (data.type === 'login') {
            const nick = (data.nick || '').trim();
            const pwd  = data.password || '';
            const user = users[nick];
            if (!user || hashPassword(pwd, user.salt) !== user.hash) {
                ws.send(JSON.stringify({ type: 'authResult', success: false, error: !user ? 'Неизвестный ник' : 'Неверный пароль' })); return;
            }
            if (!user.email) {
                // legacy user without email — let them in directly
                if (clients[nick] && clients[nick] !== ws) {
                    try { clients[nick].send(JSON.stringify({ type: 'kicked' })); clients[nick].close(); } catch {}
                }
                ws.authenticated = true; ws.name = nick; clients[nick] = ws;
                broadcastOnline();
                ws.send(JSON.stringify({ type: 'authResult', success: true, nick }));
                const pending = flushQueue(nick);
                for (const m of pending) ws.send(JSON.stringify(m));
                const myGroups = {};
                for (const id in groups) {
                    if (groups[id].members.includes(nick)) myGroups[id] = groups[id];
                }
                if (Object.keys(myGroups).length)
                    ws.send(JSON.stringify({ type: 'groupList', groups: myGroups }));
                return;
            }
            // send verification code to email
            const code = String(Math.floor(100000 + Math.random() * 900000));
            pendingLogins[nick] = { code, expiresAt: Date.now() + 5 * 60 * 1000 };
            try {
                await smtpTransport.sendMail({
                    from: process.env.SMTP_USER,
                    to: user.email,
                    subject: 'Код для входа',
                    text: 'Ваш код: ' + code
                });
                ws.send(JSON.stringify({ type: 'codeSent', email: user.email, loginNick: nick }));
            } catch (err) {
                console.error('SMTP error:', err);
                delete pendingLogins[nick];
                ws.send(JSON.stringify({ type: 'authResult', success: false, error: 'Не удалось отправить письмо' }));
            }
            return;
        }

        // ── verifyLoginCode (step 2: confirm login code) ─────────────────
        if (data.type === 'verifyLoginCode') {
            const nick = (data.nick || '').trim();
            const code = (data.code || '').trim();
            const pl = pendingLogins[nick];
            if (!pl) {
                ws.send(JSON.stringify({ type: 'authResult', success: false, error: 'Запрос не найден. Войдите заново' })); return;
            }
            if (Date.now() > pl.expiresAt) {
                delete pendingLogins[nick];
                ws.send(JSON.stringify({ type: 'authResult', success: false, error: 'Код истёк. Войдите заново' })); return;
            }
            if (pl.code !== code) {
                ws.send(JSON.stringify({ type: 'authResult', success: false, error: 'Неверный код' })); return;
            }
            delete pendingLogins[nick];
            if (clients[nick] && clients[nick] !== ws) {
                try { clients[nick].send(JSON.stringify({ type: 'kicked' })); clients[nick].close(); } catch {}
            }
            ws.authenticated = true; ws.name = nick; clients[nick] = ws;
            broadcastOnline();
            ws.send(JSON.stringify({ type: 'authResult', success: true, nick }));
            const pending = flushQueue(nick);
            for (const m of pending) ws.send(JSON.stringify(m));
            const myGroups = {};
            for (const id in groups) {
                if (groups[id].members.includes(nick)) myGroups[id] = groups[id];
            }
            if (Object.keys(myGroups).length)
                ws.send(JSON.stringify({ type: 'groupList', groups: myGroups }));
            return;
        }

        if (!ws.authenticated) return;

        // ── checkNick ──────────────────────────────────────────────────────
        if (data.type === 'checkNick') {
            ws.send(JSON.stringify({ type: 'nickResult', nick: data.nick, exists: !!users[(data.nick || '').trim()] }));
            return;
        }

        // ── message ────────────────────────────────────────────────────────
        if (data.type === 'message') {
            if (!users[data.to]) { ws.send(JSON.stringify({ type: 'deliveryError', to: data.to, error: 'no_user' })); return; }
            if (clients[data.to]) {
                clients[data.to].send(JSON.stringify(data));
            } else {
                enqueue(data.to, data);
                const preview = data.text ? data.text.slice(0, 80) : '📎 Вложение';
                sendPush(data.to, { title: ws.name, body: preview, tag: ws.name });
            }
            return;
        }

        // ── edit / delete / read / reaction ────────────────────────────────
        if (data.type === 'edit' || data.type === 'delete') {
            if (clients[data.to]) clients[data.to].send(JSON.stringify(data));
            else enqueue(data.to, data);
            return;
        }
        if (data.type === 'read' || data.type === 'reaction') {
            if (clients[data.to]) clients[data.to].send(JSON.stringify(data));
            return;
        }

        // ── signal / typing ────────────────────────────────────────────────
        if (data.type === 'signal' || data.type === 'typing') {
            if (clients[data.to]) clients[data.to].send(JSON.stringify(data));
            return;
        }

        // ── createGroup ────────────────────────────────────────────────────
        if (data.type === 'createGroup') {
            const name = (data.name || '').trim();
            if (!name || name.length > 64) return;
            const members = [...new Set(Array.isArray(data.members) ? data.members : [])];
            if (!members.includes(ws.name)) members.push(ws.name);
            if (members.length < 2) return;
            for (const m of members) { if (!users[m]) return; }
            const id = 'g_' + Date.now().toString(36) + '_' + crypto.randomBytes(4).toString('hex');
            const avatar = typeof data.avatar === 'string' && data.avatar.startsWith('data:image/') ? data.avatar : undefined;
            const group = { id, name, members, creator: ws.name, avatar };
            groups[id] = group;
            saveJSON('groups', groups);
            const notif = { type: 'groupCreated', group };
            for (const m of members) {
                if (clients[m]) clients[m].send(JSON.stringify(notif));
                else enqueue(m, notif);
            }
            return;
        }

        // ── addGroupMember ─────────────────────────────────────────────────

        // ── setGroupAvatar ────────────────────────────────────────────────
        if (data.type === 'setGroupAvatar') {
            const group = groups[data.groupId];
            if (!group || !group.members.includes(ws.name)) return;
            const avatar = (typeof data.avatar === 'string' && data.avatar.startsWith('data:image/')) ? data.avatar : null;
            if (avatar && avatar.length > 2_000_000) return;
            if (avatar) group.avatar = avatar;
            else delete group.avatar;
            saveJSON('groups', groups);
            const notif = { type: 'groupUpdated', groupId: data.groupId, group };
            for (const m of group.members) {
                if (clients[m]) clients[m].send(JSON.stringify(notif));
                else enqueue(m, notif);
            }
            return;
        }

        if (data.type === 'addGroupMember') {
            const nick = (data.nick || '').trim();
            if (!nick || !users[nick]) { ws.send(JSON.stringify({ type: 'addMemberError', groupId: data.groupId, error: 'no_user' })); return; }
            const group = groups[data.groupId];
            if (!group || !group.members.includes(ws.name)) return;
            if (group.members.includes(nick)) {
                ws.send(JSON.stringify({ type: 'addMemberError', groupId: data.groupId, error: 'already_member' })); return;
            }
            group.members.push(nick);
            saveJSON('groups', groups);
            const notif = { type: 'groupMemberAdded', groupId: data.groupId, nick, group };
            for (const m of group.members) {
                if (clients[m]) clients[m].send(JSON.stringify(notif));
                else enqueue(m, notif);
            }
            return;
        }

        // ── groupMessage / groupEdit / groupDelete / groupTyping / groupRead / groupReaction
        if (['groupMessage','groupEdit','groupDelete','groupTyping','groupRead','groupReaction'].includes(data.type)) {
            const group = groups[data.groupId];
            if (!group || !group.members.includes(ws.name)) return;
            deliverToGroup(data.groupId, data, ws.name);
            return;
        }

        // ── groupSignal (WebRTC сигналинг для групповых звонков) ──────────
        if (data.type === 'groupSignal') {
            const group = groups[data.groupId];
            if (!group || !group.members.includes(ws.name)) return;
            // пересылаем только конкретному получателю
            if (data.to && clients[data.to]) {
                clients[data.to].send(JSON.stringify(data));
            }
            return;
        }
    });

    ws.on('close', () => {
        if (ws.name && clients[ws.name] === ws) {
            lastSeen[ws.name] = Date.now();
            delete clients[ws.name];
            broadcastOnline();
        }
    });
});

// ── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log('Server on port ' + PORT));
