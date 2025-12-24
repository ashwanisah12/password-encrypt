
/*
Token encoding:
- salt: 16 bytes, random
- iv: 12 bytes (AES-GCM)
- ciphertext: AES-GCM output
Token string = base64(salt) + ":" + base64(iv) + ":" + base64(ciphertext)
Derive key: PBKDF2(password, salt, iterations, SHA-256) → AES-GCM-256 key
*/
const ITERATIONS = 150000; // reasonable KDF work factor; increase if slow
const SALT_LEN = 16;
const IV_LEN = 12;

const enc = new TextEncoder();
const dec = new TextDecoder();

function b64encode(buf){ return btoa(String.fromCharCode(...new Uint8Array(buf))); }
function b64decode(s){ const bin = atob(s); const arr = new Uint8Array(bin.length); for(let i=0;i<bin.length;i++) arr[i]=bin.charCodeAt(i); return arr; }

async function deriveKey(passphrase, salt){
  const passKey = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {name:'PBKDF2', salt: salt, iterations: ITERATIONS, hash:'SHA-256'},
    passKey,
    {name:'AES-GCM', length:256},
    false,
    ['encrypt','decrypt']
  );
}

async function encryptSecret(secret, passphrase){
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const key = await deriveKey(passphrase, salt);
  const ciphertext = await crypto.subtle.encrypt({name:'AES-GCM', iv: iv}, key, enc.encode(secret));
  // return token string
  return `${b64encode(salt)}:${b64encode(iv)}:${b64encode(ciphertext)}`;
}

async function decryptToken(token, passphrase){
  try{
    const parts = token.trim().split(':');
    if(parts.length !== 3) throw new Error('Invalid token format');
    const salt = b64decode(parts[0]);
    const iv = b64decode(parts[1]);
    const ciphertext = b64decode(parts[2]);
    const key = await deriveKey(passphrase, salt);
    const plainBuf = await crypto.subtle.decrypt({name:'AES-GCM', iv: iv}, key, ciphertext);
    return dec.decode(plainBuf);
  } catch(e){
    throw e;
  }
}

/* UI wiring */
const secretInput = document.getElementById('secretInput');
const pwdInput = document.getElementById('pwdInput');
const encryptBtn = document.getElementById('encryptBtn');
const tokenOutput = document.getElementById('tokenOutput');
const encryptStatus = document.getElementById('encryptStatus');
const copyTokenBtn = document.getElementById('copyTokenBtn');
const downloadTokenBtn = document.getElementById('downloadTokenBtn');
const saveLocalBtn = document.getElementById('saveLocalBtn');
const clearStoredBtn = document.getElementById('clearStoredBtn');

const tokenInput = document.getElementById('tokenInput');
const pwdInput2 = document.getElementById('pwdInput2');
const decryptBtn = document.getElementById('decryptBtn');
const decryptedOutput = document.getElementById('decryptedOutput');
const decryptStatus = document.getElementById('decryptStatus');
const loadLocalBtn = document.getElementById('loadLocalBtn');
const copyDecryptedBtn = document.getElementById('copyDecryptedBtn');

function showStatus(el, msg, ok=true){
  el.style.display='inline-block'; el.textContent = msg;
  el.className = 'status ' + (ok? 'ok':'err');
  setTimeout(()=>{ el.style.display='none'; }, 4200);
}

/* encrypt */
encryptBtn.addEventListener('click', async () => {
  const secret = secretInput.value.trim();
  const pass = pwdInput.value;
  if(!secret){ alert('Enter secret/text to encrypt'); return; }
  if(!pass){ alert('Enter passphrase to protect token'); return; }
  encryptBtn.disabled = true; encryptBtn.textContent='Encrypting...';
  try {
    const token = await encryptSecret(secret, pass);
    tokenOutput.value = token;
    showStatus(encryptStatus, 'Encryption successful', true);
  } catch(e){
    console.error(e);
    showStatus(encryptStatus, 'Encryption failed', false);
  } finally {
    encryptBtn.disabled = false; encryptBtn.textContent='Encrypt & Generate Token';
  }
});

/* copy token */
copyTokenBtn.addEventListener('click', () => {
  const t = tokenOutput.value.trim();
  if(!t) return showStatus(encryptStatus, 'Nothing to copy', false);
  navigator.clipboard.writeText(t).then(()=> showStatus(encryptStatus,'Token copied',true));
});

/* download token as .token file */
downloadTokenBtn.addEventListener('click', () => {
  const t = tokenOutput.value.trim();
  if(!t) return showStatus(encryptStatus, 'Nothing to download', false);
  const blob = new Blob([t], {type:'text/plain;charset=utf-8'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'token.txt'; document.body.appendChild(a); a.click();
  a.remove(); URL.revokeObjectURL(url);
  showStatus(encryptStatus, 'Downloaded token', true);
});

/* save in localStorage */
saveLocalBtn.addEventListener('click', () => {
  const t = tokenOutput.value.trim();
  if(!t) return showStatus(encryptStatus,'No token to save',false);
  localStorage.setItem('saved_token', t);
  showStatus(encryptStatus,'Token saved locally',true);
});
clearStoredBtn.addEventListener('click', () => {
  localStorage.removeItem('saved_token');
  showStatus(encryptStatus,'Saved token cleared',true);
});

/* load saved token into decrypt area */
loadLocalBtn.addEventListener('click', () => {
  const s = localStorage.getItem('saved_token');
  if(!s) return showStatus(decryptStatus,'No saved token', false);
  tokenInput.value = s;
  showStatus(decryptStatus,'Loaded saved token', true);
});

/* decrypt */
decryptBtn.addEventListener('click', async () => {
  const token = tokenInput.value.trim();
  const pass = pwdInput2.value;
  if(!token){ alert('Paste token to decrypt'); return; }
  if(!pass){ alert('Enter passphrase'); return; }
  decryptBtn.disabled = true; decryptBtn.textContent='Decrypting...';
  try {
    const plain = await decryptToken(token, pass);
    decryptedOutput.value = plain;
    showStatus(decryptStatus, 'Decryption successful', true);
  } catch(e){
    console.error(e);
    showStatus(decryptStatus, 'Decryption failed — wrong passphrase or corrupted token', false);
    decryptedOutput.value = '';
  } finally {
    decryptBtn.disabled = false; decryptBtn.textContent='Decrypt';
  }
});

/* copy decrypted */
copyDecryptedBtn.addEventListener('click', () => {
  const t = decryptedOutput.value.trim();
  if(!t) return showStatus(decryptStatus,'Nothing to copy',false);
  navigator.clipboard.writeText(t).then(()=> showStatus(decryptStatus,'Copied',true));
});

/* load token on start if present */
window.addEventListener('load', () => {
  const s = localStorage.getItem('saved_token');
  if(s) tokenOutput.value = s;
});
