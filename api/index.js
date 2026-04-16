const crypto = require('crypto');

// 1. MASUKKAN PRIVATE KEY ANDA
// Pastikan tidak ada tulisan -----BEGIN... yang ganda/dobel
const RAW_PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Bo7QbU0fR73VFfUZSjKaATHy6rvmV3jvvuhWnvRDnL2iWMF
sfitdSENXJP/1uJvjce2Q+RzUVFfDnpO0DjRl0mTRCQHji4hyJP6NmdiXH8xQAQJ
Wg3136y35UNuXW2WMNko6ajC/Nud74W1GepdMvCHQPOzk6kV21OyWyd7FWsjfys9
xDj/KDS7BB+k0nq4WrclmGXD0/jtwunTkA2QkNoBRrecOAShSmuliOWbxJJtzZV9
cUsYiPOjTYFNWg02B9ztrT9Z7eb0gpuaOFIJCuVfvQ9LwX5EozJSR15n+eyaUTIF
PC3NYpoh0N9n1Tx/SZuXGxerAiMprsaDByw1QwIDAQABAoIBAAnEcWuQGbqVrX4j
8TAeTgG717TTfRNxuLLKFLSugw1uj+u63hWQWnPY7UufFq77SckZypA9NLxoWVHQ
o8paIFw9c9AK8N/XgnZrm57aE1/MCH+8sMOtTBEHhkoYdCGmdxor1yPAbAZ6OFt5
pxpkSaOOboq55X/Uu9Xjg8eLftdubjoS1JLghabqorA6+gsCU2fVaBYXSJemtEgd
ELVzYxrk6AAoCTrMDfgvbz5RjrVhqTTk59iJGiJbAuCC+Ff/pDhbgnPynvvuoJEB
YDLW4fEmH7G8yxRdcTByZybV+U/mwodM/ZP6yyNU7dHYZ0rb3objhUjFGkReJm7Y
17wZzYECgYEA7uwhb5erOF7S+B/kS51lCONpBFB56E79KLNf2vOF7j9yT32n7Z1E
IO/uSRaEuGoqvRYeP8XDeSxpxmt+sFM6x/lUk+SItkynFS9XQKp1/XPq7oj8PFaf
/fRD/sCAfB1HbvZujap8KkRlfp5jAAo6eajzAl+FINiu6nM/zbo4wLMCgYEA3vom
NuU418+u3ElLeKrmi6qBEgJlzvU6sYSbi+Bu9AWAwQKmXs4+m0xkG7fjTKNHhDpz
2a4dNIu3CN2HXob9WxThVYBigSDy7lYZ+KmRE+jdvh1ljSg+sA4snKllEP2Yplsi
76pMLRg1NRv/I/FcdJYrEDbhLyhrsQBUjvBG4TECgYEA5Gl+ta6sFCIjUu86VEfO
1aaDOYquYTdSs1x5IVt7CQBDCle4+WNGRK7cgaczjxKAdXD1zkYE0I1zOix+W5fW
NGPbReBQCuhRO+GcasgMMRhm21C+w/iU0DZ74sqqiv1600xo+KqqNcZZuak2QE2H
BdRNLlGfdn1xC9bOgqGrrB0CgYA3xGqgWi4gU7IRKEe2809b6RYE8hKSc2TtlxPs
JQK7B1FPdKE1nvGrl6yF/jTcKw4s9Q2aiOCHDtaFYhqEOtDM4ekFoGmCkEIR9/jg
51AAocIr1WBbsJAVKkZgHEHJwRNXr/2J4ZbRxHcyREFItQoBork8ge1KBRsCFuoP
IesoUQKBgQC1HdH8IiQofcoldP9iNZ148BcPLWZ0urkDDPSF8Z6ZfsFLFu5subTR
84wrT1l/lMjgzWhmfgY+QPnTJRzrUQkdYB9aSaHpNpZA3o7DC4ucVcnMdFmj1E+n
/saLDDwIyMLrBmZ0uv+IDMvUiGQuPpmPhqAAzpbRHMKd/5SpPgAlwQ==
-----END RSA PRIVATE KEY-----`;

const PRIVATE_KEY = RAW_PRIVATE_KEY.trim();

// 2. MASUKKAN URL WEB APP GOOGLE APPS SCRIPT ANDA
const GAS_URL = "https://script.google.com/macros/s/AKfycbw6mm9T6R9wc_cfu7AJoQF-Jhi_2Z6_2FkCxVBnsUnGcBBhIbpD-tjMSupVCSIhF7uk/exec";

module.exports = async function (req, res) {
  // Hanya menerima metode POST dari Meta
  if (req.method !== 'POST') {
    return res.status(405).send('Method Not Allowed');
  }

  try {
    // Memaksa Vercel untuk selalu membaca dalam format Object (JSON)
    let bodyData = req.body;
    if (typeof bodyData === 'string') {
      bodyData = JSON.parse(bodyData);
    }

    const { encrypted_aes_key, encrypted_flow_data, initial_vector } = bodyData;

    // --- DEKRIPSI KUNCI AES ---
    const decryptedAesKey = crypto.privateDecrypt(
      {
        key: PRIVATE_KEY,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      Buffer.from(encrypted_aes_key, 'base64')
    );

    // X-RAY LOG: Melacak ukuran byte dari Meta
    console.log("X-RAY -> Panjang Kunci AES dari Meta:", decryptedAesKey.length, "bytes");

    if (decryptedAesKey.length !== 32) {
      console.error("GAGAL: Meta tidak mengirimkan kunci 32 byte!");
      return res.status(500).send('Invalid Key Length');
    }

    // --- DEKRIPSI PESAN META ---
    const flowDataBuffer = Buffer.from(encrypted_flow_data, 'base64');
    const initialVectorBuffer = Buffer.from(initial_vector, 'base64');

    const authTag = flowDataBuffer.subarray(-16);
    const ciphertext = flowDataBuffer.subarray(0, -16);

    const decipher = crypto.createDecipheriv('aes-256-gcm', decryptedAesKey, initialVectorBuffer);
    decipher.setAuthTag(authTag);

    let decryptedData = decipher.update(ciphertext, undefined, 'utf8');
    decryptedData += decipher.final('utf8');
    
    // X-RAY LOG: Melihat apa isi pesan Meta
    console.log("X-RAY -> Isi Pesan:", decryptedData);
    
    const requestData = JSON.parse(decryptedData);

    // --- LOGIKA ENDPOINT WAYAN ---
    let responsePayload = {};

    if (requestData.action === 'ping') {
      responsePayload = { data: { status: 'active' } };
    } else if (requestData.action === 'data_exchange') {
      const fetchResponse = await fetch(GAS_URL);
      const daftarPegawai = await fetchResponse.json();

      responsePayload = {
        screen: 'SCREEN_AKTIVITAS',
        data: {
          daftar_pegawai: Array.isArray(daftarPegawai) ? daftarPegawai : []
        }
      };
    }

    // --- ENKRIPSI BALASAN KE META ---
    const flippedIv = Buffer.alloc(12);
    for (let i = 0; i < initialVectorBuffer.length; i++) {
      flippedIv[i] = ~initialVectorBuffer[i];
    }

    const cipher = crypto.createCipheriv('aes-256-gcm', decryptedAesKey, flippedIv);
    let encryptedResponse = cipher.update(JSON.stringify(responsePayload));
    encryptedResponse = Buffer.concat([encryptedResponse, cipher.final()]);
    const responseAuthTag = cipher.getAuthTag();

    const finalCiphertext = Buffer.concat([encryptedResponse, responseAuthTag]).toString('base64');

    res.setHeader('Content-Type', 'text/plain');
    return res.status(200).send(finalCiphertext);

  } catch (error) {
    // X-RAY LOG: Menangkap Error dengan sangat rinci
    console.error("X-RAY ERROR ->", error.message);
    return res.status(500).send('Internal Server Error');
  }
};
