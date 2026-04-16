const crypto = require('crypto');

// 1. PRIVATE KEY (Otomatis terisi)
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

// 2. URL GOOGLE APPS SCRIPT (Otomatis terisi)
const GAS_URL = "https://script.google.com/macros/s/AKfycbw6mm9T6R9wc_cfu7AJoQF-Jhi_2Z6_2FkCxVBnsUnGcBBhIbpD-tjMSupVCSIhF7uk/exec";

module.exports = async function (req, res) {
  if (req.method !== 'POST') return res.status(405).send('Method Not Allowed');

  try {
    let bodyData = req.body;
    if (typeof bodyData === 'string') bodyData = JSON.parse(bodyData);
    
    const { encrypted_aes_key, encrypted_flow_data, initial_vector } = bodyData;

    // --- DEKRIPSI KUNCI META ---
    const decryptedAesKey = crypto.privateDecrypt(
      { key: PRIVATE_KEY, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
      Buffer.from(encrypted_aes_key, 'base64')
    );

    const aesAlgorithm = decryptedAesKey.length === 32 ? 'aes-256-gcm' : 'aes-128-gcm';
    const flowDataBuffer = Buffer.from(encrypted_flow_data, 'base64');
    const initialVectorBuffer = Buffer.from(initial_vector, 'base64');
    const authTag = flowDataBuffer.subarray(-16);
    const ciphertext = flowDataBuffer.subarray(0, -16);

    const decipher = crypto.createDecipheriv(aesAlgorithm, decryptedAesKey, initialVectorBuffer);
    decipher.setAuthTag(authTag);
    let decryptedData = decipher.update(ciphertext, undefined, 'utf8');
    decryptedData += decipher.final('utf8');
    const requestData = JSON.parse(decryptedData);

    let responsePayload = {};
    const flowVersion = requestData.version || "3.0";

    // --- LOGIKA APLIKASI WAYAN ---
    if (requestData.action === 'ping') {
      responsePayload = { data: { status: 'active' } };
    } 
    // TAHAP 1: FORM DIBUKA (Minta Unit Kerja)
    else if (requestData.action === 'INIT') {
      const fetchResponse = await fetch(GAS_URL);
      const semuaData = await fetchResponse.json();
      const petaUnit = new Map();

      semuaData.forEach(item => {
        if (!item.unit_kerja) return;
        let titlePendek = item.unit_kerja;
        const bagianTeks = item.unit_kerja.split('-');
        if (bagianTeks.length >= 2) titlePendek = bagianTeks[1].trim(); 
        if (titlePendek.length > 80) titlePendek = titlePendek.substring(0, 77) + "...";

        if (!petaUnit.has(titlePendek)) {
          petaUnit.set(titlePendek, { id: String(titlePendek), title: String(titlePendek) });
        }
      });

      responsePayload = { 
        version: flowVersion, 
        screen: 'SCREEN_PILIH_UNIT', 
        data: { daftar_unit: Array.from(petaUnit.values()) } 
      };
    } 
    // TAHAP 2 & 3: FILTER DATA ATAU SIMPAN DATA
    else if (requestData.action === 'data_exchange') {
      const isianForm = requestData.data || {};
      
      // Tahap 2: Pengguna Baru Saja Memilih Unit Kerja -> Kirim Daftar Nama
      if (isianForm.tahap === 'filter_pegawai') {
        const fetchResponse = await fetch(GAS_URL);
        const semuaData = await fetchResponse.json();
        const unitPilihan = isianForm.unit_dipilih; 

        const pegawaiTersaring = semuaData
          .filter(item => {
            if (!item.unit_kerja) return false;
            let titlePendekPegawai = item.unit_kerja;
            const bagianTeks = item.unit_kerja.split('-');
            if (bagianTeks.length >= 2) titlePendekPegawai = bagianTeks[1].trim();
            if (titlePendekPegawai.length > 80) titlePendekPegawai = titlePendekPegawai.substring(0, 77) + "...";
            return titlePendekPegawai === unitPilihan;
          })
          .map(item => ({
            // MENGIRIM NIP DAN NAMA KE BELAKANG LAYAR
            id: `${item.id || item.title}|${item.title || "Tanpa Nama"}`, 
            // MENAMPILKAN NAMA SAJA DI LAYAR HP
            title: String(item.title || "Tanpa Nama")
          }));

        responsePayload = { 
          version: flowVersion, 
          screen: 'SCREEN_AKTIVITAS', 
          data: { daftar_pegawai: pegawaiTersaring } 
        };
      }
      // Tahap 3: Pengguna Menekan Tombol "Kirim Laporan" -> Tulis ke Sheets
      else if (isianForm.tahap === 'simpan_laporan') {
        // Meneruskan data ke Google Sheets
        await fetch(GAS_URL, {
          method: 'POST',
          body: JSON.stringify(isianForm),
          headers: { 'Content-Type': 'application/json' },
          redirect: 'follow' // Mengamankan jika Google meminta pengalihan (redirect 302)
        });

        // Menampilkan Layar Sukses Bawaan WhatsApp
        responsePayload = {
          version: flowVersion,
          screen: 'SUCCESS',
          data: {
            extension_message_response: {
              params: {
                flow_token: requestData.flow_token,
                status: "Berhasil",
                detail: "Laporan aktivitas Anda berhasil disimpan ke sistem."
              }
            }
          }
        };
      }
    }

    // --- ENKRIPSI BALASAN KE META ---
    const flippedIvBuffer = Buffer.alloc(initialVectorBuffer.length);
    for (let i = 0; i < initialVectorBuffer.length; i++) {
      flippedIvBuffer[i] = ~initialVectorBuffer[i] & 0xFF;
    }

    const cipher = crypto.createCipheriv(aesAlgorithm, decryptedAesKey, flippedIvBuffer);
    let encryptedResponse = cipher.update(JSON.stringify(responsePayload), 'utf-8');
    encryptedResponse = Buffer.concat([encryptedResponse, cipher.final()]);
    const responseAuthTag = cipher.getAuthTag();
    const finalCiphertext = Buffer.concat([encryptedResponse, responseAuthTag]).toString('base64');

    res.setHeader('Content-Type', 'text/plain');
    return res.status(200).send(finalCiphertext);

  } catch (error) {
    console.error("💥 CRASH REPORT:", error.message);
    return res.status(500).send('Internal Server Error');
  }
};
