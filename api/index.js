const crypto = require('crypto');

// 1. MASUKKAN PRIVATE KEY ANDA
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
  if (req.method !== 'POST') {
    return res.status(405).send('Method Not Allowed');
  }

  try {
    let bodyData = req.body;
    if (typeof bodyData === 'string') {
      bodyData = JSON.parse(bodyData);
    }

    const { encrypted_aes_key, encrypted_flow_data, initial_vector } = bodyData;

    // --- BUKA KUNCI DARI META ---
    const decryptedAesKey = crypto.privateDecrypt(
      {
        key: PRIVATE_KEY,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      Buffer.from(encrypted_aes_key, 'base64')
    );

    // --- DETEKSI OTOMATIS ALGORITMA META ---
    // Membuat server kebal terhadap perubahan aturan Meta
    const aesAlgorithm = decryptedAesKey.length === 32 ? 'aes-256-gcm' : 'aes-128-gcm';

    // --- BACA PESAN META ---
    const flowDataBuffer = Buffer.from(encrypted_flow_data, 'base64');
    const initialVectorBuffer = Buffer.from(initial_vector, 'base64');

    const authTag = flowDataBuffer.subarray(-16);
    const ciphertext = flowDataBuffer.subarray(0, -16);

    const decipher = crypto.createDecipheriv(aesAlgorithm, decryptedAesKey, initialVectorBuffer);
    decipher.setAuthTag(authTag);

    let decryptedData = decipher.update(ciphertext, undefined, 'utf8');
    decryptedData += decipher.final('utf8');
    const requestData = JSON.parse(decryptedData);

    // --- LOGIKA ENDPOINT WAYAN ---
    // --- LOGIKA ENDPOINT WAYAN ---
    let responsePayload = {};
    const flowVersion = requestData.version || "3.0";

    if (requestData.action === 'ping') {
      responsePayload = { data: { status: 'active' } };
    } 
    // LAYAR 1: Saat Form Pertama Kali Dibuka (INIT)
    else if (requestData.action === 'INIT') {
      const fetchResponse = await fetch(GAS_URL);
      const semuaData = await fetchResponse.json();

      // Mengambil daftar Unit Kerja yang unik (tidak dobel)
      const unitUnik = [...new Set(semuaData.map(item => item.unit_kerja))].filter(Boolean);
      
      const daftarUnitArray = unitUnik.map(unit => {
        let titlePendek = unit;
        
        // Memecah teks berdasarkan tanda hubung '-'
        const bagianTeks = unit.split('-');
        
        // Jika ada lebih dari 1 bagian (ada minimal 1 tanda hubung)
        if (bagianTeks.length >= 2) {
          // Ambil bagian indeks ke-1 (teks setelah '-' pertama) dan bersihkan spasinya
          titlePendek = bagianTeks[1].trim(); 
        }

        // Fitur Pengaman Tambahan: Jika entah kenapa teksnya masih > 80 karakter,
        // kita potong paksa dan tambahkan titik-titik agar Meta tidak error.
        if (titlePendek.length > 80) {
          titlePendek = titlePendek.substring(0, 77) + "...";
        }

        return {
          id: unit,          // ID wajib pakai nama asli utuh untuk modal filter di Layar 2
          title: titlePendek // Title pakai versi rapi yang sudah dipotong
        };
      });

      responsePayload = {
        version: flowVersion,
        screen: 'SCREEN_PILIH_UNIT',
        data: {
          daftar_unit: daftarUnitArray
        }
      };
    } 
    // LAYAR 2: Saat Tombol Lanjut Ditekan
    else if (requestData.action === 'data_exchange') {
      // Menangkap data dari tombol Layar 1
      const isianForm = requestData.data || {};
      
      if (isianForm.tahap === 'filter_pegawai') {
        const fetchResponse = await fetch(GAS_URL);
        const semuaData = await fetchResponse.json();

        // Saring pegawai khusus untuk unit yang dipilih saja
        const unitPilihan = isianForm.unit_dipilih;
        const pegawaiTersaring = semuaData.filter(item => item.unit_kerja === unitPilihan);

        responsePayload = {
          version: flowVersion,
          screen: 'SCREEN_AKTIVITAS',
          data: {
            daftar_pegawai: pegawaiTersaring
          }
        };
      }
    }

    // --- BUNGKUS BALASAN KE META ---
    // BUG FIX: Menggunakan panjang persis dari Meta, tidak mengunci di angka 12
    const flippedIvBuffer = Buffer.alloc(initialVectorBuffer.length);
    for (let i = 0; i < initialVectorBuffer.length; i++) {
      flippedIvBuffer[i] = ~initialVectorBuffer[i] & 0xFF;
    }

    const cipher = crypto.createCipheriv(aesAlgorithm, decryptedAesKey, flippedIvBuffer);
    
    // Pastikan format teks UTF-8 sangat bersih
    let encryptedResponse = cipher.update(JSON.stringify(responsePayload), 'utf-8');
    encryptedResponse = Buffer.concat([encryptedResponse, cipher.final()]);
    const responseAuthTag = cipher.getAuthTag();

    const finalCiphertext = Buffer.concat([encryptedResponse, responseAuthTag]).toString('base64');

    res.setHeader('Content-Type', 'text/plain');
    return res.status(200).send(finalCiphertext);

  } catch (error) {
    console.error("Error Detail:", error.message);
    return res.status(500).send('Internal Server Error');
  }
};
