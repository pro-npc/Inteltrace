// Client-side AES-GCM encryption for securing case data at rest in Firestore.
// Cloudflare Workers natively support the Web Crypto API.

function base64ToBytes(base64: string): Uint8Array {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binaryString = '';
  for (let i = 0; i < bytes.length; i++) {
    binaryString += String.fromCharCode(bytes[i]);
  }
  return btoa(binaryString);
}

// Derive an AES-GCM key from the ENCRYPTION_KEY environment variable
async function getEncryptionKey(secret: string): Promise<CryptoKey> {
  const enc = new TextEncoder();
  // Hash the secret to ensure it's exactly 256 bits (32 bytes)
  const keyMaterial = await crypto.subtle.digest('SHA-256', enc.encode(secret));
  
  return await crypto.subtle.importKey(
    'raw',
    keyMaterial,
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypts a JSON-serializable object into a base64 string using AES-GCM.
 * The IV is randomly generated and prepended to the ciphertext.
 */
export async function encryptPayload(data: unknown, secret: string): Promise<string> {
  if (!secret) throw new Error('Encryption secret is missing');
  
  const key = await getEncryptionKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  
  const enc = new TextEncoder();
  const encoded = enc.encode(JSON.stringify(data));
  
  const ciphertextBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoded
  );
  
  // Pack IV and Ciphertext together: [IV (12 bytes)] + [Ciphertext]
  const ciphertextBytes = new Uint8Array(ciphertextBuffer);
  const combined = new Uint8Array(iv.length + ciphertextBytes.length);
  combined.set(iv, 0);
  combined.set(ciphertextBytes, iv.length);
  
  return bytesToBase64(combined);
}

/**
 * Decrypts a base64 string back into a JSON object using AES-GCM.
 */
export async function decryptPayload(encryptedBase64: string, secret: string): Promise<unknown> {
  if (!secret) throw new Error('Encryption secret is missing');
  
  const key = await getEncryptionKey(secret);
  const combined = base64ToBytes(encryptedBase64);
  
  // Extract IV and Ciphertext
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);
  
  const decryptedBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  );
  
  const dec = new TextDecoder();
  const decryptedString = dec.decode(decryptedBuffer);
  
  return JSON.parse(decryptedString);
}
