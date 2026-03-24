# Crypt
Crypt is a 100% client-side, zero-dependency library for securely encrypting and decrypting PDF documents and user signatures directly in the browser using the native WebCrypto API. It features automatic memory sanitization to ensure sensitive buffers are wiped out of scope.

## Installation
You can install the library using your preferred package manager:
```
bun add @unityaisolutions/crypt
# or
npm install @unityaisolutions/crypt
# or
yarn add @unityaisolutions/crypt
```
If you are not using a bundler, you can include the minified script directly in your HTML:
```html
<script src="path/to/dist/index.min.js"></script>
```

## Example 1: Vanilla JavaScript (Encryption)
Here is a basic implementation using standard HTML inputs and Vanilla JS. It demonstrates capturing the inputs, triggering the encryption, and downloading the resulting ```.crypt``` file.
```javascript
<!-- index.html -->
<input type="file" id="pdfInput" accept="application/pdf" />
<input type="password" id="passkeyInput" placeholder="Enter secure passkey" />
<input type="text" id="signatureInput" placeholder="Type your signature" />
<button id="encryptBtn">Encrypt Document</button>

<script type="module">
  import { DocumentEncryptor } from '@unityaisolutions/crypt';

  document.getElementById('encryptBtn').addEventListener('click', async () => {
    const fileInput = document.getElementById('pdfInput');
    const passkey = document.getElementById('passkeyInput').value;
    const signature = document.getElementById('signatureInput').value;

    if (!fileInput.files.length) return alert("Please select a PDF.");

    try {
      const file = fileInput.files[0];
      
      // 1. Process and encrypt the document
      const result = await DocumentEncryptor.encryptPDF(file, passkey, signature);

      // 2. Trigger the download automatically
      const a = document.createElement('a');
      a.href = result.objectUrl;
      a.download = result.filename; // e.g., "document.crypt"
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);

      // 3. SECURE CLEANUP: Revoke the Object URL and wipe temp state
      result.cleanup();
      
      alert("Encryption successful and downloaded!");
    } catch (error) {
      console.error("Encryption failed:", error);
      alert(error.message);
    }
  });
</script>
```

## Example 2: React Integration (Recommended)
This example shows how to take an already encrypted ```.crypt``` file, supply the original passkey, and recover the PDF and signature securely.
```javascript
import React, { useState, useEffect } from 'react';
import { DocumentEncryptor, DecryptionResult } from '@unityaisolutions/crypt';

export default function SecureDocumentDecoder() {
  const [file, setFile] = useState<File | null>(null);
  const [passkey, setPasskey] = useState('');
  const [decryptedData, setDecryptedData] = useState<DecryptionResult | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);

  // CRUCIAL: Cleanup memory when component unmounts or new data is generated
  useEffect(() => {
    return () => {
      if (decryptedData) {
        decryptedData.cleanup();
      }
    };
  }, [decryptedData]);

  const handleDecrypt = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file || !passkey) return;

    setIsProcessing(true);
    try {
      if (decryptedData) decryptedData.cleanup();

      const result = await DocumentEncryptor.decryptPDF(file, passkey);
      setDecryptedData(result);
      setPasskey(''); // Clear passkey from state immediately for security
    } catch (error: any) {
      alert(`Decryption failed: ${error.message}`);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleDownloadAndCleanup = () => {
    if (!decryptedData) return;
    
    const a = document.createElement('a');
    a.href = decryptedData.pdfUrl;
    a.download = decryptedData.filename;
    a.click();

    decryptedData.cleanup();
    setDecryptedData(null); 
    setFile(null);
  };

  return (
    <div className="p-6 max-w-md mx-auto bg-white rounded-xl shadow-md space-y-4">
      <h2 className="text-xl font-bold">Secure Document Decryption</h2>
      
      <form onSubmit={handleDecrypt} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700">Select .crypt File</label>
          <input 
            type="file" 
            accept=".crypt" 
            onChange={(e) => setFile(e.target.files?.[0] || null)}
            className="mt-1 block w-full"
            required
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700">Passkey</label>
          <input 
            type="password" 
            value={passkey}
            onChange={(e) => setPasskey(e.target.value)}
            className="mt-1 block w-full border border-gray-300 rounded-md p-2"
            required
          />
        </div>

        <button 
          type="submit" 
          disabled={isProcessing}
          className="w-full bg-purple-600 text-white p-2 rounded-md hover:bg-purple-700 disabled:opacity-50"
        >
          {isProcessing ? 'Decrypting...' : 'Decrypt Document'}
        </button>
      </form>

      {decryptedData && (
        <div className="mt-4 p-4 bg-green-50 border border-green-200 rounded-md space-y-3">
          <p className="text-green-800 text-sm font-medium">Decryption successful!</p>
          
          <div className="bg-white p-2 rounded border border-green-100">
            <p className="text-xs text-gray-500">Recovered Signature:</p>
            <p className="font-mono text-sm">{decryptedData.signature}</p>
          </div>

          <button 
            onClick={handleDownloadAndCleanup}
            className="w-full bg-green-600 text-white p-2 rounded-md hover:bg-green-700"
          >
            Download {decryptedData.filename}
          </button>
        </div>
      )}
    </div>
  );
}
```

## API Reference
```DocumentEncryptor.encryptPDF(file, passkey, signature)```
Encrypts a PDF file and a signature string using AES-GCM 256-bit encryption derived from the provided passkey.

**Parameters:**
- ```file``` (*File*): The standard HTML File object. **Must** have a MIME type of ```application/pdf```.
- ```passkey``` (*string*): A user-generated string used to derive the cryptographic key via PBKDF2.
- ```signature``` (*string*): A text string or a Base64-encoded image (e.g., from an HTML Canvas) representing the user's signature.
Returns:
A ```Promise``` that resolves to an ```EncryptionResult``` object:
```
interface EncryptionResult {
  /** The temporary URL pointing to the Blob in browser memory. Use this for standard <a> tag downloads. */
  objectUrl: string;
  
  /** The raw Blob containing the JSON payload. Useful if you want to POST this via fetch() to a server instead of downloading. */
  blob: Blob;
  
  /** The suggested filename, formatted as "OriginalName.crypt" */
  filename: string;
  
  /** * CRUCIAL METHOD. You MUST call this function when the file is done downloading 
   * or uploading. It severs the Object URL and wipes temporary session memory. 
   */
  cleanup: () => void;
}
```
```DocumentEncryptor.decryptPDF(file, passkey)```
Decrypts a ```.crypt``` file back into its original PDF and extracts the embedded signature string.

**Parameters:**
- ```file``` (*File*): The .crypt JSON file generated by the encryptor.
- ```passkey``` (*string*): The original string used to encrypt the document. If incorrect, the function will throw a decryption error.
**Returns:**
A ```Promise``` resolving to a ```DecryptionResult``` object:
```
interface DecryptionResult {
  /** The temporary URL pointing to the decrypted PDF in browser memory. */
  pdfUrl: string;
  
  /** The raw decrypted PDF Blob. */
  pdfBlob: Blob;
  
  /** The recovered signature string or Base64 image data. */
  signature: string;
  
  /** The suggested filename, formatted back to "OriginalName.pdf" */
  filename: string;
  
  /** * CRUCIAL METHOD. Severs the Object URL and wipes temporary session memory. */
  cleanup: () => void;
}
```
**Security Considerations**
1. Never skip ```cleanup()```: Browser ObjectURLs (blob:http://...) remain in memory until the document unloads. Failing to call ```cleanup()``` retains the decrypted file in memory longer than necessary.
2. Passkeys are volatile: The library intentionally drops the passkey and derived WebCrypto keys out of scope and overwrites their typed arrays with zeroes (```crypto.getRandomValues```). You should ensure your UI framework (like React state) clears the passkey variable from the input field after usage if high security is required.