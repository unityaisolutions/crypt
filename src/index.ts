export interface EncryptionResult {
    objectUrl: string;
    blob: Blob;
    filename: string;
    cleanup: () => void;
  }
  
  export interface DecryptionResult {
    pdfUrl: string;
    pdfBlob: Blob;
    signature: string;
    filename: string;
    cleanup: () => void;
  }
  
  export class DocumentEncryptor {
    /**
     * Helper function to convert an ArrayBuffer to a Base64 string robustly.
     * Prevents call stack size limits on large PDFs.
     */
    private static bufferToBase64(buffer: ArrayBuffer): Promise<string> {
      return new Promise((resolve, reject) => {
        const blob = new Blob([buffer]);
        const reader = new FileReader();
        reader.onload = () => {
          const dataUrl = reader.result as string;
          resolve(dataUrl.split(",")[1]); // Strip the data: URL prefix
        };
        reader.onerror = reject;
        reader.readAsDataURL(blob);
      });
    }
  
    /**
     * Helper function to convert a Uint8Array to Base64 string.
     */
    private static uint8ToBase64(uint8: Uint8Array): string {
      let binary = "";
      for (let i = 0; i < uint8.byteLength; i++) {
        binary += String.fromCharCode(uint8[i]);
      }
      return btoa(binary);
    }
  
    /**
     * Helper function to convert a Base64 string back to a Uint8Array.
     */
    private static base64ToUint8Array(base64: string): Uint8Array {
      const binaryString = atob(base64);
      const len = binaryString.length;
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
      return bytes;
    }
  
    /**
     * Wipes a Uint8Array with secure random values to scrub memory.
     */
    private static wipeMemory(array: Uint8Array): void {
      crypto.getRandomValues(array);
    }
  
    /**
     * Encrypts a PDF file and user signature according to the framework specifications.
     */
    public static async encryptPDF(
      file: File,
      passkey: string,
      signature: string // Base64 or plain text
    ): Promise<EncryptionResult> {
      // 1. Data Validation
      if (file.type !== "application/pdf") {
        throw new Error("Invalid file type. Only application/pdf is supported.");
      }
  
      const fileBuffer = await file.arrayBuffer();
      const pdfView = new Uint8Array(fileBuffer);
  
      // Validate PDF Header (%PDF- starts with 25 50 44 46 in hex)
      if (
        pdfView[0] !== 0x25 ||
        pdfView[1] !== 0x50 ||
        pdfView[2] !== 0x44 ||
        pdfView[3] !== 0x46
      ) {
        throw new Error("Invalid file header. File does not appear to be a valid PDF.");
      }
  
      const encoder = new TextEncoder();
      const passkeyArr = encoder.encode(passkey);
      const signatureArr = encoder.encode(signature);
  
      try {
        // 2. Cryptographic Processing
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
  
        // Key Derivation (PBKDF2 -> AES-GCM)
        const keyMaterial = await crypto.subtle.importKey(
          "raw",
          passkeyArr,
          { name: "PBKDF2" },
          false,
          ["deriveKey"]
        );
  
        const cryptoKey = await crypto.subtle.deriveKey(
          {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256",
          },
          keyMaterial,
          { name: "AES-GCM", length: 256 },
          false, // Key not extractable
          ["encrypt"]
        );
  
        // Encrypt PDF and Signature
        const encryptedPdfBuffer = await crypto.subtle.encrypt(
          { name: "AES-GCM", iv: iv },
          cryptoKey,
          pdfView
        );
  
        const encryptedSignatureBuffer = await crypto.subtle.encrypt(
          { name: "AES-GCM", iv: iv },
          cryptoKey,
          signatureArr
        );
  
        // 3. File Packaging and Formatting
        const encryptedPdfBase64 = await this.bufferToBase64(encryptedPdfBuffer);
        const encryptedSignatureBase64 = await this.bufferToBase64(encryptedSignatureBuffer);
  
        const payload = {
          encryptedFile: encryptedPdfBase64,
          encryptedSignature: encryptedSignatureBase64,
          salt: this.uint8ToBase64(salt),
          iv: this.uint8ToBase64(iv),
        };
  
        const payloadString = JSON.stringify(payload);
        
        // 4. Browser State and Availability
        const finalBlob = new Blob([payloadString], { type: "application/json" });
        const objectUrl = URL.createObjectURL(finalBlob);
        const originalName = file.name.replace(".pdf", "");
  
        // 5. Sanitization and Privacy Scrubbing
        const cleanup = () => {
          // Memory Revocation
          URL.revokeObjectURL(objectUrl);
          // Trace Removal from Storage (Ensuring clean state)
          sessionStorage.removeItem("temp_pdf_crypto_state");
        };
  
        return {
          objectUrl,
          blob: finalBlob,
          filename: `${originalName}.crypt`,
          cleanup,
        };
      } finally {
        // Variable Clearing (Guaranteed execution via finally block)
        this.wipeMemory(pdfView);
        this.wipeMemory(passkeyArr);
        this.wipeMemory(signatureArr);
      }
    }
  
    /**
     * Decrypts a .crypt file back into a PDF and retrieves the original signature.
     */
    public static async decryptPDF(
      file: File,
      passkey: string
    ): Promise<DecryptionResult> {
      if (!file.name.endsWith('.crypt')) {
        throw new Error("Invalid file type. Only .crypt files are supported.");
      }
  
      const fileText = await file.text();
      let payload;
      try {
        payload = JSON.parse(fileText);
      } catch (e) {
        throw new Error("Invalid file format. Could not parse payload.");
      }
  
      const { encryptedFile, encryptedSignature, salt, iv } = payload;
      if (!encryptedFile || !encryptedSignature || !salt || !iv) {
        throw new Error("Invalid payload structure. Missing required cryptographic fields.");
      }
  
      const saltArr = this.base64ToUint8Array(salt);
      const ivArr = this.base64ToUint8Array(iv);
      const encryptedPdfArr = this.base64ToUint8Array(encryptedFile);
      const encryptedSigArr = this.base64ToUint8Array(encryptedSignature);
  
      const encoder = new TextEncoder();
      const passkeyArr = encoder.encode(passkey);
  
      let decryptedPdfBuffer: ArrayBuffer | null = null;
      let decryptedSigBuffer: ArrayBuffer | null = null;
  
      try {
        // 1. Key Derivation (Rebuilding the key from the passkey and extracted salt)
        const keyMaterial = await crypto.subtle.importKey(
          "raw",
          passkeyArr,
          { name: "PBKDF2" },
          false,
          ["deriveKey"]
        );
  
        const cryptoKey = await crypto.subtle.deriveKey(
          {
            name: "PBKDF2",
            salt: saltArr as any,
            iterations: 100000,
            hash: "SHA-256",
          },
          keyMaterial,
          { name: "AES-GCM", length: 256 },
          false,
          ["decrypt"]
        );
  
        // 2. Decryption
        try {
          decryptedPdfBuffer = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: ivArr as any },
            cryptoKey,
            encryptedPdfArr as any
          );
  
          decryptedSigBuffer = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: ivArr as any },
            cryptoKey,
            encryptedSigArr as any
          );
        } catch (e) {
          throw new Error("Decryption failed. Incorrect passkey or corrupted file.");
        }
  
        // 3. Reconstruct Original Data
        const decoder = new TextDecoder();
        const decryptedSignature = decoder.decode(decryptedSigBuffer);
  
        const pdfBlob = new Blob([decryptedPdfBuffer], { type: "application/pdf" });
        const pdfUrl = URL.createObjectURL(pdfBlob);
        const originalName = file.name.replace(".crypt", ".pdf");
  
        const cleanup = () => {
          URL.revokeObjectURL(pdfUrl);
          sessionStorage.removeItem("temp_pdf_crypto_state");
        };
  
        return {
          pdfUrl,
          pdfBlob,
          signature: decryptedSignature,
          filename: originalName,
          cleanup,
        };
      } finally {
        // 4. Secure Memory Sanitization
        this.wipeMemory(passkeyArr);
        this.wipeMemory(saltArr);
        this.wipeMemory(ivArr);
        this.wipeMemory(encryptedPdfArr);
        this.wipeMemory(encryptedSigArr);
        if (decryptedPdfBuffer) this.wipeMemory(new Uint8Array(decryptedPdfBuffer));
        if (decryptedSigBuffer) this.wipeMemory(new Uint8Array(decryptedSigBuffer));
      }
    }
  }