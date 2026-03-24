export interface EncryptionResult {
    objectUrl: string;
    blob: Blob;
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
  }