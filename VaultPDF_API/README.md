# 🔐 VaultPDF REST API

A production-ready **Flask REST API** for AES-256-CBC PDF encryption and decryption.  
Converted from the original VaultPDF web-app while keeping **all existing crypto logic intact**.

---

## 📁 Project Structure

```
VaultPDF_API/
├── app.py                        # Main entry point — Flask app factory + blueprint registration
├── requirements.txt              # Python dependencies
├── .gitignore
│
├── routes/
│   ├── __init__.py               # Exports all blueprints
│   ├── encrypt.py                # POST /encrypt, GET/DELETE /encrypt/files
│   ├── decrypt.py                # POST /decrypt, POST /decrypt/by-id
│   └── health.py                 # GET /health
│
├── utils/
│   ├── __init__.py
│   ├── crypto.py                 # ← ORIGINAL AES-256 logic (unchanged)
│   └── helpers.py                # Validation, metadata I/O, response builders
│
├── uploads/
│   ├── encrypted/                # Server-stored .enc files (auto-created)
│   └── .metadata.json            # File registry (auto-created)
│
└── logs/
    └── vaultpdf.log              # Auto-created on first run
```

---

## 🚀 Quick Start

### 1. Create a virtual environment

```bash
python -m venv venv
source venv/bin/activate        # macOS / Linux
venv\Scripts\activate           # Windows
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the development server

```bash
python app.py
```

### 4. Production (gunicorn)

```bash
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

---

## 📡 API Endpoints

### `GET /health`

Liveness + readiness probe.

**Response 200:**
```json
{
  "status":          "success",
  "message":         "VaultPDF API is running",
  "api_version":     "1.0.0",
  "encryption":      "AES-256-CBC",
  "key_derivation":  "PBKDF2-HMAC-SHA256 (260,000 iterations)",
  "uptime":          "0d 1h 23m",
  "storage":         "accessible",
  "total_files":     5,
  "total_size":      "12.4 MB",
  "timestamp":       "2026-05-27T14:00:00"
}
```

---

### `POST /encrypt`

Encrypt a PDF with a user-supplied password.

**Request:** `multipart/form-data`

| Field    | Type   | Required | Description                |
|----------|--------|----------|----------------------------|
| file     | File   | ✅        | PDF to encrypt             |
| password | string | ✅        | 4–128 character password   |

**Response 200:**
```json
{
  "status":     "success",
  "message":    "PDF encrypted successfully",
  "file_id":    "3f7a2b1c-89d4-4e2a-a1f0-123456789abc",
  "filename":   "contract.pdf",
  "size":       "248.3 KB",
  "file":       "uploads/encrypted/3f7a2b1c-....enc",
  "created_at": "May 27, 2026 at 02:15 PM"
}
```

> **Save the `file_id`** — you need it to decrypt via `/decrypt/by-id`.

---

### `GET /encrypt/files`

List all encrypted files stored on the server.

**Response 200:**
```json
{
  "status":  "success",
  "message": "2 file(s) found",
  "count":   2,
  "files":   [
    {
      "id":           "3f7a2b1c-...",
      "original_name":"contract.pdf",
      "readable_size":"248.3 KB",
      "operation":    "encrypt",
      "created_at":   "2026-05-27T14:00:00"
    }
  ]
}
```

---

### `DELETE /encrypt/files/<file_id>`

Delete a stored encrypted file and its metadata.

**Response 200:**
```json
{
  "status":   "success",
  "message":  "File deleted successfully",
  "file_id":  "3f7a2b1c-..."
}
```

---

### `POST /decrypt/by-id`

Decrypt a server-side file by its UUID. Returns the PDF as a download.

**Request:** JSON body or `multipart/form-data`

| Field    | Type   | Required | Description                       |
|----------|--------|----------|-----------------------------------|
| file_id  | string | ✅        | UUID from POST /encrypt response  |
| password | string | ✅        | Password used during encryption   |

**Response 200:** Binary PDF stream (`Content-Disposition: attachment`)

**Response 400:** Wrong password or corrupted file
```json
{
  "status":  "error",
  "message": "Decryption failed. Please check your password and try again."
}
```

---

### `POST /decrypt`

Decrypt an `.enc` file you upload directly (without a server-side UUID).

**Request:** `multipart/form-data`

| Field    | Type   | Required | Description                              |
|----------|--------|----------|------------------------------------------|
| file     | File   | ✅        | The `.enc` file to decrypt               |
| password | string | ✅        | Password used during encryption          |
| salt_hex | string | ✅        | `salt_hex` from POST /encrypt metadata   |

**Response 200:** Binary PDF stream

> The `salt_hex` must be stored by the caller when encrypting — it is returned
> in the encrypt response metadata record.  The server does **not** expose it
> via the public file list.

---

## 🔑 Security Architecture

```
Encrypt flow:
  PDF upload  →  magic-byte validation  →  temp file
             →  PBKDF2-HMAC-SHA256(password, random salt, 260k iter)  →  32-byte AES key
             →  AES-256-CBC encrypt (unique IV per file)
             →  .enc file saved  →  temp file deleted  →  salt stored in metadata

Decrypt flow:
  file_id + password  →  load salt from metadata
                      →  PBKDF2-HMAC-SHA256(password, salt, 260k iter)  →  AES key
                      →  AES-256-CBC decrypt  →  temp PDF  →  streamed to client  →  temp deleted
```

| Feature          | Implementation                                   |
|------------------|--------------------------------------------------|
| Encryption       | AES-256-CBC                                      |
| Key derivation   | PBKDF2-HMAC-SHA256, 260,000 iterations           |
| IV               | Unique random 16 bytes per file                  |
| Salt             | Unique random 32 bytes per file                  |
| File storage     | Only `.enc` encrypted blobs                      |
| Path traversal   | UUID validation on all file IDs                  |
| Input validation | Extension + MIME type + `%PDF` magic bytes       |
| File size limit  | 50 MB (Werkzeug-enforced)                        |
| Temp file cleanup| Deleted immediately after encrypt/decrypt        |
| CORS             | Configurable via `CORS_ORIGINS` env var          |

---

## 🧪 Postman Testing

### 1. Health check
```
GET http://127.0.0.1:5000/health
```

### 2. Encrypt a PDF
```
POST http://127.0.0.1:5000/encrypt
Body → form-data:
  file     = [select a PDF file]
  password = mySecret123
```
Copy the `file_id` from the response.

### 3. List encrypted files
```
GET http://127.0.0.1:5000/encrypt/files
```

### 4. Decrypt by ID
```
POST http://127.0.0.1:5000/decrypt/by-id
Body → raw JSON:
{
  "file_id":  "3f7a2b1c-...",
  "password": "mySecret123"
}
```
Set **"Send and download"** in Postman to save the returned PDF.

### 5. Delete a file
```
DELETE http://127.0.0.1:5000/encrypt/files/3f7a2b1c-...
```

---

## 💻 cURL Examples

### Encrypt
```bash
curl -X POST http://127.0.0.1:5000/encrypt \
  -F "file=@/path/to/document.pdf" \
  -F "password=mySecret123"
```

### Decrypt by ID
```bash
curl -X POST http://127.0.0.1:5000/decrypt/by-id \
  -H "Content-Type: application/json" \
  -d '{"file_id":"3f7a2b1c-...","password":"mySecret123"}' \
  -o decrypted_output.pdf
```

### List files
```bash
curl http://127.0.0.1:5000/encrypt/files
```

### Delete a file
```bash
curl -X DELETE http://127.0.0.1:5000/encrypt/files/3f7a2b1c-...
```

---

## 🐘 PHP cURL Integration

```php
<?php
// ── Encrypt a PDF ──────────────────────────────────────────────────────────
function encryptPdf(string $filePath, string $password): array
{
    $ch = curl_init('http://127.0.0.1:5000/encrypt');

    $postData = [
        'file'     => new CURLFile($filePath, 'application/pdf', basename($filePath)),
        'password' => $password,
    ];

    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $postData,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 60,
    ]);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    $data = json_decode($response, true);

    if ($httpCode !== 200 || $data['status'] !== 'success') {
        throw new RuntimeException('Encryption failed: ' . ($data['message'] ?? 'Unknown error'));
    }

    return $data;  // contains file_id, filename, size, etc.
}

// ── Decrypt a PDF and save to disk ─────────────────────────────────────────
function decryptPdf(string $fileId, string $password, string $savePath): void
{
    $ch = curl_init('http://127.0.0.1:5000/decrypt/by-id');

    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => json_encode(['file_id' => $fileId, 'password' => $password]),
        CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 60,
        CURLOPT_FILE           => fopen($savePath, 'wb'),
    ]);

    curl_exec($ch);
    curl_close($ch);
}

// Usage:
$result = encryptPdf('/path/to/report.pdf', 'mySecret123');
echo "Encrypted! file_id = " . $result['file_id'] . PHP_EOL;

decryptPdf($result['file_id'], 'mySecret123', '/path/to/decrypted.pdf');
echo "Decrypted to /path/to/decrypted.pdf" . PHP_EOL;
```

---

## 🌐 JavaScript / Fetch (AJAX) Integration

```javascript
// ── Encrypt a PDF ──────────────────────────────────────────────────────────
async function encryptPdf(file, password) {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('password', password);

  const res = await fetch('http://127.0.0.1:5000/encrypt', {
    method: 'POST',
    body: formData,
  });

  const data = await res.json();
  if (!res.ok || data.status !== 'success') {
    throw new Error(data.message || 'Encryption failed');
  }

  return data;  // { file_id, filename, size, created_at, ... }
}

// ── Decrypt and trigger browser download ───────────────────────────────────
async function decryptAndDownload(fileId, password, fileName) {
  const res = await fetch('http://127.0.0.1:5000/decrypt/by-id', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ file_id: fileId, password }),
  });

  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.message || 'Decryption failed');
  }

  // Trigger browser save-dialog
  const blob = await res.blob();
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = fileName || 'decrypted.pdf';
  a.click();
  URL.revokeObjectURL(url);
}

// ── Example: wiring up an HTML form ────────────────────────────────────────
document.getElementById('encryptForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const file     = e.target.pdfFile.files[0];
  const password = e.target.password.value;

  try {
    const result = await encryptPdf(file, password);
    console.log('Encrypted:', result);
    alert(`Success! file_id: ${result.file_id}`);
  } catch (err) {
    alert('Error: ' + err.message);
  }
});
```

---

## ⚙️ Environment Variables

| Variable           | Default            | Purpose                                   |
|--------------------|--------------------|-------------------------------------------|
| `FLASK_SECRET_KEY` | random on startup  | Flask session signing key (rotate this!)  |
| `CORS_ORIGINS`     | `*`                | Allowed CORS origins (e.g. `https://yourapp.com`) |

```bash
# Example .env (load with python-dotenv or export manually)
export FLASK_SECRET_KEY="your-long-random-secret-here"
export CORS_ORIGINS="https://yourapp.com"
```

---

## 🏭 Production Checklist

- [ ] Set `FLASK_SECRET_KEY` via environment variable (not hardcoded)
- [ ] Restrict `CORS_ORIGINS` to your front-end domain
- [ ] Run behind HTTPS (nginx + Let's Encrypt)
- [ ] Use gunicorn: `gunicorn -w 4 app:app`
- [ ] Set `debug=False` (already the default via gunicorn)
- [ ] Mount `uploads/` on persistent storage (not ephemeral)
- [ ] Rotate logs: configure logrotate for `logs/vaultpdf.log`
- [ ] Back up (and secure) the `uploads/.metadata.json` file

---

## 📦 Dependencies

| Package       | Purpose                                            |
|---------------|----------------------------------------------------|
| Flask         | Web framework                                      |
| Flask-CORS    | Cross-Origin Resource Sharing headers              |
| cryptography  | AES-256-CBC via hazmat primitives                  |
| Werkzeug      | Secure filename, request utilities                 |
| pypdf         | PDF validation                                     |
| gunicorn      | Production WSGI server                             |
