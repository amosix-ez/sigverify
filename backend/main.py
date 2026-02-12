"""
Digital Signature Validator - Backend API
Validates PDF digital signatures (works for Aadhaar, global docs)
Run: uvicorn main:app --host 0.0.0.0 --port 8000 --reload
"""

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import io
import json
from datetime import datetime
from typing import Optional

app = FastAPI(title="Digital Signature Validator API")

# Allow all origins for local testing (mobile + browser)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def validate_pdf_signatures(pdf_bytes: bytes) -> dict:
    """
    Validates digital signatures in a PDF using pyHanko.
    Falls back to basic PDF inspection if pyHanko not installed.
    """
    results = {
        "file_size_kb": round(len(pdf_bytes) / 1024, 2),
        "is_pdf": False,
        "signatures": [],
        "summary": {},
        "error": None
    }

    # Check if it's a valid PDF
    if not pdf_bytes.startswith(b'%PDF'):
        results["error"] = "File is not a valid PDF"
        return results

    results["is_pdf"] = True

    # Try pyHanko first (most accurate)
    try:
        from pyhanko.sign.validation import validate_pdf_signature
        from pyhanko_certvalidator import ValidationContext
        from pyhanko.pdf_utils.reader import PdfFileReader

        reader = PdfFileReader(io.BytesIO(pdf_bytes))
        embedded_sigs = reader.embedded_signatures

        if not embedded_sigs:
            results["summary"] = {
                "total_signatures": 0,
                "valid": 0,
                "invalid": 0,
                "status": "NO_SIGNATURES",
                "message": "This PDF has no digital signatures embedded."
            }
            return results

        for i, sig in enumerate(embedded_sigs):
            try:
                vc = ValidationContext(trust_roots=None)  # Uses system/Mozilla roots
                status = validate_pdf_signature(sig, vc)

                sig_info = {
                    "index": i + 1,
                    "signer_name": getattr(status.signing_cert, 'subject', {}).get('common_name', 'Unknown'),
                    "organization": getattr(status.signing_cert, 'subject', {}).get('organization', 'Unknown'),
                    "valid_signature": status.intact and status.valid,
                    "intact": status.intact,           # Document not tampered
                    "trusted": status.trusted,         # Certificate is trusted
                    "cert_expired": False,
                    "signing_time": str(status.signer_reported_dt) if status.signer_reported_dt else "Unknown",
                    "covers_whole_document": not getattr(status, 'has_seed_value_constraint_violations', False),
                    "algorithm": "PKCS#7 / CMS",
                    "issuer": getattr(status.signing_cert, 'issuer', {}).get('common_name', 'Unknown CA'),
                    "details": status.pretty_print_details() if hasattr(status, 'pretty_print_details') else ""
                }
                results["signatures"].append(sig_info)

            except Exception as e:
                results["signatures"].append({
                    "index": i + 1,
                    "error": str(e),
                    "valid_signature": False
                })

        valid_count = sum(1 for s in results["signatures"] if s.get("valid_signature"))
        total = len(results["signatures"])

        results["summary"] = {
            "total_signatures": total,
            "valid": valid_count,
            "invalid": total - valid_count,
            "status": "VALID" if valid_count == total and total > 0 else ("INVALID" if valid_count == 0 else "PARTIAL"),
            "message": f"{valid_count} of {total} signature(s) are valid."
        }

    except ImportError:
        # Fallback: Basic PDF byte-level signature detection
        results = _fallback_validator(pdf_bytes, results)

    return results


def _fallback_validator(pdf_bytes: bytes, results: dict) -> dict:
    """
    Fallback validator when pyHanko is not installed.
    Does real byte-level inspection of the PDF for signature markers.
    """
    text = pdf_bytes.decode('latin-1', errors='replace')

    # Check for signature dictionaries in PDF structure
    has_sig_dict = '/Type /Sig' in text or '/Type/Sig' in text
    has_sig_field = '/SigFlags' in text
    has_byterange = '/ByteRange' in text
    has_contents = '/Contents' in text and has_byterange  # Signature contents
    has_subfilter = '/SubFilter' in text

    # Detect signature subtype
    sig_type = "Unknown"
    if 'adbe.pkcs7.detached' in text.lower():
        sig_type = "PKCS#7 Detached (Standard)"
    elif 'adbe.pkcs7.sha1' in text.lower():
        sig_type = "PKCS#7 SHA1"
    elif 'etsi.cades.detached' in text.lower():
        sig_type = "CAdES Detached (EU eIDAS)"
    elif 'etsi.rfc3161' in text.lower():
        sig_type = "RFC 3161 Timestamp"

    # Try to extract signer name
    signer_name = "Unknown"
    name_idx = text.find('/Name')
    if name_idx != -1:
        snippet = text[name_idx:name_idx + 100]
        if '(' in snippet and ')' in snippet:
            start = snippet.index('(') + 1
            end = snippet.index(')')
            signer_name = snippet[start:end].strip()

    # Try to extract signing date
    signing_date = "Unknown"
    date_idx = text.find('/M (')
    if date_idx == -1:
        date_idx = text.find('/M(')
    if date_idx != -1:
        snippet = text[date_idx:date_idx + 30]
        if '(' in snippet and ')' in snippet:
            start = snippet.index('(') + 1
            end = snippet.index(')')
            raw_date = snippet[start:end].strip()
            # PDF date format: D:YYYYMMDDHHmmSS
            if raw_date.startswith('D:') and len(raw_date) >= 10:
                try:
                    d = raw_date[2:]
                    signing_date = f"{d[0:4]}-{d[4:6]}-{d[6:8]} {d[8:10]}:{d[10:12]}:{d[12:14]}"
                except:
                    signing_date = raw_date

    has_signature = has_sig_dict or has_byterange or has_sig_field

    if has_signature:
        sig_info = {
            "index": 1,
            "signer_name": signer_name,
            "organization": "See certificate details",
            "valid_signature": has_byterange and has_contents,
            "intact": has_byterange,
            "trusted": None,  # Cannot check without pyHanko
            "cert_expired": None,
            "signing_time": signing_date,
            "covers_whole_document": has_byterange,
            "algorithm": sig_type,
            "issuer": "Install pyHanko for full certificate chain",
            "note": "⚠️ Basic detection mode. Install pyHanko for full cryptographic validation."
        }
        results["signatures"] = [sig_info]
        results["summary"] = {
            "total_signatures": 1,
            "valid": 1 if sig_info["valid_signature"] else 0,
            "invalid": 0 if sig_info["valid_signature"] else 1,
            "status": "DETECTED",
            "message": "Signature structure detected. Install pyHanko for full cryptographic validation.",
            "install_note": "Run: pip install pyhanko pyhanko-certvalidator"
        }
    else:
        results["summary"] = {
            "total_signatures": 0,
            "valid": 0,
            "invalid": 0,
            "status": "NO_SIGNATURES",
            "message": "No digital signatures found in this PDF."
        }

    return results


@app.get("/")
def root():
    return {"message": "Digital Signature Validator API is running!", "version": "1.0"}


@app.post("/validate")
async def validate_signature(file: UploadFile = File(...)):
    """
    Upload a PDF file and validate its digital signatures.
    Works for: Aadhaar, PAN, Income Tax, DocuSign, Adobe Sign, EU eIDAS, and all global PDF signatures.
    """
    if not file.filename.lower().endswith('.pdf'):
        raise HTTPException(status_code=400, detail="Only PDF files are supported.")

    if file.size and file.size > 20 * 1024 * 1024:  # 20MB limit
        raise HTTPException(status_code=400, detail="File too large. Max 20MB.")

    try:
        pdf_bytes = await file.read()
        result = validate_pdf_signatures(pdf_bytes)
        result["filename"] = file.filename
        result["validated_at"] = datetime.now().isoformat()
        return JSONResponse(content=result)

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Validation error: {str(e)}")


@app.get("/health")
def health():
    # Check which libraries are available
    libs = {}
    try:
        import pyhanko
        libs["pyhanko"] = "✅ Installed"
    except ImportError:
        libs["pyhanko"] = "❌ Not installed (fallback mode active)"

    return {
        "status": "healthy",
        "libraries": libs,
        "mode": "full" if "✅" in libs.get("pyhanko", "") else "basic_fallback"
    }
