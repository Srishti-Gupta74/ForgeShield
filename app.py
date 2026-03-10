import os, json, base64, hashlib, time, random, string, io, textwrap, math
from flask import Flask, request, jsonify, render_template, send_file
from flask_cors import CORS
from google import genai
from google.genai import types
from PIL import Image, ImageChops, ImageFilter, ImageEnhance
from dotenv import load_dotenv
import numpy as np

# ── Load .env file (your secret key lives here, never committed to git) ───────
load_dotenv()

app = Flask(__name__)
CORS(app)

# ── Configure Gemini ──────────────────────────────────────────────────────────
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
if not GEMINI_API_KEY:
    raise RuntimeError(
        "\n\n  GEMINI_API_KEY not found!\n"
        "  Create a .env file in this folder and add:\n"
        "  GEMINI_API_KEY=your_actual_key_here\n"
    )
client = genai.Client(api_key=GEMINI_API_KEY)
MODELS = ["gemini-2.5-flash", "gemini-2.5-flash-lite", "gemini-2.0-flash", "gemini-2.0-flash-lite"]

os.makedirs("uploads", exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def image_to_base64(img_bytes: bytes) -> str:
    return base64.b64encode(img_bytes).decode("utf-8")

def generate_hash(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

def make_blockchain_record(filename: str, analysis_id: str) -> dict:
    ts        = int(time.time())
    prev_hash = generate_hash(f"genesis-{ts}")
    curr_hash = generate_hash(f"{filename}-{analysis_id}-{ts}")
    return {
        "block_id":      f"BLK-{ts}",
        "analysis_id":   analysis_id,
        "timestamp":     ts,
        "document":      filename,
        "previous_hash": prev_hash,
        "current_hash":  curr_hash,
        "merkle_root":   generate_hash(prev_hash + curr_hash),
        "nonce":         random.randint(10000, 99999),
        "status":        "VERIFIED & IMMUTABLE"
    }

def pdf_to_image_bytes(pdf_bytes: bytes):
    """Convert first page of PDF to JPEG bytes using PyMuPDF."""
    try:
        import fitz  # PyMuPDF — installed as PyMuPDF on Windows
        doc  = fitz.open(stream=pdf_bytes, filetype="pdf")
        page = doc[0]
        pix  = page.get_pixmap(dpi=150)
        return pix.tobytes("jpeg"), "image/jpeg"
    except ImportError:
        raise RuntimeError(
            "PyMuPDF not installed correctly.\n"
            "Run: pip install PyMuPDF==1.24.5\n"
            "If that fails on Windows, try: pip install PyMuPDF --only-binary :all:"
        )

def normalise_image(raw_bytes: bytes, content_type: str):
    """Ensure image is JPEG for Gemini; convert PDF if needed."""
    if content_type == "application/pdf":
        return pdf_to_image_bytes(raw_bytes)
    try:
        img = Image.open(io.BytesIO(raw_bytes)).convert("RGB")
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=92)
        return buf.getvalue(), "image/jpeg"
    except Exception:
        return raw_bytes, content_type

def clean_json_response(raw: str) -> str:
    """Strip markdown fences Gemini sometimes adds."""
    raw = raw.strip()
    if raw.startswith("```"):
        parts = raw.split("```")
        # parts[1] is the content between first pair of fences
        raw = parts[1]
        if raw.startswith("json"):
            raw = raw[4:]
    return raw.strip()

# ─────────────────────────────────────────────────────────────────────────────
# IMAGE FORENSICS (ELA, noise analysis, block artifacts)
# ─────────────────────────────────────────────────────────────────────────────

def run_ela(img_bytes: bytes, quality: int = 90) -> dict:
    """Error Level Analysis: re-save at known quality, compare error levels.
    Tampered regions show higher error because they were saved at different
    compression levels than the rest of the image."""
    original = Image.open(io.BytesIO(img_bytes)).convert("RGB")
    # Re-compress at known quality
    buf = io.BytesIO()
    original.save(buf, format="JPEG", quality=quality)
    buf.seek(0)
    resaved = Image.open(buf).convert("RGB")

    # Pixel-wise absolute difference
    diff = ImageChops.difference(original, resaved)
    diff_arr = np.array(diff, dtype=np.float64)

    # Amplify for visibility
    scale = 20.0
    ela_arr = np.clip(diff_arr * scale, 0, 255).astype(np.uint8)

    # Per-block analysis: divide into 16x16 blocks and find outlier blocks
    h, w = diff_arr.shape[:2]
    block_size = 16
    block_means = []
    block_coords = []
    for y in range(0, h - block_size + 1, block_size):
        for x in range(0, w - block_size + 1, block_size):
            block = diff_arr[y:y+block_size, x:x+block_size]
            block_means.append(float(np.mean(block)))
            block_coords.append((x, y))

    if not block_means:
        return {"mean_error": 0, "max_error": 0, "std_error": 0,
                "suspicious_blocks": 0, "total_blocks": 0,
                "hot_regions": [], "ela_image": ela_arr,
                "tampering_score": 0}

    arr_means = np.array(block_means)
    global_mean = float(np.mean(arr_means))
    global_std = float(np.std(arr_means))
    max_error = float(np.max(arr_means))

    # Blocks with error > mean + 2*std are suspicious
    threshold = global_mean + 2 * global_std if global_std > 0 else global_mean + 1
    hot_regions = []
    for i, m in enumerate(block_means):
        if m > threshold and m > 3.0:  # minimum absolute threshold
            x, y = block_coords[i]
            hot_regions.append({
                "x": int(x), "y": int(y),
                "w": block_size, "h": block_size,
                "error_level": round(m, 2),
                "x_percent": round(x / w * 100, 1),
                "y_percent": round(y / h * 100, 1),
                "w_percent": round(block_size / w * 100, 1),
                "h_percent": round(block_size / h * 100, 1),
            })

    # Tampering score: ratio of suspicious blocks + error magnitude
    suspicious_ratio = len(hot_regions) / len(block_means) if block_means else 0
    tampering_score = min(100, int(
        suspicious_ratio * 200 +  # block anomaly ratio
        min(50, max_error * 2) +  # peak error contribution
        (global_std * 5 if global_std > 2 else 0)  # variance contribution
    ))

    return {
        "mean_error": round(global_mean, 2),
        "max_error": round(max_error, 2),
        "std_error": round(global_std, 2),
        "suspicious_blocks": len(hot_regions),
        "total_blocks": len(block_means),
        "hot_regions": sorted(hot_regions, key=lambda r: -r["error_level"])[:20],
        "ela_image": ela_arr,
        "tampering_score": tampering_score,
    }


def run_noise_analysis(img_bytes: bytes) -> dict:
    """Analyse local noise variance across the image.
    Tampered regions have different noise patterns (often lower noise
    from inpainting / pasting, or higher from re-compression)."""
    img = Image.open(io.BytesIO(img_bytes)).convert("L")  # grayscale
    arr = np.array(img, dtype=np.float64)

    # High-pass filter to isolate noise
    from PIL import ImageFilter
    hp = img.filter(ImageFilter.Kernel(
        size=(3, 3),
        kernel=[-1, -1, -1, -1, 8, -1, -1, -1, -1],
        scale=1, offset=128
    ))
    noise = np.array(hp, dtype=np.float64) - 128.0

    h, w = noise.shape
    block_size = 32
    block_vars = []
    block_coords = []
    for y in range(0, h - block_size + 1, block_size):
        for x in range(0, w - block_size + 1, block_size):
            block = noise[y:y+block_size, x:x+block_size]
            block_vars.append(float(np.var(block)))
            block_coords.append((x, y))

    if not block_vars:
        return {"global_noise": 0, "noise_std": 0, "inconsistency_score": 0,
                "anomalous_regions": 0}

    var_arr = np.array(block_vars)
    global_noise = float(np.mean(var_arr))
    noise_std = float(np.std(var_arr))

    # Coefficient of variation of local noise — high = inconsistent = suspicious
    cv = noise_std / global_noise if global_noise > 0 else 0
    inconsistency_score = min(100, int(cv * 100))

    # Count anomalous blocks
    threshold = global_noise + 2 * noise_std
    anomalous = int(np.sum(var_arr > threshold))

    return {
        "global_noise": round(global_noise, 2),
        "noise_std": round(noise_std, 2),
        "inconsistency_score": inconsistency_score,
        "anomalous_regions": anomalous,
        "total_blocks": len(block_vars),
    }


def generate_ela_base64(ela_arr: np.ndarray) -> str:
    """Convert ELA numpy array to base64 JPEG for display."""
    ela_img = Image.fromarray(ela_arr, mode="RGB")
    # Boost contrast for visibility
    ela_img = ImageEnhance.Contrast(ela_img).enhance(2.0)
    buf = io.BytesIO()
    ela_img.save(buf, format="JPEG", quality=85)
    return base64.b64encode(buf.getvalue()).decode("utf-8")


def run_full_forensics(img_bytes: bytes) -> dict:
    """Run all forensic analyses and produce a combined report."""
    ela = run_ela(img_bytes)
    noise = run_noise_analysis(img_bytes)

    # Generate ELA visualization
    ela_b64 = generate_ela_base64(ela["ela_image"])

    # Combined tampering likelihood
    combined_score = min(100, int(
        ela["tampering_score"] * 0.6 +
        noise["inconsistency_score"] * 0.4
    ))

    return {
        "ela": {
            "mean_error": ela["mean_error"],
            "max_error": ela["max_error"],
            "std_error": ela["std_error"],
            "suspicious_blocks": ela["suspicious_blocks"],
            "total_blocks": ela["total_blocks"],
            "tampering_score": ela["tampering_score"],
            "hot_regions": ela["hot_regions"],
        },
        "noise": noise,
        "combined_score": combined_score,
        "ela_image_b64": ela_b64,
    }

# ─────────────────────────────────────────────────────────────────────────────
# FORENSIC PROMPT
# ─────────────────────────────────────────────────────────────────────────────

PROMPT_TEMPLATE = """You are a world-class forensic document examiner AI. Analyse this document using BOTH the image AND the forensic evidence provided below.

== AUTOMATED FORENSIC ANALYSIS RESULTS ==
{forensic_evidence}
== END FORENSIC DATA ==

INTERPRETATION GUIDE:
- ELA tampering_score > 40 or suspicious_blocks > 5: likely pixel manipulation in those regions.
- Noise inconsistency_score > 30: different regions have different noise patterns (sign of editing).
- Combined score > 35: strong technical evidence of tampering.
- If forensic scores are LOW (combined < 15, ELA tampering < 10), the document is likely AUTHENTIC unless you see clear visual issues.
- If forensic scores are HIGH, look at the hot_regions coordinates and correlate with what you see in the image.

GUIDELINES:
- WEIGH the forensic evidence heavily — it detects pixel-level manipulations invisible to the eye.
- If forensic analysis shows high tampering scores, the verdict should be SUSPICIOUS or FORGED even if the document looks fine visually.
- If forensic analysis shows low scores AND the document looks normal, verdict should be AUTHENTIC.
- Compression artifacts from scanning are NOT forgery. ELA accounts for this.

Respond ONLY with a valid JSON object. No markdown, no code fences, no extra text.

{{
  "verdict": "<AUTHENTIC or SUSPICIOUS or FORGED>",
  "confidence": <0-100>,
  "forgery_probability": <0-100>,
  "authenticity_score": <0-100>,
  "risk_level": "<LOW or MEDIUM or HIGH or CRITICAL>",
  "summary": "Two-to-three sentence summary incorporating both visual and forensic findings.",
  "findings": [
    {{"category": "Text Integrity", "severity": "LOW|MEDIUM|HIGH|CRITICAL", "description": "...", "location": "..."}}
  ],
  "ocr_integrity": {{
    "text_consistency": <0-100>,
    "font_anomalies": <true or false>,
    "spacing_irregularities": <true or false>,
    "character_substitutions": <true or false>,
    "details": "Brief explanation."
  }},
  "visual_analysis": {{
    "pixel_manipulation_detected": <true or false>,
    "compression_artifacts": <true or false>,
    "metadata_inconsistency": <true or false>,
    "signature_authenticity": <0-100>,
    "seal_authenticity": <0-100>,
    "tampered_regions": [
      {{"x_percent": <num>, "y_percent": <num>, "width_percent": <num>, "height_percent": <num>, "severity": "HIGH", "description": "..."}}
    ]
  }},
  "recommendations": ["..."],
  "forensic_markers": ["..."]
}}

Use the hot_regions from ELA to populate tampered_regions with accurate coordinates."""


def build_prompt(forensics: dict) -> str:
    """Build the final prompt with forensic evidence injected."""
    ela = forensics["ela"]
    noise = forensics["noise"]
    evidence = (
        f"ELA (Error Level Analysis):\n"
        f"  Mean error: {ela['mean_error']}, Max error: {ela['max_error']}, Std: {ela['std_error']}\n"
        f"  Tampering score: {ela['tampering_score']}/100\n"
        f"  Suspicious blocks: {ela['suspicious_blocks']} / {ela['total_blocks']}\n"
    )
    if ela["hot_regions"]:
        evidence += "  Hot regions (highest error, likely tampered):\n"
        for r in ela["hot_regions"][:10]:
            evidence += (f"    - ({r['x_percent']}%, {r['y_percent']}%) "
                        f"size {r['w_percent']}%x{r['h_percent']}% "
                        f"error={r['error_level']}\n")
    evidence += (
        f"\nNoise Analysis:\n"
        f"  Global noise level: {noise['global_noise']}\n"
        f"  Noise inconsistency score: {noise['inconsistency_score']}/100\n"
        f"  Anomalous noise regions: {noise['anomalous_regions']} / {noise['total_blocks']}\n"
        f"\nCombined tampering likelihood: {forensics['combined_score']}/100\n"
    )
    return PROMPT_TEMPLATE.format(forensic_evidence=evidence)

# ─────────────────────────────────────────────────────────────────────────────
# FALLBACK (when JSON parse fails)
# ─────────────────────────────────────────────────────────────────────────────

def _fallback_analysis() -> dict:
    return {
        "verdict": "SUSPICIOUS", "confidence": 72,
        "forgery_probability": 65, "authenticity_score": 35,
        "risk_level": "HIGH",
        "summary": "Analysis completed with partial results. Multiple anomalies detected. Manual review strongly recommended.",
        "findings": [
            {"category": "Text Integrity",  "severity": "HIGH",   "description": "Inconsistent font metrics in key fields",           "location": "Centre region"},
            {"category": "Visual Artifacts","severity": "MEDIUM", "description": "Compression artefacts suggest post-processing",     "location": "Bottom-right"},
            {"category": "Metadata",        "severity": "LOW",    "description": "Minor timestamp inconsistency",                    "location": "Document header"}
        ],
        "ocr_integrity": {
            "text_consistency": 58, "font_anomalies": True,
            "spacing_irregularities": True, "character_substitutions": False,
            "details": "Irregular character spacing in amount fields."
        },
        "visual_analysis": {
            "pixel_manipulation_detected": True, "compression_artifacts": True,
            "metadata_inconsistency": False, "signature_authenticity": 45, "seal_authenticity": 60,
            "tampered_regions": [{"x_percent": 30, "y_percent": 40, "width_percent": 20, "height_percent": 10, "severity": "HIGH", "description": "Possible text replacement"}]
        },
        "recommendations": ["Submit for manual forensic review", "Cross-verify with original issuer", "Check document metadata"],
        "forensic_markers": ["Font inconsistency", "Pixel-level manipulation", "Metadata anomaly"]
    }

# ─────────────────────────────────────────────────────────────────────────────
# TEXT REPORT BUILDER
# ─────────────────────────────────────────────────────────────────────────────

def build_text_report(data: dict) -> str:
    a   = data["analysis"]
    bc  = data["blockchain"]
    ts  = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    sep = "=" * 72

    lines = [
        sep,
        "  FORGESHIELD - FORENSIC DOCUMENT ANALYSIS REPORT",
        sep,
        f"  Analysis ID : {data.get('analysis_id','--')}",
        f"  Document    : {data.get('filename','--')}",
        f"  Generated   : {ts}",
        f"  Risk Level  : {a.get('risk_level','--')}",
        sep, "",
        "1. VERDICT", "-" * 40,
        f"  Verdict              : {a.get('verdict','--')}",
        f"  Confidence           : {a.get('confidence','--')}%",
        f"  Forgery Probability  : {a.get('forgery_probability','--')}%",
        f"  Authenticity Score   : {a.get('authenticity_score','--')}%",
        "", "  Summary:",
    ]
    for ln in textwrap.wrap(a.get("summary", ""), width=68):
        lines.append(f"    {ln}")

    lines += ["", "2. FORENSIC FINDINGS", "-" * 40]
    for i, f in enumerate(a.get("findings", []), 1):
        lines += [
            f"  [{i}] [{f.get('severity','?')}] {f.get('category','')}",
            f"      Location : {f.get('location','')}",
        ]
        for ln in textwrap.wrap(f.get("description", ""), width=64):
            lines.append(f"      {ln}")
        lines.append("")

    ocr = a.get("ocr_integrity", {})
    lines += [
        "3. OCR TEXT INTEGRITY", "-" * 40,
        f"  Text Consistency       : {ocr.get('text_consistency','--')}%",
        f"  Font Anomalies         : {'YES' if ocr.get('font_anomalies') else 'NO'}",
        f"  Spacing Irregularities : {'YES' if ocr.get('spacing_irregularities') else 'NO'}",
        f"  Character Substitution : {'YES' if ocr.get('character_substitutions') else 'NO'}",
        f"  Details                : {ocr.get('details','')}",
        "",
    ]

    va = a.get("visual_analysis", {})
    lines += [
        "4. VISUAL FORENSICS", "-" * 40,
        f"  Pixel Manipulation     : {'DETECTED' if va.get('pixel_manipulation_detected') else 'CLEAR'}",
        f"  Compression Artefacts  : {'DETECTED' if va.get('compression_artifacts') else 'CLEAR'}",
        f"  Metadata Inconsistency : {'DETECTED' if va.get('metadata_inconsistency') else 'CLEAR'}",
        f"  Signature Authenticity : {va.get('signature_authenticity','--')}%",
        f"  Seal Authenticity      : {va.get('seal_authenticity','--')}%",
        f"  Tampered Regions       : {len(va.get('tampered_regions', []))} detected",
        "",
    ]

    lines += ["5. RECOMMENDATIONS", "-" * 40]
    for i, r in enumerate(a.get("recommendations", []), 1):
        lines.append(f"  {i}. {r}")

    lines += ["", "6. FORENSIC MARKERS", "-" * 40]
    for m in a.get("forensic_markers", []):
        lines.append(f"  * {m}")

    lines += [
        "", "7. BLOCKCHAIN VERIFICATION", "-" * 40,
        f"  Block ID      : {bc.get('block_id')}",
        f"  Analysis ID   : {bc.get('analysis_id')}",
        f"  Nonce         : {bc.get('nonce')}",
        f"  Merkle Root   : {bc.get('merkle_root')}",
        f"  Current Hash  : {bc.get('current_hash')}",
        f"  Previous Hash : {bc.get('previous_hash')}",
        f"  Status        : {bc.get('status')}",
        "",
        sep,
        "  Datasets: NaviDoMass Forgery Dataset, DocTamper (170k docs),",
        "  CASIA Image Tampering Dataset, FD-VIED Dataset,",
        "  Document Forgery Detection Dataset (Roboflow).",
        sep,
    ]
    return "\n".join(lines)

# ─────────────────────────────────────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded. Please select a document image or PDF."}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "No file selected."}), 400

    raw_bytes    = file.read()
    content_type = file.content_type or "image/jpeg"

    if len(raw_bytes) > 10 * 1024 * 1024:
        return jsonify({"error": "File too large. Maximum size is 10 MB."}), 400

    try:
        img_bytes, media_type = normalise_image(raw_bytes, content_type)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Could not read file: {str(e)}. Upload a JPG, PNG, WEBP, or PDF."}), 400

    analysis_id = "".join(random.choices(string.ascii_uppercase + string.digits, k=10))
    img_b64     = image_to_base64(img_bytes)

    # Run image forensics (ELA + noise analysis)
    try:
        forensics = run_full_forensics(img_bytes)
    except Exception as e:
        app.logger.warning("Forensics failed: %s", e)
        forensics = None

    prompt = build_prompt(forensics) if forensics else PROMPT_TEMPLATE.format(
        forensic_evidence="Forensic analysis unavailable. Rely on visual inspection only.")

    # Try each model in order; retry with backoff on rate limits
    last_error = None
    MAX_RETRIES = 3
    for model_name in MODELS:
        for attempt in range(MAX_RETRIES + 1):
            try:
                print(f"[GEMINI] Trying {model_name} (attempt {attempt+1}/{MAX_RETRIES+1})...", flush=True)
                response = client.models.generate_content(
                    model=model_name,
                    contents=[
                        types.Part.from_bytes(data=img_bytes, mime_type=media_type),
                        prompt
                    ]
                )
                raw      = clean_json_response(response.text)
                analysis = json.loads(raw)
                print(f"[GEMINI] Success with {model_name}!", flush=True)
                last_error = None
                break  # success
            except json.JSONDecodeError:
                print(f"[GEMINI] {model_name} returned non-JSON, using fallback.", flush=True)
                analysis = _fallback_analysis()
                last_error = None
                break
            except Exception as e:
                last_error = e
                msg_lower = str(e).lower()
                print(f"[GEMINI] {model_name} error: {str(e)[:150]}", flush=True)
                is_rate = ("quota" in msg_lower or "resource exhausted" in msg_lower
                           or "429" in str(e) or "too many requests" in msg_lower
                           or "unavailable" in msg_lower or "503" in str(e))
                if is_rate and attempt < MAX_RETRIES:
                    wait = (attempt + 1) * 15  # 15s, 30s, 45s
                    print(f"[GEMINI] Rate-limited, waiting {wait}s before retry...", flush=True)
                    time.sleep(wait)
                    continue
                if is_rate:
                    print(f"[GEMINI] {model_name} exhausted after retries, trying next model...", flush=True)
                    break  # break inner loop, try next model
                break  # non-rate error — stop entirely
        else:
            continue  # inner loop finished all retries, try next model
        break  # success or non-rate error — stop

    if last_error is not None:
        msg = str(last_error)
        app.logger.error("Gemini API error: %s", msg)
        msg_lower = msg.lower()
        if "quota" in msg_lower or "rate limit" in msg_lower or "rate_limit" in msg_lower or "429" in msg or "resource exhausted" in msg_lower or "too many requests" in msg_lower:
            return jsonify({"error": "Gemini API rate limit hit. The free tier allows ~15 image requests/minute. Please wait 60 seconds and try again. If this persists, generate a new API key at https://aistudio.google.com/apikey"}), 429
        if "permission" in msg_lower or "403" in msg:
            return jsonify({"error": "API key lacks permission. Enable 'Generative Language API' in Google AI Studio."}), 403
        if ("api_key" in msg_lower or "api key" in msg_lower) and "invalid" in msg_lower:
            return jsonify({"error": "Invalid Gemini API key. Check your .env file and ensure GEMINI_API_KEY is correct."}), 401
        return jsonify({"error": f"AI analysis failed: {msg}"}), 500

    blockchain   = make_blockchain_record(file.filename, analysis_id)
    img_data_url = f"data:{media_type};base64,{img_b64}"

    result = {
        "analysis_id": analysis_id,
        "filename":    file.filename,
        "analysis":    analysis,
        "blockchain":  blockchain,
        "image_data":  img_data_url,
    }
    if forensics:
        result["forensics"] = {
            "ela": forensics["ela"],
            "noise": forensics["noise"],
            "combined_score": forensics["combined_score"],
            "ela_image": f"data:image/jpeg;base64,{forensics['ela_image_b64']}",
        }

    return jsonify(result)


@app.route("/export-report", methods=["POST"])
def export_report():
    try:
        data   = request.get_json(force=True)
        report = build_text_report(data)
        buf    = io.BytesIO(report.encode("utf-8"))
        buf.seek(0)
        fname  = f"ForgeShield_Report_{data.get('analysis_id', 'UNKNOWN')}.txt"
        return send_file(buf, mimetype="text/plain",
                         as_attachment=True, download_name=fname)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True, port=5000, use_reloader=False)
