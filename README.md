# 🛡️ ForgeShield — Document Forgery Detection System

**Hackathon:** Secure AI Software and Systems Hackathon 2026
**Organizers:** IIT Madras × BITS Goa (ISEA Phase-III)
**Challenge:** Problem Statement 3 — Document Forgery Detection (Blue Team)

---

## ⚡ Quick Start (3 steps)

### Step 1 — Install dependencies
Open this folder in VS Code, open the Terminal (Ctrl + `) and run:
```
pip install -r requirements.txt
```

### Step 2 — Add your Gemini API key
Open `app.py`, find line 13 and replace:
```python
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "YOUR_GEMINI_API_KEY_HERE")
```
with your actual key:
```python
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "AIza...your-real-key...")
```

### Step 3 — Run the app
```
python app.py
```
Open browser → http://localhost:5000

---

## ✅ All Challenge Requirements Met

| Requirement | Implementation |
|---|---|
| OCR + ML for text integrity | Gemini vision extracts & checks all text |
| Signature & seal verification | Dedicated authenticity scores (0-100) |
| Blockchain integration | SHA-256 block with merkle root per analysis |
| Forensic report with confidence scores | Downloadable .txt report + dashboard |
| Multi-modal visual + textual analysis | 6-layer pipeline fusing both modalities |

## 📂 All 5 Recommended Datasets
See the **Datasets tab** in the app for full descriptions and links to:
1. NaviDoMass Forgery Dataset
2. FD-VIED Dataset
3. CASIA Image Tampering Dataset
4. DocTamper Dataset (170k documents)
5. Document Forgery Detection Dataset (Roboflow)

## 🗂 Project Structure
```
forgery-detector/
├── app.py              ← Flask backend + Gemini API + report export
├── requirements.txt    ← Python dependencies
├── README.md
└── templates/
    └── index.html      ← Full frontend (Analyze + Datasets + Methodology tabs)
```

## 🆓 Everything Is Free & Local
- Flask — free Python web framework
- Gemini 1.5 Flash — free tier (15 req/min, 1M tokens/day)
- PyMuPDF — free PDF processing
- No cloud services, no billing, runs entirely on your laptop

---
*Secure AI Software and Systems Hackathon 2026 — IIT Madras × BITS Goa*
