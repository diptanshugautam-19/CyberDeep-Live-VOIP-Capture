# Starting CyberDeep

Use this guide to start the CyberDeep backend and application interface.

## 🐍 1. Start the API Server & Application

Open a terminal in the root of the project (`d:\cyberdeep`) and run:

```powershell
.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

---

## 🌐 2. Application URLs

Once the server is running, access the following endpoints in your browser:

- **Main Application:** [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Interactive OpenAPI Documentation:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Liveness Health Check:** [http://127.0.0.1:8000/healthz](http://127.0.0.1:8000/healthz)

> **Note:** The frontend application (HTML/CSS/JS) is served directly by the FastAPI backend server under static/template routes. No separate `npm` or Vite server is required.
