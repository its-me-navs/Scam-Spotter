# Scam Spotter (PayNest)

Academic project: a scam-awareness chatbot for **PayNest, a fictional payments app** (not affiliated with any real company).
It compares two ways of building a safety-critical assistant and puts one shared guardrail layer in front of both.

**Research question:** when should a safety-critical system use a generative LLM, and when is verified retrieval safer?

## Current status

**Only Phase 1 (LLM chatbot) is enabled.** The Phase 2 retrieval code and the hybrid router are in the repo but switched off in the CLI and UI.
To enable them for a later demo, set `SCAMSPOTTER_PHASES=llm,retrieval` (or `llm,retrieval,hybrid`), or edit `DEFAULT_PHASES` in `app/config.py`.

## Architecture

```
user query -> input guardrails -> phase -> output guardrails -> reply
              (validate, redact,   retrieval | llm | hybrid     (no OTP/PIN requests,
               injection, harm,                                    no invented contacts)
               scope checks)
```

- **Phase 1 (`llm`)**: LLM answers, grounded in the knowledge base, returns JSON, checked by output guardrails. Provider is model-agnostic.
- **Phase 2 (`retrieval`)**: retrieval-based chatbot, no generative AI. TF-IDF + keyword blend, similarity threshold and margin, safe fallback.
- **Hybrid**: retrieval answers when confident; the LLM is called only for unclear queries.
- **Guardrails (`app/guardrails.py`)**: shared by all phases. Input validation, OTP/PIN/card redaction before anything reaches a model, prompt-injection and harmful-request checks, scope check, output checks.

## Run

```bash
pip install -r requirements.txt
python chat.py                            # Phase 1 only, by default
streamlit run ui/streamlit_app.py
SCAMSPOTTER_PHASES=llm,retrieval streamlit run ui/streamlit_app.py   # later: show Phase 2 too
python -m pytest -q tests
python -m eval.run_eval                                              # Phase 1, dev set
python -m eval.run_eval --cases data/heldout_cases.json --tag heldout   # Phase 1, held-out set
python -m eval.run_eval --phases llm retrieval hybrid                 # compare all phases
```

Phase 1 uses a built-in mock LLM by default so everything runs offline. For a real model:

Copy `.env.example` to `.env` and fill in your provider, key and model. The app loads it automatically, and `.env` is git-ignored so your key stays off GitHub.
(Setting the same names as environment variables also works, and takes priority over `.env`.)

## Languages (English, Hindi, Kannada)

Type in Hindi (Devanagari) or Kannada script and the reply comes back in the same language. Detection is by script, so it works offline.
Each language has its own retrieval index, guardrail patterns (injection, harmful request, OTP/PIN redaction including Hindi/Kannada digits) and output checks.
The sidebar (or `--lang hi|kn|en` in the CLI) can force the reply language, which is the way to handle Hindi/Kannada typed in English letters ("Hinglish"); that is **not** auto-detected.

## Live pipeline trace

Both the UI and `python chat.py` show what happens to each message, step by step: language detected, sensitive data found and
**replaced before anything else sees it**, injection/harm/scope checks, retrieval or model call, output check. The exact text the
model receives is shown (already redacted), then the checked answer is streamed.
The answer is only streamed after output guardrails pass it; the raw OTP/PIN is never displayed, stored or sent.
Use the sidebar slider to slow the steps down for a demo.

## Results (Phase 2 retrieval only; recorded for the later comparison)

Run: `python -m eval.run_eval --cases data/test_cases.json data/test_cases_indic.json --phases retrieval`
(and the `heldout_*` files for the held-out set).

| set | cases | scam accuracy | wrong answers | safe fallback | correct refusals |
|---|---|---|---|---|---|
| dev (used while tuning) | 95 (63 en, 16 hi, 16 kn) | 97% | 2% (2 cases) | 2% | 100% |
| held-out | 69 (37 en, 16 hi, 16 kn) | 72% | 2% | 26% | 100% |

Per language, cases fully correct: dev en 63/63, hi 15/16, kn 15/16; held-out en 30/37, hi 13/16, kn 12/16.

Caveats, please state them if you present these numbers:
- The dev score is optimistic because the knowledge base was tuned on it. The held-out score is the honest one:
  retrieval rarely answered wrongly but fell back on about a quarter of paraphrased scam descriptions. That gap motivates the hybrid router.
- The Hindi/Kannada held-out set was written by me (an AI), not by native speakers. After the first held-out run, three guardrail
  gaps (Hindi/Kannada injection and harmful-request wording) were fixed, so the held-out refusal score of 100% is no longer a clean
  blind result for those categories.
- Mock-LLM numbers are not real LLM results. Run with a real key in `.env` (`--phases llm hybrid`) to complete the comparison.

## Sources and accuracy

The scam patterns and advice in `data/knowledge_base.json` are paraphrased from public Indian sources, listed with dates and links in the file's `sources` field (checked 2026-11-10). Each source is marked `current` (published 2025 or later) or `foundational` (older guidance that is still the best official source for that scam type).

Current (2025-26):
- RBI discussion paper, 9 Apr 2026: safeguards in digital payments to curb frauds
- PIB, 10 Feb 2026: national conference on cyber-enabled frauds
- PIB, 5 Feb 2026: Chakshu facility of Sanchar Saathi (reporting suspected fraud calls and messages)
- PIB, 24 Dec 2025: RBI cyber fraud awareness programmes
- PIB, 2 Dec 2025: Sanchar Saathi app
- PIB, 8 Oct 2025: Curbing Cyber Frauds in Digital India

Foundational:
- PIB, 10 Dec 2024: government alert on "digital arrest" scams
- RBI press releases (Feb 2024, Jan 2022, Sep 2021) and the BE(A)WARE booklet
- CERT-In awareness booklet, Oct 2023

No 2025-26 official source specific to refund links, "send Rs 1 to receive money", QR / collect-request scams, prize scams or job scams was found, so those entries rest on the foundational sources.
RBI's March 2026 draft revision of the customer-liability rules is not used, because it is still a draft.

Each entry has `source_ids`, and the UI shows which sources a reply is based on. PayNest itself is fictional, so its app screens, support channel and policies are invented.
The only real-world contacts the bot may mention are the National Cyber Crime Reporting Portal (cybercrime.gov.in), the cybercrime helpline 1930 and the Sanchar Saathi portal (sancharsaathi.gov.in). The output guardrail blocks any other website or helpline number as possibly invented.
Official contact details and procedures can change, so the answers tell users to confirm them on the official sites.
NPCI's own safety pages could not be read automatically during research, so they are not cited.

## Limitations

- Keyword and regex guardrails can be bypassed by unusual phrasing. They are one layer, not a guarantee.
- The knowledge base is small (12 categories).
- Hindi and Kannada text (answers, example queries, guardrail patterns) was written by an AI and has **not been reviewed by native speakers**. Have it reviewed before real use.
- Hinglish / Kannada in Roman letters is detected as English unless you pick the reply language by hand.
- Only Hindi, Kannada and English are supported; other scripts are treated as English.
- All support instructions are generic ("in-app Help & Support"). No real phone numbers or procedures are included.
