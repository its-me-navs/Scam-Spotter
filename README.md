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

## Results (Phase 2 retrieval, recorded for the later comparison)

| set | cases | scam accuracy | wrong answers | safe fallback | correct refusals |
|---|---|---|---|---|---|
| dev (used while tuning) | 52 | 100% | 0% | 0% | 100% |
| held-out (not used for tuning) | 31 | 65% | 0% | 35% | 100% |

The dev score is optimistic because the knowledge base was tuned on it. The held-out score is the honest one:
retrieval never gave a wrong answer, but it fell back on 35% of paraphrased scam descriptions.
That gap is the case for the hybrid router. Run the same sets with `--phases llm hybrid` and a real model to complete the comparison.

## Sources and accuracy

The scam patterns and advice in `data/knowledge_base.json` are paraphrased from public Indian sources, listed with dates and links in the file's `sources` field (checked 2026-10-27):

- RBI press release, 13 Sep 2021: frauds in the name of KYC updation
- RBI press release, 28 Jan 2022: Consumer Awareness - Cyber Threats and Frauds
- RBI press release, 2 Feb 2024: KYC updation fraud caution (reissued)
- RBI BE(A)WARE booklet on the modus operandi of financial fraudsters (undated)
- PIB explainer, 8 Oct 2025: Curbing Cyber Frauds in Digital India

Each entry has `source_ids`, and the UI shows which sources a reply is based on. PayNest itself is fictional, so its app screens, support channel and policies are invented.
The only real-world contacts the bot may mention are the National Cyber Crime Reporting Portal (cybercrime.gov.in) and the cybercrime helpline 1930. The output guardrail blocks any other website or helpline number as possibly invented.
Official contact details and procedures can change, so the answers tell users to confirm them on the official sites.
NPCI's own safety pages could not be read automatically during research, so they are not cited.

## Limitations

- Keyword and regex guardrails can be bypassed by unusual phrasing. They are one layer, not a guarantee.
- The knowledge base is small (10 categories) and English only.
- All support instructions are generic ("in-app Help & Support"). No real phone numbers or procedures are included.
