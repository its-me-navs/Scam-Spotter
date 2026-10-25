# Scam Spotter (PayNest)

Academic project: a scam-awareness chatbot for **PayNest, a fictional payments app** (not affiliated with any real company).
It compares two ways of building a safety-critical assistant and puts one shared guardrail layer in front of both.

**Research question:** when should a safety-critical system use a generative LLM, and when is verified retrieval safer?

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
python chat.py --phase retrieval          # or llm / hybrid
streamlit run ui/streamlit_app.py
python -m pytest -q tests
python -m eval.run_eval                                              # dev set
python -m eval.run_eval --cases data/heldout_cases.json --tag heldout   # held-out set
```

Phase 1 uses a built-in mock LLM by default so everything runs offline. For a real model:

```bash
export LLM_PROVIDER=anthropic   # or openai
export LLM_MODEL=<model name>   # plus the provider's API key variable
```

## Results (retrieval phase, no LLM)

| set | cases | scam accuracy | wrong answers | safe fallback | correct refusals |
|---|---|---|---|---|---|
| dev (used while tuning) | 52 | 100% | 0% | 0% | 100% |
| held-out (not used for tuning) | 31 | 65% | 0% | 35% | 100% |

The dev score is optimistic because the knowledge base was tuned on it. The held-out score is the honest one:
retrieval never gave a wrong answer, but it fell back on 35% of paraphrased scam descriptions.
That gap is the case for the hybrid router. Run the same sets with `--phases llm hybrid` and a real model to complete the comparison.

## Limitations

- Keyword and regex guardrails can be bypassed by unusual phrasing. They are one layer, not a guarantee.
- The knowledge base is small (10 categories) and English only.
- All support instructions are generic ("in-app Help & Support"). No real phone numbers or procedures are included.
