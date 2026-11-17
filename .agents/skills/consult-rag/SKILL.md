---
name: consult-rag
description: >-
  Direct inquiry to the rag-consultant agent for extraction routing, hybrid
  confidence scoring, SQL allowlist design, or multi-country tax traversal
  questions. Answers in under 300 words.
---

# /consult-rag — RAG and Extraction Routing Specialist

Use this skill when you have a specific technical question about the extraction
pipeline, model routing, or validation logic — before writing any code.

## When to Use
- "Should this document go to GPT-4o-mini or GPT-4o Vision?"
- "How do I handle reverse-charge VAT for a DE vendor?"
- "What SQL query pattern is safe against injection for the invoice filter?"
- "What confidence threshold should trigger the exception queue?"

## Steps

1. **Formulate your question** — be specific: include the vendor country,
   document type, or the FR number if known.

2. **Invoke the rag-consultant agent** (pro tier):
   - Role: `rag-consultant`
   - Brief: "<Your specific question>. Read the relevant source file first.
     Answer in under 300 words. Cite the CLAUDE.md section or source file."

3. **Review the answer** — rag-consultant is read-only. If the answer requires
   a code change, run `/plan` next.

## Notes
- `rag-consultant` uses `pro` tier (gated by `agent_guard.py`).
- Maximum response: 300 words. If the question is too broad, it will ask you
  to narrow it down.
- For implementation, always follow up with `/plan` → `/implement`.

