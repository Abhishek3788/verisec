import os
import json
import pytest
import asyncio
import logging
from app.models.schemas import Claim, ClaimType, VerdictType
from app.routers.analyze import process_single_claim

logger = logging.getLogger("verisec.test_metrics")

@pytest.mark.asyncio
async def test_end_to_end_metrics():
    dataset_path = os.path.join(os.path.dirname(__file__), "test_dataset.json")
    with open(dataset_path, "r", encoding="utf-8") as f:
        items = json.load(f)

    tp = 0  # Real claim passed/flagged
    fn = 0  # Real claim wrongly blocked
    tn = 0  # Fake claim blocked
    fp = 0  # Fake claim passed/flagged

    print("\n" + "="*70)
    print(" VERISEC HALLUCINATION FIREWALL - BENCHMARK EVALUATION ")
    print("="*70)

    for item in items:
        claim_type_str = item["claim_type"]
        val = item["value"]
        is_real = item["is_real"]

        claim = Claim(
            type=ClaimType(claim_type_str),
            value=val,
            raw_span=val
        )

        res = await process_single_claim(claim)
        predicted_verdict = res.verdict

        # Evaluate metric classification
        if is_real:
            if predicted_verdict in (VerdictType.PASS, VerdictType.FLAG):
                tp += 1
                status_symbol = "[OK PASS]"
            else:
                fn += 1
                status_symbol = "[FAIL FALSE_BLOCK]"
        else:
            if predicted_verdict == VerdictType.BLOCK:
                tn += 1
                status_symbol = "[OK BLOCKED_HALLUC]"
            else:
                fp += 1
                status_symbol = "[FAIL UNCAUGHT]"

        print(f"[{status_symbol:<20}] Type: {claim_type_str:<15} Claim: {val:<25} Pred: {predicted_verdict.value}")

    total = len(items)
    accuracy = (tp + tn) / total if total > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    hallucination_block_rate = tn / (tn + fp) if (tn + fp) > 0 else 0.0

    print("-" * 70)
    print(f" TOTAL EVALUATED        : {total}")
    print(f" ACCURACY               : {accuracy*100:.2f}%")
    print(f" PRECISION              : {precision*100:.2f}%")
    print(f" RECALL                 : {recall*100:.2f}%")
    print(f" F1 SCORE               : {f1*100:.2f}%")
    print(f" HALLUCINATION BLOCK RATE: {hallucination_block_rate*100:.2f}%")
    print("=" * 70 + "\n")

    assert accuracy >= 0.85, f"Accuracy expected >= 85%, got {accuracy*100:.2f}%"
    assert f1 >= 0.85, f"F1 Score expected >= 85%, got {f1*100:.2f}%"

if __name__ == "__main__":
    asyncio.run(test_end_to_end_metrics())
