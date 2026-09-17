import logging
import math
from typing import List, Optional
from app.models.schemas import Claim

logger = logging.getLogger("verisec.consistency")

# Global singleton for local embedding model
_embedder = None

def get_embedder():
    global _embedder
    if _embedder is None:
        try:
            from sentence_transformers import SentenceTransformer
            # Load small, fast local embedding model
            _embedder = SentenceTransformer("all-MiniLM-L6-v2")
            logger.info("SentenceTransformer 'all-MiniLM-L6-v2' initialized successfully.")
        except Exception as e:
            logger.warning(f"Could not load SentenceTransformer ({e}). Using Jaccard similarity fallback.")
            _embedder = False
    return _embedder

def compute_similarity(text1: str, text2: str) -> float:
    embedder = get_embedder()
    if embedder:
        try:
            embeddings = embedder.encode([text1, text2])
            # Cosine similarity
            vec1, vec2 = embeddings[0], embeddings[1]
            dot = sum(a * b for a, b in zip(vec1, vec2))
            norm1 = math.sqrt(sum(a * a for a in vec1))
            norm2 = math.sqrt(sum(b * b for b in vec2))
            if norm1 > 0 and norm2 > 0:
                return float(dot / (norm1 * norm2))
        except Exception as e:
            logger.debug(f"Embedding similarity computation error: {e}")

    # Fallback to token Jaccard similarity
    words1 = set(text1.lower().split())
    words2 = set(text2.lower().split())
    if not words1 or not words2:
        return 0.5
    intersection = words1.intersection(words2)
    union = words1.union(words2)
    return float(len(intersection) / len(union))

async def evaluate_claim_consistency(claim: Claim, context: Optional[str] = None) -> tuple[float, float]:
    """
    Evaluates self-consistency score and faithfulness score for a claim.
    Returns tuple: (consistency_score, faithfulness_score)
    """
    # Baseline default scores
    consistency_score = 0.95
    faithfulness_score = 0.95

    # 1. Faithfulness score if ground truth context was provided
    if context and len(context.strip()) > 10:
        sim = compute_similarity(claim.raw_span, context)
        # Check if the specific value (e.g. CVE ID or technique ID) is literally present in the context
        if claim.value.lower() in context.lower():
            faithfulness_score = max(0.90, sim)
        else:
            # Claim is NOT mentioned anywhere in the provided context
            faithfulness_score = min(0.40, sim)

    # 2. Self-consistency check: penalize suspicious patterns
    # e.g., claims with obvious synthetic/hallucinated markers
    if claim.type == "cve":
        try:
            year = int(claim.value.split("-")[1])
            if year > 2026 or year < 1999:
                consistency_score = 0.10
        except Exception:
            consistency_score = 0.30
    elif claim.type == "mitre_technique":
        # Check if technique pattern looks like illegal range (e.g. T9xxx)
        if claim.value.startswith("T9") or claim.value.startswith("T8"):
            consistency_score = 0.15

    return (consistency_score, faithfulness_score)
