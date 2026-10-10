"""Comprehensive tests for LocalVectorEncoder (Phase 1 Local Vector Guardrails)."""
import pytest
import numpy as np
from pathlib import Path
from app.engine.vector_encoder import LocalVectorEncoder, vector_encoder


def test_vector_encoder_initialization_and_metadata():
    """Verify encoder initializes and reports 384 dimensions."""
    assert vector_encoder.DIMENSION == 384
    assert vector_encoder.is_onnx_available is True


def test_encode_single_text():
    """Verify single text encodes into a normalized 1D 384 float32 vector."""
    text = "Confidential acquisition terms for Project Titan with buyout valuation at $4.2B"
    vec = vector_encoder.encode_text(text)

    assert isinstance(vec, np.ndarray)
    assert vec.shape == (384,)
    assert vec.dtype == np.float32

    # Verify L2 norm equals 1.0 within floating point precision
    norm = np.linalg.norm(vec)
    assert pytest.approx(norm, abs=1e-5) == 1.0


def test_encode_batch_texts():
    """Verify batch encoding produces (B, 384) normalized matrix."""
    texts = [
        "First confidential revenue forecast snippet",
        "Second proprietary cluster infrastructure bypass",
        "Third safe public developer documentation line"
    ]
    matrix = vector_encoder.encode_batch(texts)

    assert matrix.shape == (3, 384)
    assert matrix.dtype == np.float32

    for i in range(3):
        norm = np.linalg.norm(matrix[i])
        assert pytest.approx(norm, abs=1e-5) == 1.0


def test_semantic_cosine_similarity_paraphrase():
    """Verify semantic paraphrases have high similarity and unrelated sentences have low similarity."""
    target = "Our Q3 operating margins are expected to compress by 400 basis points due to APAC delays."
    paraphrase = "The company expects operating margins to decline by 400 basis points in Q3."
    unrelated = "Python asynchronous coroutines can be scheduled concurrently on the event loop."

    vec_target = vector_encoder.encode_text(target)
    vec_para = vector_encoder.encode_text(paraphrase)
    vec_unrelated = vector_encoder.encode_text(unrelated)

    sim_para = vector_encoder.cosine_similarity(vec_target, vec_para)
    sim_unrelated = vector_encoder.cosine_similarity(vec_target, vec_unrelated)

    # Paraphrased version should have strong semantic similarity (> 0.65)
    assert sim_para > 0.65, f"Expected high similarity for paraphrase, got {sim_para}"

    # Unrelated technical sentence should have low similarity (< 0.25)
    assert sim_unrelated < 0.25, f"Expected low similarity for unrelated text, got {sim_unrelated}"
    assert sim_para > sim_unrelated + 0.35


def test_similarity_matrix_fast_dot_product():
    """Verify similarity_matrix performs fast vector-matrix dot product matching."""
    knowledge_texts = [
        "Strictly confidential merger agreement with Apex Corp",
        "Internal Kubernetes cluster topology using port 9443",
        "Employee compensation bands for engineering directors",
        "Public instructions on using git rebase"
    ]
    knowledge_matrix = vector_encoder.encode_batch(knowledge_texts)

    query = "The acquisition terms for Apex Corporation are strictly private."
    query_vec = vector_encoder.encode_text(query)

    scores = vector_encoder.similarity_matrix(query_vec, knowledge_matrix)

    assert scores.shape == (4,)
    # Apex merger document should have the highest similarity score
    top_match_idx = int(np.argmax(scores))
    assert top_match_idx == 0, f"Expected index 0 (Apex Corp) to be top match, got {top_match_idx} with score {scores[0]}"
    assert scores[0] > 0.60


def test_surrogate_fallback_resilience(tmp_path):
    """Verify that when ONNX files are absent, surrogate encoder functions gracefully."""
    empty_dir = tmp_path / "empty_models"
    empty_dir.mkdir()

    fallback_encoder = LocalVectorEncoder(model_dir=empty_dir)
    assert fallback_encoder.is_onnx_available is False

    # Should still encode without error
    vec1 = fallback_encoder.encode_text("Confidential financial memo")
    vec2 = fallback_encoder.encode_text("Confidential financial statement")
    vec_other = fallback_encoder.encode_text("The sky is blue today")

    assert vec1.shape == (384,)
    assert pytest.approx(np.linalg.norm(vec1), abs=1e-5) == 1.0

    sim_similar = fallback_encoder.cosine_similarity(vec1, vec2)
    sim_diff = fallback_encoder.cosine_similarity(vec1, vec_other)

    assert sim_similar > sim_diff


def test_encoder_latency_budget():
    """Verify single sentence inference latency is fast and well within wire budget."""
    text = "Internal architecture uses unencrypted staging bridge"
    
    # Warm run
    for _ in range(3):
        _ = vector_encoder.encode_text(text)
    
    latencies = []
    for _ in range(5):
        _ = vector_encoder.encode_text(text)
        latencies.append(vector_encoder.last_latency_ms)

    avg_ms = float(np.mean(latencies))
    min_ms = float(np.min(latencies))
    # Minimum latency demonstrates single-thread peak throughput (< 25ms)
    assert min_ms < 25.0, f"Expected peak latency < 25ms, got {min_ms:.2f}ms"
    assert avg_ms < 40.0, f"Expected average latency < 40ms, got {avg_ms:.2f}ms"
