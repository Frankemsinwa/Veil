"""Tests for KnowledgeVectorVault and REST management endpoints (Phase 2 Local Vector Guardrails)."""
import pytest
import numpy as np
from pathlib import Path
from starlette.testclient import TestClient

from app.main import app
from app.engine.knowledge_vault import KnowledgeVectorVault, KnowledgeVectorEntry


@pytest.fixture
def temp_vault(tmp_path):
    """Provides an isolated KnowledgeVectorVault backed by a temporary directory."""
    vault = KnowledgeVectorVault(storage_dir=tmp_path)
    # Clear any seeded templates for isolated test state
    vault.clear()
    return vault


def test_vault_add_single_entry(temp_vault):
    """Verify adding a single confidential knowledge entry."""
    entry = temp_vault.add_entry(
        title="Project Apollo Internal Specs",
        text="Apollo cluster runs on subnet 10.240.12.0/24 with unauthenticated management API",
        category="INFRASTRUCTURE",
        action="BLOCK",
        threshold_override=0.82
    )

    assert entry.id is not None
    assert entry.title == "Project Apollo Internal Specs"
    assert entry.category == "INFRASTRUCTURE"
    assert entry.action == "BLOCK"
    assert entry.threshold_override == 0.82

    # Verify storage files exist
    assert temp_vault.metadata_path.exists()
    assert temp_vault.vectors_path.exists()
    assert len(temp_vault.get_all_entries()) == 1


def test_vault_embed_document_chunking(temp_vault):
    """Verify document chunking and batch embedding into overlapping sliding windows."""
    doc = (
        "Executive Summary: Q4 Financial Projections. "
        "We forecast net revenue growth of 18% driven by enterprise expansion. "
        "However, hardware supply bottlenecks in Taiwan will compress gross margins by 350 basis points. "
        "Operating expenses will increase by $14M due to datacenter leasing obligations. "
        "The board has approved a contingency reserve of $25M for supply chain relief."
    )

    entries = temp_vault.embed_document(
        title="Q4 Financial Board Report",
        document_text=doc,
        category="FINANCIAL",
        action="BLOCK",
        window_size_sentences=2,
        stride=1
    )

    # Should create multiple overlapping sentence chunks
    assert len(entries) >= 3
    for idx, e in enumerate(entries):
        assert e.parent_doc_title == "Q4 Financial Board Report"
        assert e.chunk_index == idx
        assert "Q4 Financial Board Report" in e.title
        assert len(e.text) > 20

    all_stored = temp_vault.get_all_entries()
    assert len(all_stored) == len(entries)


def test_vault_search_paraphrased_breach(temp_vault):
    """Verify semantic search detects paraphrased confidential concepts."""
    temp_vault.add_entry(
        title="Project Titan Database Bypass",
        text="The primary sharded cluster uses secret ingress port 9443 without mutual TLS encryption.",
        category="INFRASTRUCTURE",
        action="BLOCK",
        threshold_override=0.55
    )
    temp_vault.add_entry(
        title="Public Documentation",
        text="Standard REST API requests must include Bearer token headers.",
        category="SAFE_PUBLIC",
        action="ALLOW",
        threshold_override=0.90
    )

    # Test query using completely different wording describing the same secret
    query = "Our sharded database uses port 9443 without mTLS"
    query_vec = temp_vault.encoder.encode_text(query)

    matches = temp_vault.search(query_vec, top_k=2, min_threshold=0.40)

    assert len(matches) > 0
    top = matches[0]
    assert top.title == "Project Titan Database Bypass"
    assert top.similarity > 0.55
    assert top.is_breach is True
    assert top.action == "BLOCK"


def test_vault_toggle_and_delete_entry(temp_vault):
    """Verify disabling an entry skips it during search, and deletion reorganizes binary storage."""
    e1 = temp_vault.add_entry(title="Secret Alpha", text="Proprietary algorithm weights alpha")
    e2 = temp_vault.add_entry(title="Secret Beta", text="Proprietary algorithm weights beta")

    assert len(temp_vault.get_all_entries()) == 2
    assert temp_vault._vectors.shape[0] == 2

    # Toggle e1 to disabled
    toggled = temp_vault.toggle_entry(e1.id)
    assert toggled.enabled is False

    # Search should now ignore e1
    query_vec = temp_vault.encoder.encode_text("Proprietary algorithm weights alpha")
    matches = temp_vault.search(query_vec, top_k=2, min_threshold=0.50)
    # e1 should not appear in active search
    assert all(m.entry_id != e1.id for m in matches)

    # Delete e1
    deleted = temp_vault.delete_entry(e1.id)
    assert deleted is True
    assert len(temp_vault.get_all_entries()) == 1
    assert temp_vault._vectors.shape[0] == 1
    assert temp_vault.get_all_entries()[0].id == e2.id


def test_vault_stats(temp_vault):
    """Verify vault stats reporting."""
    temp_vault.add_entry(title="Test 1", text="Test confidential snippet 1")
    stats = temp_vault.get_vault_stats()

    assert stats["total_entries"] == 1
    assert stats["active_entries"] == 1
    assert stats["vector_dimensions"] == 384
    assert stats["memory_kb"] > 0
    assert "storage_paths" in stats


def test_rest_api_knowledge_vault_endpoints():
    """Verify FastAPI endpoints for knowledge vault management."""
    client = TestClient(app)

    # 1. GET /api/knowledge-vault
    res = client.get("/api/knowledge-vault")
    assert res.status_code == 200
    data = res.json()
    assert "entries" in data
    assert "stats" in data
    initial_count = len(data["entries"])

    # 2. POST /api/knowledge-vault/entry
    new_entry_payload = {
        "title": "API Test Confidential Memos",
        "text": "Internal legal strategy regarding pending patent dispute in Delaware",
        "category": "LEGAL",
        "action": "BLOCK",
        "threshold_override": 0.80
    }
    res_post = client.post("/api/knowledge-vault/entry", json=new_entry_payload)
    assert res_post.status_code == 200
    post_data = res_post.json()
    assert post_data["success"] is True
    created_id = post_data["entry"]["id"]

    # 3. POST /api/knowledge-vault/test-similarity
    sim_payload = {
        "query": "Legal strategy for the patent dispute litigation",
        "top_k": 3
    }
    res_sim = client.post("/api/knowledge-vault/test-similarity", json=sim_payload)
    assert res_sim.status_code == 200
    sim_data = res_sim.json()
    assert "matches" in sim_data
    assert len(sim_data["matches"]) > 0
    assert sim_data["matches"][0]["title"] == "API Test Confidential Memos"
    assert sim_data["latency_ms"] >= 0

    # 4. POST /api/knowledge-vault/{entry_id}/toggle
    res_toggle = client.post(f"/api/knowledge-vault/{created_id}/toggle")
    assert res_toggle.status_code == 200
    assert res_toggle.json()["enabled"] is False

    # 5. DELETE /api/knowledge-vault/{entry_id}
    res_del = client.delete(f"/api/knowledge-vault/{created_id}")
    assert res_del.status_code == 200
    assert res_del.json()["success"] is True

    # Confirm deleted
    res_after = client.get("/api/knowledge-vault")
    assert len(res_after.json()["entries"]) == initial_count
