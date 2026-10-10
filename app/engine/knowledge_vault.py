"""Enterprise Secret Knowledge Vector Repository (Phase 2 Local Vector Guardrails).

Provides ultra-low-latency, contiguous binary storage (data/knowledge_vectors.bin)
and metadata indexing for proprietary trade secrets, unreleased financial projections,
and internal infrastructure knowledge.
"""
import re
import json
import time
import uuid
import logging
import threading
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any
import numpy as np
from pydantic import BaseModel, Field

from app.core.config import settings
from app.engine.vector_encoder import LocalVectorEncoder, vector_encoder

logger = logging.getLogger("veil.knowledge_vault")


class KnowledgeVectorEntry(BaseModel):
    """Metadata entry for a protected confidential knowledge vector."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:12])
    title: str = Field(description="Descriptive title of the protected document or snippet")
    text: str = Field(description="The confidential text fragment")
    category: str = Field(default="PROPRIETARY", description="Classification category (e.g. FINANCIAL, IP, INFRASTRUCTURE, LEGAL)")
    action: str = Field(default="BLOCK", description="Policy action on match: 'BLOCK' (fail-closed) or 'REDACT' (tokenization)")
    threshold_override: Optional[float] = Field(default=None, description="Optional custom similarity threshold (defaults to policy threshold)")
    enabled: bool = Field(default=True, description="Whether actively evaluated during outbound prompt inspection")
    hit_count: int = Field(default=0, description="Cumulative count of outbound prompt matches")
    chunk_index: int = Field(default=0, description="Sequential index if created via multi-chunk document ingestion")
    parent_doc_title: Optional[str] = Field(default=None, description="Parent document title if document was chunked")
    created_at: float = Field(default_factory=time.time)


class VectorMatchResult(BaseModel):
    """Result of a semantic vector similarity match against the knowledge repository."""
    entry_id: str
    title: str
    text_snippet: str
    category: str
    similarity: float
    action: str  # 'BLOCK', 'REDACT', or 'ALLOW'
    threshold_used: float
    is_breach: bool


class KnowledgeVectorVault:
    """Manages persistent binary storage and high-speed in-memory vector matching."""

    def __init__(
        self,
        storage_dir: Optional[Path] = None,
        encoder: Optional[LocalVectorEncoder] = None
    ):
        self.storage_dir = storage_dir or settings.DATA_DIR
        self.metadata_path = self.storage_dir / "knowledge_metadata.json"
        self.vectors_path = self.storage_dir / "knowledge_vectors.bin"
        self.encoder = encoder or vector_encoder

        self._lock = threading.RLock()
        self._entries: Dict[str, KnowledgeVectorEntry] = {}
        # Contiguous (N, 384) float32 matrix
        self._vectors: np.ndarray = np.empty((0, self.encoder.DIMENSION), dtype=np.float32)
        # 1-to-1 ordering mapping between matrix rows and entry IDs
        self._entry_ids: List[str] = []

        self._load()

    def _load(self) -> None:
        """Loads metadata index and contiguous vector store from disk."""
        with self._lock:
            if not self.metadata_path.exists() or not self.vectors_path.exists():
                self._seed_default_knowledge()
                return

            try:
                with open(self.metadata_path, "r", encoding="utf-8") as f:
                    raw_data = json.load(f)
                
                loaded_entries = {}
                ordered_ids = []
                for item in raw_data:
                    entry = KnowledgeVectorEntry(**item)
                    loaded_entries[entry.id] = entry
                    ordered_ids.append(entry.id)

                num_entries = len(ordered_ids)
                if num_entries > 0:
                    raw_vecs = np.fromfile(self.vectors_path, dtype=np.float32)
                    expected_size = num_entries * self.encoder.DIMENSION
                    if raw_vecs.size == expected_size:
                        self._vectors = raw_vecs.reshape((num_entries, self.encoder.DIMENSION))
                        self._entries = loaded_entries
                        self._entry_ids = ordered_ids
                        logger.info(f"Loaded {num_entries} knowledge vectors into in-memory store from {self.vectors_path}")
                        return
                    else:
                        logger.warning(
                            f"Vector binary file size mismatch (got {raw_vecs.size}, expected {expected_size}). "
                            "Re-embedding entries from metadata text."
                        )

                # If binary was corrupted or empty, re-embed from metadata texts
                self._entries = loaded_entries
                self._entry_ids = ordered_ids
                if loaded_entries:
                    texts = [loaded_entries[eid].text for eid in ordered_ids]
                    self._vectors = self.encoder.encode_batch(texts)
                    self._save_vectors_binary()
            except Exception as e:
                logger.error(f"Error loading knowledge vector repository: {e}. Starting fresh.")
                self._entries = {}
                self._entry_ids = []
                self._vectors = np.empty((0, self.encoder.DIMENSION), dtype=np.float32)

    def _save(self) -> None:
        """Atomically persists both metadata index and contiguous binary vectors."""
        with self._lock:
            try:
                self.storage_dir.mkdir(parents=True, exist_ok=True)
                # 1. Save metadata JSON atomically
                meta_temp = self.metadata_path.with_suffix(".tmp")
                data = [self._entries[eid].model_dump() for eid in self._entry_ids if eid in self._entries]
                with open(meta_temp, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
                meta_temp.replace(self.metadata_path)

                # 2. Save contiguous binary vectors
                self._save_vectors_binary()
            except Exception as e:
                logger.error(f"Failed to persist knowledge vector vault: {e}")

    def _save_vectors_binary(self) -> None:
        """Writes contiguous float32 matrix directly to binary file."""
        vecs_temp = self.vectors_path.with_suffix(".tmp")
        self._vectors.tofile(vecs_temp)
        vecs_temp.replace(self.vectors_path)

    def _seed_default_knowledge(self) -> None:
        """Seeds initial template protected knowledge vectors if repository is new."""
        templates = [
            (
                "Unreleased Q3 Financial Outlook",
                "Internal board forecast projects Q3 operating margin compression of 400 basis points due to APAC component supply delays.",
                "FINANCIAL",
                "BLOCK",
                0.78
            ),
            (
                "Project Titan Cloud Architecture",
                "Our core sharded database cluster utilizes private ingress bypass port 9443 without mutual TLS for internal cluster replication.",
                "INFRASTRUCTURE",
                "BLOCK",
                0.80
            ),
            (
                "Project Nova Acquisition Terms",
                "Strictly confidential preliminary merger agreement with Apex Corporation at $4.2B valuation with 30-day exclusivity.",
                "LEGAL",
                "BLOCK",
                0.82
            )
        ]
        for title, text, cat, action, thresh in templates:
            self.add_entry(
                title=title,
                text=text,
                category=cat,
                action=action,
                threshold_override=thresh,
                enabled=True
            )

    def add_entry(
        self,
        title: str,
        text: str,
        category: str = "PROPRIETARY",
        action: str = "BLOCK",
        threshold_override: Optional[float] = None,
        enabled: bool = True
    ) -> KnowledgeVectorEntry:
        """Embeds a single text snippet and stores it in the knowledge repository."""
        clean_text = text.strip()
        if not clean_text:
            raise ValueError("Entry text cannot be empty")

        with self._lock:
            vec = self.encoder.encode_text(clean_text)
            entry = KnowledgeVectorEntry(
                title=title.strip() or "Confidential Snippet",
                text=clean_text,
                category=category.upper(),
                action=action.upper(),
                threshold_override=threshold_override,
                enabled=enabled
            )

            self._entries[entry.id] = entry
            self._entry_ids.append(entry.id)

            # Append vector to contiguous matrix
            if self._vectors.size == 0:
                self._vectors = vec.reshape((1, self.encoder.DIMENSION))
            else:
                self._vectors = np.vstack([self._vectors, vec.reshape((1, self.encoder.DIMENSION))])

            self._save()
            return entry

    def embed_document(
        self,
        title: str,
        document_text: str,
        category: str = "PROPRIETARY",
        action: str = "BLOCK",
        threshold_override: Optional[float] = None,
        window_size_sentences: int = 2,
        stride: int = 1
    ) -> List[KnowledgeVectorEntry]:
        """Splits a document into overlapping sentence chunks, embeds them, and stores them.
        
        Args:
            title: Document title.
            document_text: Full document or memo text.
            category: Classification category.
            action: 'BLOCK' or 'REDACT'.
            threshold_override: Optional similarity threshold override.
            window_size_sentences: Sentences per sliding window (default: 2).
            stride: Step stride between windows (default: 1 for maximum coverage).
            
        Returns:
            List[KnowledgeVectorEntry]: Created knowledge vector entries.
        """
        chunks = self._chunk_text(document_text, window_size_sentences, stride)
        if not chunks:
            # Fall back to single chunk if short
            chunks = [document_text.strip()]

        with self._lock:
            # Batch encode all chunks simultaneously
            vectors = self.encoder.encode_batch(chunks)
            created_entries = []

            for idx, (chunk_text, vec) in enumerate(zip(chunks, vectors)):
                entry = KnowledgeVectorEntry(
                    title=f"{title.strip()} [Chunk {idx+1}/{len(chunks)}]",
                    text=chunk_text,
                    category=category.upper(),
                    action=action.upper(),
                    threshold_override=threshold_override,
                    enabled=True,
                    chunk_index=idx,
                    parent_doc_title=title.strip()
                )
                self._entries[entry.id] = entry
                self._entry_ids.append(entry.id)
                created_entries.append(entry)

            # Append batch to contiguous vector matrix
            if self._vectors.size == 0:
                self._vectors = vectors
            else:
                self._vectors = np.vstack([self._vectors, vectors])

            self._save()
            logger.info(f"Ingested document '{title}' into {len(created_entries)} vector guardrail chunks")
            return created_entries

    def _chunk_text(self, text: str, window_size: int = 2, stride: int = 1) -> List[str]:
        """Splits text into cohesive sentence-level sliding windows."""
        # Split by paragraph double newlines or punctuation sentence boundaries
        raw_sentences = [s.strip() for s in re.split(r'(?<=[.!?])\s+|\n{2,}', text) if s.strip()]
        if len(raw_sentences) <= window_size:
            return [" ".join(raw_sentences)] if raw_sentences else []

        windows = []
        for i in range(0, len(raw_sentences) - window_size + 1, stride):
            window = " ".join(raw_sentences[i:i + window_size])
            if len(window) >= 20:  # Ignore trivial sentence fragments
                windows.append(window)

        # Include tail if not covered
        tail = " ".join(raw_sentences[-window_size:])
        if tail and (not windows or windows[-1] != tail):
            windows.append(tail)

        return windows

    def delete_entry(self, entry_id: str) -> bool:
        """Deletes a knowledge vector entry and reorganizes contiguous matrix."""
        with self._lock:
            if entry_id not in self._entries:
                return False

            idx = self._entry_ids.index(entry_id)
            del self._entries[entry_id]
            self._entry_ids.pop(idx)

            # Delete row from contiguous matrix
            if self._vectors.shape[0] > 1:
                self._vectors = np.delete(self._vectors, idx, axis=0)
            else:
                self._vectors = np.empty((0, self.encoder.DIMENSION), dtype=np.float32)

            self._save()
            return True

    def toggle_entry(self, entry_id: str) -> Optional[KnowledgeVectorEntry]:
        """Toggles active/inactive state of a knowledge vector entry."""
        with self._lock:
            entry = self._entries.get(entry_id)
            if not entry:
                return None
            entry.enabled = not entry.enabled
            self._save()
            return entry

    def record_hit(self, entry_id: str) -> None:
        """Increments match hit count for an entry."""
        with self._lock:
            entry = self._entries.get(entry_id)
            if entry:
                entry.hit_count += 1
                # Save metadata lazily/periodically or on next write
                self._save()

    def get_all_entries(self) -> List[KnowledgeVectorEntry]:
        """Returns all knowledge vector entries in consistent index order."""
        with self._lock:
            return [self._entries[eid] for eid in self._entry_ids if eid in self._entries]

    def get_entry(self, entry_id: str) -> Optional[KnowledgeVectorEntry]:
        """Retrieves a single entry by ID."""
        with self._lock:
            return self._entries.get(entry_id)

    def search(
        self,
        query_vec: np.ndarray,
        top_k: int = 5,
        min_threshold: float = 0.50
    ) -> List[VectorMatchResult]:
        """Performs ultra-fast SIMD vector-matrix dot product search against all active entries.
        
        Args:
            query_vec: 1D normalized query vector of shape (384,).
            top_k: Maximum number of matches to return.
            min_threshold: Minimum cosine similarity to include in results.
            
        Returns:
            List[VectorMatchResult]: Ordered matches from highest to lowest similarity.
        """
        with self._lock:
            if self._vectors.size == 0 or not self._entry_ids:
                return []

            # Filter active vectors mask
            active_indices = [
                i for i, eid in enumerate(self._entry_ids)
                if eid in self._entries and self._entries[eid].enabled
            ]

            if not active_indices:
                return []

            active_matrix = self._vectors[active_indices]
            sims = self.encoder.similarity_matrix(query_vec, active_matrix)

            # Sort descending
            sort_indices = np.argsort(sims)[::-1]
            results = []

            for rank_idx in sort_indices[:top_k]:
                score = float(sims[rank_idx])
                if score < min_threshold:
                    break

                matrix_idx = active_indices[rank_idx]
                eid = self._entry_ids[matrix_idx]
                entry = self._entries[eid]

                thresh = entry.threshold_override or (
                    settings.VECTOR_SIMILARITY_THRESHOLD_BLOCK if entry.action == "BLOCK"
                    else settings.VECTOR_SIMILARITY_THRESHOLD_WARN
                )

                is_breach = score >= thresh

                results.append(VectorMatchResult(
                    entry_id=entry.id,
                    title=entry.title,
                    text_snippet=entry.text[:120] + ("..." if len(entry.text) > 120 else ""),
                    category=entry.category,
                    similarity=round(score, 4),
                    action=entry.action,
                    threshold_used=thresh,
                    is_breach=is_breach
                ))

            return results

    def evaluate_text(self, text: str) -> Optional[VectorMatchResult]:
        """Embeds text query and checks for any policy threshold breach."""
        clean = text.strip()
        if not clean:
            return None

        query_vec = self.encoder.encode_text(clean)
        matches = self.search(query_vec, top_k=1, min_threshold=0.60)
        if matches and matches[0].is_breach:
            self.record_hit(matches[0].entry_id)
            return matches[0]
        return None

    def get_vault_stats(self) -> Dict[str, Any]:
        """Returns diagnostic health and capacity metrics for the knowledge vault."""
        with self._lock:
            active_count = sum(1 for e in self._entries.values() if e.enabled)
            total_count = len(self._entries)
            memory_bytes = self._vectors.nbytes

            return {
                "total_entries": total_count,
                "active_entries": active_count,
                "vector_dimensions": self.encoder.DIMENSION,
                "memory_kb": round(memory_bytes / 1024.0, 2),
                "is_onnx_active": self.encoder.is_onnx_available,
                "average_inference_latency_ms": round(self.encoder.average_latency_ms, 2),
                "storage_paths": {
                    "metadata": str(self.metadata_path),
                    "vectors": str(self.vectors_path)
                }
            }

    def clear(self) -> None:
        """Clears all stored knowledge vectors."""
        with self._lock:
            self._entries.clear()
            self._entry_ids.clear()
            self._vectors = np.empty((0, self.encoder.DIMENSION), dtype=np.float32)
            self._save()


# Global singleton instance
knowledge_vault = KnowledgeVectorVault()
