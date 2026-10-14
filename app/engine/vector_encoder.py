"""Local Dense Vector & Embedding Encoder for Veil Privacy Gateway.

Operates 100% on-device with zero external API calls or network egress.
Uses INT8 quantized all-MiniLM-L6-v2 running on ONNX Runtime CPU with HuggingFace
Rust Fast Tokenizer for sub-15ms dense sentence embeddings.
"""
import sys
import time
import logging
import hashlib
from pathlib import Path
from typing import List, Optional, Union
import numpy as np

from app.core.config import settings

logger = logging.getLogger("veil.vector_encoder")


class LocalVectorEncoder:
    """Ultra-low-latency 100% local dense embedding encoder.
    
    Produces 384-dimensional L2-normalized sentence vectors using INT8
    all-MiniLM-L6-v2 running on ONNX Runtime with automatic fallback resilience.
    """

    DIMENSION: int = 384

    def __init__(self, model_dir: Optional[Union[Path, str]] = None):
        self._custom_model_dir: bool = model_dir is not None
        self.model_dir = Path(model_dir) if model_dir else settings.VECTOR_MODEL_DIR
        self._tokenizer = None
        self._session = None
        self._is_onnx_available = False
        
        # Performance & telemetry counters
        self.total_inferences: int = 0
        self.total_latency_ms: float = 0.0
        self.last_latency_ms: float = 0.0

        self._init_engine()

    def _init_engine(self) -> None:
        """Initialize the ONNX session and fast tokenizer."""
        # Check PyInstaller frozen bundle location first if not a custom directory
        if not self._custom_model_dir and getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
            meipass_model_dir = Path(sys._MEIPASS) / "data" / "models" / "semantic"
            if (meipass_model_dir / "model_quantized.onnx").exists() and (meipass_model_dir / "tokenizer.json").exists():
                self.model_dir = meipass_model_dir

        model_file = self.model_dir / "model_quantized.onnx"
        tokenizer_file = self.model_dir / "tokenizer.json"

        if not model_file.exists() or not tokenizer_file.exists():
            if self._custom_model_dir:
                logger.warning(
                    f"Custom vector guardrail model dir {self.model_dir} missing artifacts. "
                    "Operating in surrogate fallback embedding mode."
                )
                return

            # Check relative fallback path
            alt_dir = Path(__file__).resolve().parent.parent.parent / "data" / "models" / "semantic"
            if (alt_dir / "model_quantized.onnx").exists() and (alt_dir / "tokenizer.json").exists():
                self.model_dir = alt_dir
                model_file = alt_dir / "model_quantized.onnx"
                tokenizer_file = alt_dir / "tokenizer.json"
            else:
                logger.warning(
                    f"Vector guardrail model artifacts not found in {self.model_dir}. "
                    "Operating in surrogate fallback embedding mode."
                )
                return

        try:
            from tokenizers import Tokenizer
            import onnxruntime as ort

            # Load fast Rust tokenizer
            self._tokenizer = Tokenizer.from_file(str(tokenizer_file))
            self._tokenizer.no_padding()
            self._tokenizer.enable_truncation(max_length=128)

            # Configure high-performance ONNX CPU session
            opts = ort.SessionOptions()
            opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
            opts.intra_op_num_threads = 2
            opts.inter_op_num_threads = 1
            opts.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL

            self._session = ort.InferenceSession(
                str(model_file),
                sess_options=opts,
                providers=["CPUExecutionProvider"]
            )
            self._is_onnx_available = True
            logger.info(f"LocalVectorEncoder initialized successfully with INT8 ONNX model from {model_file}")
        except Exception as e:
            logger.warning(
                f"Failed to initialize ONNX Runtime session: {e}. "
                "LocalVectorEncoder falling back to deterministic surrogate encoder."
            )
            self._session = None
            self._tokenizer = None
            self._is_onnx_available = False

    @property
    def is_onnx_available(self) -> bool:
        """Returns True if the INT8 ONNX transformer session is active."""
        return self._is_onnx_available

    @property
    def average_latency_ms(self) -> float:
        """Returns the rolling average inference latency in milliseconds."""
        if self.total_inferences == 0:
            return 0.0
        return self.total_latency_ms / self.total_inferences

    def encode_text(self, text: str) -> np.ndarray:
        """Encodes a single sentence/string into a normalized 384-d dense vector.
        
        Args:
            text: Input string to embed.
            
        Returns:
            np.ndarray: 1D float32 array of shape (384,) with unit L2 norm.
        """
        batch = self.encode_batch([text])
        return batch[0]

    def encode_batch(self, texts: List[str]) -> np.ndarray:
        """Encodes a batch of sentences into a normalized (B, 384) dense matrix.
        
        Args:
            texts: List of input strings.
            
        Returns:
            np.ndarray: 2D float32 array of shape (len(texts), 384) with unit L2 rows.
        """
        if not texts:
            return np.empty((0, self.DIMENSION), dtype=np.float32)

        start_time = time.perf_counter()

        if self._is_onnx_available and self._session is not None and self._tokenizer is not None:
            try:
                embeddings = self._encode_onnx(texts)
            except Exception as e:
                logger.error(f"ONNX inference failure: {e}. Falling back to surrogate encoder.")
                embeddings = self._encode_surrogate(texts)
        else:
            embeddings = self._encode_surrogate(texts)

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        self.last_latency_ms = elapsed_ms
        self.total_latency_ms += elapsed_ms
        self.total_inferences += len(texts)

        return embeddings

    def _encode_onnx(self, texts: List[str]) -> np.ndarray:
        """Runs INT8 ONNX tokenization, inference, mean pooling, and L2 normalization."""
        encoded_batch = self._tokenizer.encode_batch(texts)
        
        # Find maximum length in this batch for minimal dynamic padding
        max_len = max(len(enc.ids) for enc in encoded_batch)
        max_len = max(1, min(max_len, 128))

        batch_size = len(texts)
        input_ids = np.zeros((batch_size, max_len), dtype=np.int64)
        attention_mask = np.zeros((batch_size, max_len), dtype=np.int64)
        token_type_ids = np.zeros((batch_size, max_len), dtype=np.int64)

        for i, enc in enumerate(encoded_batch):
            seq_len = min(len(enc.ids), max_len)
            input_ids[i, :seq_len] = enc.ids[:seq_len]
            attention_mask[i, :seq_len] = enc.attention_mask[:seq_len]
            token_type_ids[i, :seq_len] = enc.type_ids[:seq_len]

        inputs = {
            "input_ids": input_ids,
            "attention_mask": attention_mask,
            "token_type_ids": token_type_ids,
        }

        outputs = self._session.run(None, inputs)
        token_embeddings = outputs[0]  # Shape: (batch_size, seq_len, 384)

        # Mean Pooling - Take attention mask into account for correct averaging
        input_mask_expanded = np.broadcast_to(
            np.expand_dims(attention_mask, -1),
            token_embeddings.shape
        )
        sum_embeddings = np.sum(token_embeddings * input_mask_expanded, axis=1)
        sum_mask = np.clip(input_mask_expanded.sum(axis=1), a_min=1e-9, a_max=None)
        mean_embeddings = sum_embeddings / sum_mask

        # L2 Normalization
        norms = np.linalg.norm(mean_embeddings, axis=1, keepdims=True)
        norms = np.clip(norms, a_min=1e-12, a_max=None)
        normalized = mean_embeddings / norms

        return normalized.astype(np.float32)

    def _encode_surrogate(self, texts: List[str]) -> np.ndarray:
        """Deterministic, zero-dependency semantic surrogate encoder.
        
        Uses feature hashing with n-gram pseudo-semantic projections and subword
        character hashing to produce reproducible 384-d unit vectors when ONNX is absent.
        """
        matrix = np.zeros((len(texts), self.DIMENSION), dtype=np.float32)

        for i, text in enumerate(texts):
            clean = text.lower().strip()
            if not clean:
                # Neutral baseline vector
                vec = np.ones(self.DIMENSION, dtype=np.float32)
                matrix[i] = vec / np.linalg.norm(vec)
                continue

            words = clean.split()
            vec = np.zeros(self.DIMENSION, dtype=np.float32)

            for w in words:
                # Hash word to dimensional buckets
                h_val = int(hashlib.sha256(w.encode("utf-8")).hexdigest(), 16)
                idx = h_val % self.DIMENSION
                sign = 1.0 if (h_val >> 8) & 1 else -1.0
                vec[idx] += sign

                # Subword 3-grams for morphological resilience
                if len(w) >= 3:
                    for j in range(len(w) - 2):
                        sub = w[j:j+3]
                        sub_h = int(hashlib.md5(sub.encode("utf-8")).hexdigest(), 16)
                        sub_idx = sub_h % self.DIMENSION
                        sub_sign = 0.5 if (sub_h >> 4) & 1 else -0.5
                        vec[sub_idx] += sub_sign

            norm = np.linalg.norm(vec)
            if norm > 1e-12:
                matrix[i] = vec / norm
            else:
                matrix[i] = np.ones(self.DIMENSION, dtype=np.float32) / np.sqrt(self.DIMENSION)

        return matrix

    @staticmethod
    def cosine_similarity(vec1: np.ndarray, vec2: np.ndarray) -> float:
        """Calculates cosine similarity between two 1D L2-normalized vectors.
        
        Because both vectors are unit normalized (norm == 1.0), this is a single dot product.
        """
        dot = float(np.dot(vec1, vec2))
        return max(-1.0, min(1.0, dot))

    @staticmethod
    def similarity_matrix(query_vec: np.ndarray, matrix: np.ndarray) -> np.ndarray:
        """Computes cosine similarity between a 1D query vector and a 2D knowledge matrix.
        
        Args:
            query_vec: 1D normalized query vector of shape (384,)
            matrix: 2D normalized knowledge matrix of shape (N, 384)
            
        Returns:
            np.ndarray: 1D array of similarity scores of shape (N,)
        """
        if matrix.size == 0:
            return np.empty((0,), dtype=np.float32)
        sims = np.dot(matrix, query_vec)
        return np.clip(sims, -1.0, 1.0).astype(np.float32)


# Global singleton instance
vector_encoder = LocalVectorEncoder()
