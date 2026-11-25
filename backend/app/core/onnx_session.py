"""Memory-safe CPU SessionOptions factory for ONNX Runtime on Linux/Windows."""

from __future__ import annotations

import onnxruntime as ort


def build_cpu_session_options(intra_threads: int = 4) -> ort.SessionOptions:
    """Create ONNX SessionOptions with CPU memory arena & pattern disabled to prevent RSS retention."""
    opts = ort.SessionOptions()
    opts.enable_cpu_mem_arena = False
    opts.enable_mem_pattern = False
    opts.intra_op_num_threads = max(1, intra_threads)
    opts.inter_op_num_threads = 1
    opts.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
    opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
    return opts
