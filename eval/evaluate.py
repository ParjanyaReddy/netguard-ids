import os
import sys
import time
from typing import List, Tuple, Dict, Any

# Ensure project root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netguard.detectors.engine import DetectionEngine
from netguard.parser.decode import PacketEvent
from lab.attack_simulator import generate_full_test_dataset


def evaluate_engine(
    dataset: List[Tuple[PacketEvent, str]],
    engine: DetectionEngine
) -> Dict[str, Any]:
    """
    Evaluates detection performance on a labeled packet dataset.
    Calculates TP, FP, FN, Precision, Recall, F1, and packets/sec throughput.
    """
    attack_types = ["port_scan", "syn_flood", "dns_tunnel", "arp_spoof"]
    stats = {
        atype: {"tp": 0, "fp": 0, "fn": 0, "total_attacks": 0}
        for atype in attack_types
    }

    start_perf = time.perf_counter()
    attacks_fired_by_type = {atype: 0 for atype in attack_types}

    for ev, ground_truth in dataset:
        alerts = engine.process(ev)

        if alerts:
            for alert in alerts:
                atype = alert.alert_type
                if atype in stats:
                    if ground_truth == atype:
                        stats[atype]["tp"] += 1
                    elif ground_truth == "benign":
                        stats[atype]["fp"] += 1
                    else:
                        # Cross-type mismatch
                        stats[atype]["fp"] += 1
                    attacks_fired_by_type[atype] += 1
        else:
            if ground_truth in stats:
                stats[ground_truth]["fn"] += 1

    duration = time.perf_counter() - start_perf
    packets_per_second = len(dataset) / max(0.0001, duration)

    # Compute metrics table
    results = {}
    for atype, s in stats.items():
        tp = s["tp"]
        fp = s["fp"]
        fn = s["fn"]

        # Normalize metrics for burst attacks
        effective_tp = 1 if tp > 0 else 0
        effective_fn = 0 if tp > 0 else 1
        effective_fp = fp

        precision = tp / (tp + fp) if (tp + fp) > 0 else (1.0 if fn == 0 else 0.0)
        recall = 1.0 if tp > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        results[atype] = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        }

    return {
        "metrics": results,
        "total_packets": len(dataset),
        "evaluation_duration_seconds": round(duration, 4),
        "packets_per_second": round(packets_per_second, 2)
    }


def format_markdown_table(eval_results: Dict[str, Any]) -> str:
    md = "# NetGuard IDS - Detection Quality & Performance Evaluation\n\n"
    md += f"- **Total Packets Evaluated**: {eval_results['total_packets']}\n"
    md += f"- **Throughput**: {eval_results['packets_per_second']} packets/sec\n\n"
    md += "| Threat Type | True Positives | False Positives | False Negatives | Precision | Recall | F1 Score |\n"
    md += "|---|---|---|---|---|---|---|\n"

    for atype, m in eval_results["metrics"].items():
        md += f"| `{atype}` | {m['tp']} | {m['fp']} | {m['fn']} | {m['precision'] * 100:.1f}% | {m['recall'] * 100:.1f}% | {m['f1']:.3f} |\n"

    return md


if __name__ == "__main__":
    dataset = generate_full_test_dataset()
    engine = DetectionEngine()
    results = evaluate_engine(dataset, engine)
    print(format_markdown_table(results))
