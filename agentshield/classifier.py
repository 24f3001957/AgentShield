"""Policy-aware advisory classifier for proposed tool calls.

A deliberately small model: TF-IDF over policy-shaped features and a
multinomial logistic-regression head, implemented here in plain Python (no
NumPy/sklearn dependency) so the prototype stays installable anywhere.

What it is for
--------------
The classifier is **advisory only**. It never authorises anything and it never
changes a verdict: :class:`agentshield.gateway.Gateway` still runs validation,
policy, approval and authorization exactly as before, and only records the
advisory alongside the authoritative decision. A confident "allow" prediction
cannot make the gateway execute a denied call, and a confident "deny"
prediction cannot stop an allowed one on its own.

It abstains when the signal is weak (low probability, small margin between the
top two classes, or too many features never seen in training). An abstention is
the safe fallback: the deterministic policy remains the only decision maker.

Metrics are reported for a deterministic held-out split of the bundled fixture
set and labelled as such. They are *not* external benchmark results.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

from .models import POLICY_VERSION
from .tools import APPROVED_DESTINATIONS, INTERNAL_DOMAINS, TOOL_REGISTRY

#: Version string for the feature extractor + model recipe.
MODEL_VERSION = "policy-classifier-tfidf-lr-v1"

#: Minimum top-class probability for a non-abstaining prediction.
CONFIDENCE_THRESHOLD = 0.50

#: Minimum gap between the top two class probabilities.
MARGIN_THRESHOLD = 0.05

#: Fraction of unseen features above which the input is treated as unfamiliar.
OOV_THRESHOLD = 0.5

_DATASET_PATH = Path(__file__).with_name("data") / "classifier_fixtures.json"

LABELS: tuple[str, ...] = ("allow", "approval", "ambiguous", "deny")
UNSAFE_LABELS = frozenset({"deny", "approval"})


@dataclass(frozen=True)
class Prediction:
    """One advisory prediction plus the evidence needed to review it."""

    label: str
    confidence: float
    margin: float
    abstained: bool
    reason: str | None
    probabilities: dict[str, float]

    @property
    def decision_hint(self) -> str:
        return "abstain" if self.abstained else self.label

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_version": MODEL_VERSION,
            "policy_version": POLICY_VERSION,
            "prediction": self.label,
            "decision_hint": self.decision_hint,
            "confidence": round(self.confidence, 4),
            "margin": round(self.margin, 4),
            "abstained": self.abstained,
            "reason": self.reason,
            "probabilities": {
                name: round(value, 4) for name, value in self.probabilities.items()
            },
            "threshold": CONFIDENCE_THRESHOLD,
            "margin_threshold": MARGIN_THRESHOLD,
            "authority": "advisory only; the gateway policy is authoritative",
        }


# --------------------------------------------------------------------- features


def _destination_class(destination: Any) -> str:
    """Map a destination to the class the policy actually cares about."""
    if not isinstance(destination, str) or not destination.strip():
        return "none"
    value = destination.strip().lower()
    if "@" in value:
        domain = value.rsplit("@", 1)[1]
        if domain in {item.lower() for item in INTERNAL_DOMAINS}:
            return "internal"
        if domain in {item.lower() for item in APPROVED_DESTINATIONS}:
            return "approved"
        return "external"
    if value in {item.lower() for item in INTERNAL_DOMAINS}:
        return "internal"
    if value in {item.lower() for item in APPROVED_DESTINATIONS}:
        return "approved"
    return "external"


def _resource_root(resource: Any) -> str:
    if not isinstance(resource, str) or not resource.strip():
        return "none"
    value = resource.strip()
    if value.startswith("/public/"):
        return "public"
    if value.startswith("/internal/"):
        return "internal"
    if value.startswith(("/secret/", "/private/")):
        return "restricted"
    return "other"


def request_tokens(payload: dict[str, Any]) -> list[str]:
    """Turn a proposed call into policy-shaped tokens.

    Features mirror the inputs the deterministic policy uses (tool, operation,
    resource scope, destination class, classification, provenance) rather than
    free text, so the model cannot be steered by message bodies.
    """
    tool = str(payload.get("tool_name") or "").strip().lower()
    operation = str(payload.get("operation") or "").strip().lower()
    classification = str(payload.get("data_classification") or "internal").lower()
    root = _resource_root(payload.get("resource"))
    destination = _destination_class(payload.get("destination"))
    provenance = bool(payload.get("provenance"))
    known_tool = tool in TOOL_REGISTRY
    arguments = payload.get("arguments")
    has_arguments = isinstance(arguments, dict) and bool(arguments)

    tokens = [
        f"tool={tool or 'none'}",
        f"op={operation or 'none'}",
        f"class={classification}",
        f"root={root}",
        f"dest={destination}",
        f"prov={'yes' if provenance else 'no'}",
        f"known_tool={'yes' if known_tool else 'no'}",
        f"args={'yes' if has_arguments else 'no'}",
    ]
    # Interactions: the policy reasons about combinations, not single fields.
    tokens.append(f"combo={tool}.{operation}")
    tokens.append(f"flow={classification}->{destination}")
    tokens.append(f"scope={operation}:{root}")
    tokens.append(f"cover={'provenanced' if provenance else 'bare'}:{destination}")
    return tokens


# ------------------------------------------------------------------------- model


@dataclass
class _Vectorizer:
    vocabulary: dict[str, int]
    idf: list[float]

    def transform(self, tokens: Sequence[str]) -> list[float]:
        counts = [0.0] * len(self.vocabulary)
        for token in tokens:
            index = self.vocabulary.get(token)
            if index is not None:
                counts[index] += 1.0
        vector = [
            (1.0 + math.log(count)) * self.idf[index] if count > 0 else 0.0
            for index, count in enumerate(counts)
        ]
        norm = math.sqrt(sum(value * value for value in vector)) or 1.0
        return [value / norm for value in vector]

    def out_of_vocabulary_ratio(self, tokens: Sequence[str]) -> float:
        if not tokens:
            return 0.0
        unseen = sum(1 for token in tokens if token not in self.vocabulary)
        return unseen / len(tokens)


def _fit_vectorizer(documents: Sequence[Sequence[str]]) -> _Vectorizer:
    vocabulary: dict[str, int] = {}
    document_frequency: list[int] = []
    for tokens in documents:
        for token in set(tokens):
            if token not in vocabulary:
                vocabulary[token] = len(vocabulary)
                document_frequency.append(0)
            document_frequency[vocabulary[token]] += 1
    total = max(1, len(documents))
    idf = [math.log((1 + total) / (1 + df)) + 1.0 for df in document_frequency]
    return _Vectorizer(vocabulary=vocabulary, idf=idf)


@dataclass
class _SoftmaxModel:
    weights: list[list[float]]
    biases: list[float]
    classes: tuple[str, ...]

    def probabilities(self, features: Sequence[float]) -> list[float]:
        logits = [
            sum(w * x for w, x in zip(row, features)) + bias
            for row, bias in zip(self.weights, self.biases)
        ]
        peak = max(logits)
        exponentials = [math.exp(value - peak) for value in logits]
        total = sum(exponentials)
        return [value / total for value in exponentials]


def _train(
    documents: Sequence[Sequence[str]],
    labels: Sequence[str],
    classes: Sequence[str] = LABELS,
    *,
    epochs: int = 600,
    learning_rate: float = 1.2,
    l2: float = 1e-4,
) -> tuple[_Vectorizer, _SoftmaxModel]:
    """Full-batch gradient descent: deterministic, fast, dependency free."""
    vectorizer = _fit_vectorizer(documents)
    dense = [vectorizer.transform(tokens) for tokens in documents]
    # Sparse view for training: a document only has a handful of tokens, so
    # touching every feature for every sample would be wasted work.
    features = [
        [(index, value) for index, value in enumerate(vector) if value]
        for vector in dense
    ]
    width = len(vectorizer.vocabulary)
    index_of = {name: index for index, name in enumerate(classes)}
    targets = [index_of[label] for label in labels]
    weights = [[0.0] * width for _ in classes]
    biases = [0.0] * len(classes)
    count = len(features)

    # Balanced class weights keep the smaller "approval"/"ambiguous" classes
    # from being flattened by the larger allow/deny groups.
    label_counts = [targets.count(index) for index in range(len(classes))]
    class_weights = [
        count / (len(classes) * value) if value else 0.0 for value in label_counts
    ]

    for _ in range(epochs):
        weight_grads = [[0.0] * width for _ in classes]
        bias_grads = [0.0] * len(classes)
        for vector, target in zip(features, targets):
            logits = [
                sum(row[index] * value for index, value in vector) + bias
                for row, bias in zip(weights, biases)
            ]
            peak = max(logits)
            exponentials = [math.exp(value - peak) for value in logits]
            total = sum(exponentials)
            probabilities = [value / total for value in exponentials]
            sample_weight = class_weights[target]
            for class_index in range(len(classes)):
                error = (probabilities[class_index] - (1.0 if class_index == target else 0.0)) * sample_weight
                if error == 0.0:
                    continue
                bias_grads[class_index] += error
                row = weight_grads[class_index]
                for feature_index, value in vector:
                    row[feature_index] += error * value
        for class_index in range(len(classes)):
            biases[class_index] -= learning_rate * bias_grads[class_index] / count
            row = weights[class_index]
            grad = weight_grads[class_index]
            for feature_index in range(width):
                if grad[feature_index]:
                    row[feature_index] -= learning_rate * (
                        grad[feature_index] / count + l2 * row[feature_index]
                    )
    return vectorizer, _SoftmaxModel(weights, biases, tuple(classes))


def _classify(
    vectorizer: _Vectorizer, model: _SoftmaxModel, payload: dict[str, Any]
) -> Prediction:
    tokens = request_tokens(payload)
    vector = vectorizer.transform(tokens)
    probabilities = model.probabilities(vector)
    ranked = sorted(
        zip(model.classes, probabilities), key=lambda item: item[1], reverse=True
    )
    label, confidence = ranked[0]
    margin = confidence - ranked[1][1]
    distribution = {name: value for name, value in ranked}
    oov = vectorizer.out_of_vocabulary_ratio(tokens)

    if str(payload.get("tool_name") or "").strip().lower() not in TOOL_REGISTRY:
        # Unknown tools are a deterministic policy denial; the model has no
        # evidence to score them, so it abstains rather than guessing.
        return Prediction(label, confidence, margin, True, "unregistered tool", distribution)
    if oov >= OOV_THRESHOLD:
        return Prediction(label, confidence, margin, True, "unfamiliar features", distribution)
    if confidence < CONFIDENCE_THRESHOLD:
        return Prediction(label, confidence, margin, True, "low confidence", distribution)
    if margin < MARGIN_THRESHOLD:
        return Prediction(label, confidence, margin, True, "ambiguous classes", distribution)
    if label == "ambiguous":
        return Prediction(label, confidence, margin, True, "model predicts ambiguity", distribution)
    return Prediction(label, confidence, margin, False, None, distribution)


# ---------------------------------------------------------------------- metrics


def _as_payload(sample: dict[str, Any]) -> dict[str, Any]:
    """Map a fixture row onto the request-shaped input the model consumes."""
    return {
        "tool_name": sample.get("tool"),
        "operation": sample.get("operation"),
        "resource": sample.get("resource"),
        "destination": sample.get("destination"),
        "data_classification": sample.get("classification"),
        "provenance": ["fixture"] if sample.get("provenance") else [],
        "arguments": {"path": sample.get("resource")} if sample.get("resource") else {},
    }


def _dataset() -> dict[str, Any]:
    with _DATASET_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _prf(
    truth: Sequence[str], predicted: Sequence[str], label: str
) -> dict[str, float | int | None]:
    tp = sum(1 for t, p in zip(truth, predicted) if t == label and p == label)
    fp = sum(1 for t, p in zip(truth, predicted) if t != label and p == label)
    fn = sum(1 for t, p in zip(truth, predicted) if t == label and p != label)
    precision = None if tp + fp == 0 else tp / (tp + fp)
    recall = None if tp + fn == 0 else tp / (tp + fn)
    if precision is None or recall is None or precision + recall == 0:
        f1: float | None = None if precision is None or recall is None else 0.0
    else:
        f1 = 2 * precision * recall / (precision + recall)
    return {
        "support": tp + fn,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": None if precision is None else round(precision, 4),
        "recall": None if recall is None else round(recall, 4),
        "f1": None if f1 is None else round(f1, 4),
    }


def _evaluate_split(samples: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Stratified deterministic split: every third sample per label is held out."""
    by_label: dict[str, list[dict[str, Any]]] = {}
    for sample in samples:
        by_label.setdefault(str(sample["label"]), []).append(sample)

    train: list[dict[str, Any]] = []
    test: list[dict[str, Any]] = []
    for label in sorted(by_label):
        group = by_label[label]
        for index, sample in enumerate(group):
            (test if index % 3 == 2 else train).append(sample)

    vectorizer, model = _train(
        [request_tokens(_as_payload(sample)) for sample in train],
        [str(sample["label"]) for sample in train],
    )

    truth: list[str] = []
    predicted: list[str] = []
    pooled: list[str] = []  # abstentions replaced by the predicted label
    abstentions = 0
    for sample in test:
        prediction = _classify(vectorizer, model, _as_payload(sample))
        truth.append(str(sample["label"]))
        predicted.append("abstain" if prediction.abstained else prediction.label)
        pooled.append(prediction.label)
        abstentions += 1 if prediction.abstained else 0

    labels = list(LABELS)
    matrix: dict[str, dict[str, int]] = {
        expected: {actual: 0 for actual in labels + ["abstain"]} for expected in labels
    }
    for expected, actual in zip(truth, predicted):
        matrix[expected][actual] += 1

    per_class = {label: _prf(truth, predicted, label) for label in labels}
    scored = [row["f1"] for row in per_class.values() if row["f1"] is not None]
    macro_f1 = round(sum(scored) / len(scored), 4) if scored else None
    exact_match = round(
        sum(1 for t, p in zip(truth, predicted) if t == p) / max(1, len(truth)), 4
    )
    # Abstention is a designed outcome, so it counts as correct for fixtures
    # labelled ambiguous - and never as a correct answer for the other labels.
    consistent = sum(
        1
        for t, p in zip(truth, predicted)
        if (t == "ambiguous" and p == "abstain") or (t != "ambiguous" and t == p)
    )
    decision_accuracy = round(consistent / max(1, len(truth)), 4)

    # Binary "should not be allowed silently" view: deny/approval are treated as
    # unsafe, allow as safe, ambiguous excluded from the binary count because
    # abstention is its own outcome.
    binary = [(t, p) for t, p in zip(truth, pooled) if t in {"allow", "deny", "approval"}]
    false_positive = sum(1 for t, p in binary if t == "allow" and p in UNSAFE_LABELS)
    false_negative = sum(1 for t, p in binary if t in UNSAFE_LABELS and p == "allow")

    return {
        "dataset_version": "agentshield-classifier-fixtures-v1",
        "dataset_source": (
            "Authored in this repository from the CB-05 policy scenarios; "
            "not an external benchmark."
        ),
        "dataset_size": len(samples),
        "train_size": len(train),
        "test_size": len(test),
        "split": "deterministic stratified hold-out (every third sample per label)",
        "evaluation_scope": "held-out split of the bundled fixtures",
        "labels": labels,
        "accuracy": decision_accuracy,
        "accuracy_definition": (
            "decision accuracy: abstention counts as correct only for fixtures "
            "labelled ambiguous, and never as a correct answer elsewhere"
        ),
        "exact_match_accuracy": exact_match,
        "macro_f1": macro_f1,
        "macro_f1_note": (
            "macro F1 over the four fixture labels; an abstention is a miss for "
            "the true class, so low-coverage classes score lower by design"
        ),
        "per_class": per_class,
        "confusion_matrix": matrix,
        "abstentions": abstentions,
        "abstention_rate": round(abstentions / max(1, len(test)), 4),
        "false_positive": false_positive,
        "false_negative": false_negative,
        "false_positive_definition": "predicted deny/approval for a fixture labelled allow",
        "false_negative_definition": "predicted allow for a fixture labelled deny/approval",
        "thresholds": {
            "confidence": CONFIDENCE_THRESHOLD,
            "margin": MARGIN_THRESHOLD,
            "oov_ratio": OOV_THRESHOLD,
        },
        "feature_count": len(vectorizer.vocabulary),
        "model_version": MODEL_VERSION,
        "policy_version": POLICY_VERSION,
    }


# ------------------------------------------------------------------- classifier


class PolicyClassifier:
    """Advisory classifier: predict, abstain, and report its own metrics."""

    def __init__(self, dataset_path: Path | None = None) -> None:
        source = dataset_path or _DATASET_PATH
        with source.open("r", encoding="utf-8") as handle:
            bundle = json.load(handle)
        self.dataset_version = str(bundle["dataset_version"])
        self.dataset_source = str(bundle["source"])
        self._samples: list[dict[str, Any]] = [
            dict(sample) for sample in bundle["samples"]
        ]
        self._metrics = _evaluate_split(self._samples)
        # Serving model is trained on every fixture after the held-out report.
        self._vectorizer, self._model = _train(
            [request_tokens(_as_payload(sample)) for sample in self._samples],
            [str(sample["label"]) for sample in self._samples],
        )

    # -- inference ----------------------------------------------------------
    def predict(self, payload: dict[str, Any]) -> Prediction:
        return _classify(self._vectorizer, self._model, payload)

    def advisory(self, payload: dict[str, Any] | None) -> dict[str, Any] | None:
        """Advisory record for the audit trail; never authoritative."""
        if not isinstance(payload, dict):
            return None
        try:
            return self.predict(payload).to_dict()
        except Exception:  # noqa: BLE001 - advisory faults must not block a call
            return None

    # -- reporting ----------------------------------------------------------
    def describe(self) -> dict[str, Any]:
        return {
            "model_version": MODEL_VERSION,
            "dataset_version": self.dataset_version,
            "dataset_source": self.dataset_source,
            "labels": list(LABELS),
            "thresholds": {
                "confidence": CONFIDENCE_THRESHOLD,
                "margin": MARGIN_THRESHOLD,
                "oov_ratio": OOV_THRESHOLD,
            },
            "authority": (
                "Advisory only. The deterministic policy in agentshield/policy.py "
                "is authoritative; the classifier cannot authorise or block a call."
            ),
        }

    def metrics(self) -> dict[str, Any]:
        return self._metrics


_default: PolicyClassifier | None = None


def default_classifier() -> PolicyClassifier:
    """Process-wide classifier (training is deterministic and cheap)."""
    global _default
    if _default is None:
        _default = PolicyClassifier()
    return _default


def classify_many(payloads: Iterable[dict[str, Any]]) -> list[Prediction]:
    classifier = default_classifier()
    return [classifier.predict(payload) for payload in payloads]
