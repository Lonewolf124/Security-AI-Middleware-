"""
Model detection with a sensitivity dial.

The token classifier gives every token a probability for each label and for
"nothing here". PIIModel.detect takes the most likely one. This reads the
same probabilities and lets one number decide how readily a token counts
as private:

    sensitivity 0.5   the model's own choice (same result as PIIModel.detect)
    above 0.5         also flag tokens the model was unsure about: fewer
                      missed values, more ordinary words masked
    below 0.5         flag only what the model is confident about: fewer
                      ordinary words masked, more missed values

Because masking is reversible, a wrongly masked word is put back in the
reply, while a missed value is a leak. That argues for running above 0.5.
"""

import json
import os

import numpy as np


# At sensitivity 1.0 a token is flagged unless the model is at least this
# sure that it is nothing; at 0.0 a label needs at least this probability.
MAX_NOTHING_CUTOFF = 0.98
MAX_LABEL_FLOOR = 0.90


def softmax(logits):

    shifted = logits - logits.max(axis=-1, keepdims=True)
    exp = np.exp(shifted)

    return exp / exp.sum(axis=-1, keepdims=True)


class Detector:

    def __init__(self, pii_model, sensitivity=0.5, model_dir=None):

        self._tokenizer = pii_model.tokenizer
        self._session = pii_model.session
        self.sensitivity = min(1.0, max(0.0, float(sensitivity)))

        if model_dir is None:

            from onnx_quantized_all17 import pii_model as module

            model_dir = module.MODEL_DIR

        with open(os.path.join(model_dir, "config.json"), encoding="utf-8") as handle:
            id2label = json.load(handle)["id2label"]

        self._labels = [id2label[str(i)] for i in range(len(id2label))]
        self._nothing = self._labels.index("O")

    def _decide(self, probabilities):
        """Return (label id, confidence) per token; the 'nothing' id if not flagged."""

        nothing = probabilities[:, self._nothing]

        labelled = probabilities.copy()
        labelled[:, self._nothing] = -1.0

        best = labelled.argmax(axis=-1)
        best_p = labelled.max(axis=-1)

        s = self.sensitivity

        if s >= 0.5:
            cutoff = (s - 0.5) * 2 * MAX_NOTHING_CUTOFF
            flagged = (best_p > nothing) | (nothing < cutoff)

        else:
            floor = (0.5 - s) * 2 * MAX_LABEL_FLOOR
            flagged = (best_p > nothing) & (best_p >= floor)

        return np.where(flagged, best, self._nothing), np.where(flagged, best_p, nothing)

    def detect(self, text):
        """Entities as dicts with start, end, type and score (mean confidence)."""

        if not isinstance(text, str) or not text.strip():
            return []

        encoded = self._tokenizer(
            text,
            return_tensors="np",
            return_offsets_mapping=True,
            truncation=True,
            max_length=512,
        )

        offsets = encoded.pop("offset_mapping")[0]

        logits = self._session.run(
            ["logits"],
            {
                "input_ids": encoded["input_ids"].astype("int64"),
                "attention_mask": encoded["attention_mask"].astype("int64"),
                "token_type_ids": encoded["token_type_ids"].astype("int64"),
            },
        )[0][0]

        label_ids, confidence = self._decide(softmax(logits))

        entities = []
        current = None

        for (start, end), label_id, score in zip(offsets, label_ids, confidence):

            start, end = int(start), int(end)

            # Special tokens such as [CLS] and [SEP].
            if start == end:
                continue

            label = self._labels[int(label_id)]

            if label == "O":
                current = None
                continue

            prefix, entity_type = label.split("-", 1)

            if current is not None and prefix == "I" and current["type"] == entity_type:
                current["end"] = end
                current["scores"].append(float(score))
                continue

            current = {
                "type": entity_type,
                "start": start,
                "end": end,
                "scores": [float(score)],
            }

            entities.append(current)

        for entity in entities:
            scores = entity.pop("scores")
            entity["score"] = sum(scores) / len(scores)
            entity["text"] = text[entity["start"]:entity["end"]]

        return entities
