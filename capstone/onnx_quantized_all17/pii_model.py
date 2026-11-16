import os

import onnxruntime as ort
from transformers import AutoTokenizer


# Resolve the model directory relative to this file so the project can be
# moved between drives without editing any paths.
MODEL_DIR = os.path.dirname(os.path.abspath(__file__))


class PIIModel:

    def __init__(self, model_dir=MODEL_DIR):

        print("[PII] Loading tokenizer...")

        self.tokenizer = AutoTokenizer.from_pretrained(
            model_dir,
            local_files_only=True
        )

        print("[PII] Loading ONNX model...")

        self.session = ort.InferenceSession(
            os.path.join(model_dir, "model_quantized.onnx"),
            providers=["CPUExecutionProvider"]
        )

        print("[PII] Model loaded successfully")

    def detect(self, text):

        if not isinstance(text, str) or not text.strip():
            return []

        encoded = self.tokenizer(
            text,
            return_tensors="np",
            return_offsets_mapping=True,
            truncation=True,
            max_length=512
        )

        offset_mapping = encoded.pop("offset_mapping")[0]

        inputs = {
            "input_ids": encoded["input_ids"].astype("int64"),
            "attention_mask": encoded["attention_mask"].astype("int64"),
            "token_type_ids": encoded["token_type_ids"].astype("int64")
        }

        outputs = self.session.run(
            ["logits"],
            inputs
        )

        logits = outputs[0][0]

        predicted_ids = logits.argmax(axis=-1)

        id2label = self.session.get_modelmeta()

        # Labels from the model configuration
        labels = {
            0: "O",
            1: "B-AADHAAR",
            2: "I-AADHAAR",
            3: "B-ADDRESS",
            4: "I-ADDRESS",
            5: "B-API_KEY",
            6: "I-API_KEY",
            7: "B-CREDIT_CARD",
            8: "I-CREDIT_CARD",
            9: "B-DATE_OF_BIRTH",
            10: "I-DATE_OF_BIRTH",
            11: "B-DRIVER_LICENSE",
            12: "I-DRIVER_LICENSE",
            13: "B-EMAIL",
            14: "I-EMAIL",
            15: "B-IP_ADDRESS",
            16: "I-IP_ADDRESS",
            17: "B-PAN_CARD",
            18: "I-PAN_CARD",
            19: "B-PASSPORT",
            20: "I-PASSPORT",
            21: "B-PASSWORD",
            22: "I-PASSWORD",
            23: "B-PERSON_NAME",
            24: "I-PERSON_NAME",
            25: "B-PHONE",
            26: "I-PHONE",
            27: "B-SSN",
            28: "I-SSN",
            29: "B-UPI_ID",
            30: "I-UPI_ID",
            31: "B-USERNAME",
            32: "I-USERNAME",
            33: "B-VEHICLE_REG",
            34: "I-VEHICLE_REG"
        }

        entities = []

        current_type = None
        current_start = None
        current_end = None

        for token_id, label_id in enumerate(predicted_ids):

            label = labels.get(int(label_id), "O")

            start, end = offset_mapping[token_id]

            start = int(start)
            end = int(end)

            # Special tokens such as [CLS] and [SEP]
            if start == end:
                continue

            if label == "O":

                if current_type is not None:
                    entities.append({
                        "type": current_type,
                        "start": current_start,
                        "end": current_end,
                        "text": text[current_start:current_end]
                    })

                    current_type = None
                    current_start = None
                    current_end = None

                continue

            prefix, entity_type = label.split("-", 1)

            if prefix == "B":

                if current_type is not None:
                    entities.append({
                        "type": current_type,
                        "start": current_start,
                        "end": current_end,
                        "text": text[current_start:current_end]
                    })

                current_type = entity_type
                current_start = start
                current_end = end

            elif prefix == "I":

                if current_type == entity_type:
                    current_end = end

                else:
                    # Handle an unexpected I-token safely
                    if current_type is not None:
                        entities.append({
                            "type": current_type,
                            "start": current_start,
                            "end": current_end,
                            "text": text[current_start:current_end]
                        })

                    current_type = entity_type
                    current_start = start
                    current_end = end

        # Flush final entity
        if current_type is not None:
            entities.append({
                "type": current_type,
                "start": current_start,
                "end": current_end,
                "text": text[current_start:current_end]
            })

        # Normalize boundaries
        for entity in entities:

            while (
                entity["end"] > entity["start"]
                and text[entity["end"] - 1] in ".,;:!?)]}"
            ):
                entity["end"] -= 1

            entity["text"] = text[
                entity["start"]:entity["end"]
            ]

        return entities

    def redact(self, text):

        entities = self.detect(text)

        redacted = text

        for entity in sorted(
            entities,
            key=lambda x: x["start"],
            reverse=True
        ):

            replacement = (
                f"[{entity['type']}_REDACTED]"
            )

            redacted = (
                redacted[:entity["start"]]
                + replacement
                + redacted[entity["end"]:]
            )

        return redacted, entities