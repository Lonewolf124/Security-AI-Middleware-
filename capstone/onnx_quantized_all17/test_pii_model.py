# import json
# import numpy as np
# import onnxruntime as ort
# from transformers import AutoTokenizer


# MODEL_DIR = r"F:\capstone\onnx_quantized_all17"
# MODEL_PATH = r"F:\capstone\onnx_quantized_all17\model_quantized.onnx"


# # --------------------------------------------------
# # Load labels
# # --------------------------------------------------

# with open(MODEL_DIR + r"\config.json", "r", encoding="utf-8") as f:
#     config = json.load(f)

# id2label = {
#     int(k): v
#     for k, v in config["id2label"].items()
# }


# # --------------------------------------------------
# # Load tokenizer + ONNX model
# # --------------------------------------------------

# tokenizer = AutoTokenizer.from_pretrained(
#     MODEL_DIR,
#     local_files_only=True
# )

# session = ort.InferenceSession(
#     MODEL_PATH,
#     providers=["CPUExecutionProvider"]
# )


# # --------------------------------------------------
# # Test text
# # --------------------------------------------------

# text = (
#     "My name is Rahul Sharma. "
#     "My email is rahul@example.com. "
#     "My IP address is 192.168.1.50."
# )


# # --------------------------------------------------
# # Tokenize WITH character offsets
# # --------------------------------------------------

# encoded = tokenizer(
#     text,
#     return_tensors="np",
#     truncation=True,
#     max_length=512,
#     return_offsets_mapping=True
# )

# offsets = encoded.pop("offset_mapping")[0]


# # --------------------------------------------------
# # ONNX inputs
# # --------------------------------------------------

# inputs = {
#     "input_ids": encoded["input_ids"].astype(np.int64),
#     "attention_mask": encoded["attention_mask"].astype(np.int64),
#     "token_type_ids": encoded["token_type_ids"].astype(np.int64),
# }


# # --------------------------------------------------
# # Run model
# # --------------------------------------------------

# logits = session.run(
#     ["logits"],
#     inputs
# )[0]

# predictions = np.argmax(logits, axis=-1)[0]

# tokens = tokenizer.convert_ids_to_tokens(
#     encoded["input_ids"][0]
# )


# # --------------------------------------------------
# # Build entity spans from B/I labels
# # --------------------------------------------------

# entities = []

# current_type = None
# current_start = None
# current_end = None


# for token, label_id, offset, attention in zip(
#     tokens,
#     predictions,
#     offsets,
#     encoded["attention_mask"][0]
# ):

#     if attention == 0:
#         continue

#     start, end = offset
#     label = id2label[int(label_id)]

#     # Special tokens such as [CLS] / [SEP]
#     if start == end:
#         continue

#     if label.startswith("B-"):

#         # Finish previous entity
#         if current_type is not None:
#             entities.append({
#                 "type": current_type,
#                 "start": current_start,
#                 "end": current_end,
#                 "text": text[current_start:current_end],
#             })

#         current_type = label[2:]
#         current_start = start
#         current_end = end

#     elif label.startswith("I-"):

#         entity_type = label[2:]

#         if current_type == entity_type:
#             current_end = end

#         else:
#             # Unexpected I- without matching B-
#             if current_type is not None:
#                 entities.append({
#                     "type": current_type,
#                     "start": current_start,
#                     "end": current_end,
#                     "text": text[current_start:current_end],
#                 })

#             current_type = entity_type
#             current_start = start
#             current_end = end

#     else:

#         # O → finish current entity
#         if current_type is not None:
#             entities.append({
#                 "type": current_type,
#                 "start": current_start,
#                 "end": current_end,
#                 "text": text[current_start:current_end],
#             })

#             current_type = None
#             current_start = None
#             current_end = None


# # Finish final entity
# if current_type is not None:
#     entities.append({
#         "type": current_type,
#         "start": current_start,
#         "end": current_end,
#         "text": text[current_start:current_end],
#     })



# # --------------------------------------------------
# # Redact detected entities
# # --------------------------------------------------

# def redact_entities(text, entities):
#     """
#     Replace detected entity spans from right to left.
#     """

#     redacted = text

#     for entity in sorted(
#         entities,
#         key=lambda x: x["start"],
#         reverse=True
#     ):
#         start = entity["start"]
#         end = entity["end"]
#         entity_type = entity["type"]

#         replacement = f"[{entity_type}_REDACTED]"

#         redacted = (
#             redacted[:start]
#             + replacement
#             + redacted[end:]
#         )

#     return redacted


# redacted_text = redact_entities(text, entities)


# print("=" * 70)
# print("REDACTED TEXT")
# print("=" * 70)
# print(redacted_text)




# # --------------------------------------------------
# # Display results
# # --------------------------------------------------

# print("=" * 70)
# print("ORIGINAL TEXT")
# print("=" * 70)
# print(text)

# print()
# print("=" * 70)
# print("DETECTED ENTITIES")
# print("=" * 70)

# for entity in entities:
#     print(
#         f"Type : {entity['type']}\n"
#         f"Text : {entity['text']}\n"
#         f"Start: {entity['start']}\n"
#         f"End  : {entity['end']}\n"
#     )


from pii_model import PIIModel


model = PIIModel()


text = (
    "My name is Rahul Sharma. "
    "My email is rahul@example.com. "
    "My IP address is 192.168.1.50."
)


print("=" * 70)
print("ORIGINAL")
print("=" * 70)

print(text)


entities = model.detect(text)


print("\n" + "=" * 70)
print("ENTITIES")
print("=" * 70)

for entity in entities:
    print(
        f"Type : {entity['type']}\n"
        f"Text : {entity['text']}\n"
        f"Start: {entity['start']}\n"
        f"End  : {entity['end']}\n"
    )


redacted, _ = model.redact(text)


print("=" * 70)
print("REDACTED")
print("=" * 70)

print(redacted)