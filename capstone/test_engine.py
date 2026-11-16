from dlp_engine.engine import inspect


text = (
    "My name is Rahul Sharma. "
    "My email is rahul@example.com. "
    "My IP is 192.168.1.50. "
    "My AWS test key is AKIA1234567890ABCDEF."
)


print("=" * 70)
print("ORIGINAL")
print("=" * 70)

print(text)


modified, findings = inspect(text)


print("\n" + "=" * 70)
print("FINDINGS")
print("=" * 70)

for finding in findings:
    print(finding)


print("\n" + "=" * 70)
print("FINAL REDACTED TEXT")
print("=" * 70)

print(modified)