# Pinned timestamp strict verification

Post-session AI-assisted verification, separate from model tests. Python3.14.3. Offline generated RSA2048 TSA keys remain in memory. All fixtures are newly signed and independently verified with cryptography. PYTHONPATH must contain matching frozen source and verification/tsa-strict-r1. python -B -m pytest -q -s test_tsa_strict_review.py records46 pass,4 genuine per-call policy binding failures and1 reviewer exception-type expectation error. The malformed-DER case was actually rejected by PyAsn1Error; prompt imposes no ValueError-only contract. The unchanged frozen code passes its corrected focused check in tsa-der-rejection-r2. Thus51 unique reviewed cases:47 pass and4 failures of one root cause; original failed output retained. Model suite42 pass; explicit offline upstream2 pass, scopes not summed. No public TSA accessed. Mock post captures actual DER request policy, valid token has different policy; direct strict explicitly rejects that token for the requested policy, while Remote accepts with constructorNone or old policy and both return modes. The recording demo is reviewer support, not model code, and prints real failures with exit1. No source or native trajectory edits.

No automatic submission; user review required.


冻结产物提交：https://github.com/9873199/timestamp-token-pinned-validation/commit/025a190cefe347d2444f2c732e64d520ab8de381
这些独立验收文件在模型首轮结束后生成，不是模型原轨中的测试。
