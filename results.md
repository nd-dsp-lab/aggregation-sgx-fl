# Results

| Type | Number of Clients | Vector Dim | Number of Vectors | KeyGen per Client (ms) | KeyGen Total (ms) | Precomp per client (ms) | Precomp Trusted (ms) | Encrypt per vector (ms) | Addition (ms) | Decrypt (ms) | Total Aggregation (ms) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| TERSE-Native | 1000 | 1000000 | 5 | 0.403 | 41.142 | 105.201 | 391.517 | 48.714 | 235.853 | 2.985 | 238.838 |
| AES-Native | 1000 | 1000000 | 5 | 3.563 | 359.759 | 0.000 | 0.461 | 8.990 | 0.000 | 635.870 | 635.870 |
| TERSE-SGX | 1000 | 1000000 | 5 | 0.403 | 41.142 | 105.201 | 391.517 | 48.714 | 235.853 | 2.971 | 238.824 |
| AES-SGX | 1000 | 1000000 | 5 | 0.000 | 0.000 | 0.000 | 3.787 | 8.990 | 0.000 | 240.803 | 240.803 |
