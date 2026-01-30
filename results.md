# Small-scale Results:

| Type | Number of Clients | Vector Dim | Number of Vectors | KeyGen per Client (ms) | KeyGen Total (ms) | Precomp per client (ms) | Precomp Trusted (ms) | Encrypt per vector (ms) | Addition (ms) | Decrypt (ms) | Total Aggregation (ms) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| TERSE-Native | 100 | 10 | 100 | 1.60205 | 162.603 | 137.168 | 137.565 | 0.000927222 | 0.001339 | 0.00012653 | 0.00146553 |
| AES-Native | 100 | 10 | 100 | 3.7063 | 0 | 0 | 0 | 0.00135781 | 0 | 0.116252 | 0.116252 |
| TERSE-SGX | 100 | 10 | 100 | 1.06771 | 422.108 | 163.804 | 164.102 | 0.000927136 | 0.001281 | 0.00032000 | 0.00160100 |
| AES-SGX | 100 | 10 | 100 | 3.47709 | 0 | 0 | 0 | 0.00131468 | 0 | 0.0987 | 0.0987 |
