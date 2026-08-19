# MicroAPI Guard — Viva Question Bank

Every answer below is grounded in what the code actually does and what was
actually measured. Nothing here is invented. If you do not know an answer in the
viva, say so — that costs far less than a confident wrong answer.

**Numbers you must know by heart:**

| | |
|---|---|
| Dataset | 35,496 labelled events |
| Features | 34 (no endpoint identity) |
| Signature rules | 26 |
| Confusion matrix | TN 1358 · FP 27 · FN 75 · TP 667 (n = 2,127) |
| Accuracy / Precision / Recall / F1 | 0.9520 / 0.9611 / 0.8989 / 0.9290 |
| ROC-AUC / PR-AUC | 0.9926 / 0.9863 |
| FPR / FNR | 0.0195 / 0.1011 |
| Zero-day recall | 0.8865 single run · 0.598 over 10 seeds |
| Layer 1 | 31/31 attacks blocked, 0 FP in 1,200 requests |
| Latency | 10.96 ms median detection |

---

## 1 · Basics and motivation

**Q1. What problem does your project solve?**
> APIs are now the main attack surface for microservice applications. The two
> existing defences each fail in a different way: signature-based WAFs only catch
> attacks someone already wrote a rule for, and pure machine-learning detectors
> block real users too often. We combine both so each covers the other's gap.

**Q2. Why is it called a "gateway"?**
> It sits between the client and the backend as a reverse proxy. Every request
> must pass through it before reaching the application, so it can block a request
> before the backend ever sees it.

**Q3. What is a "learned stacking ensemble"?**
> Stacking means training a second-level model on the *outputs* of first-level
> models. Our three base detectors each produce a score; the logistic regression
> meta-learner is trained on those three scores and produces the final decision.
> "Learned" distinguishes it from a fixed rule like averaging or voting.

**Q4. What does "zero-day" mean here?**
> An attack type the system never saw during training. We measure it by removing
> three whole attack families — command injection, template injection and data
> exfiltration — from training, then testing only on them.

---

## 2 · Architecture

**Q5. Explain the four layers.**
> Layer 1 is deterministic: 26 signature rules plus Redis-based rate limiting.
> Layers 2 and 3 are Isolation Forest and an autoencoder, both trained only on
> normal traffic. Layer 4 is logistic regression, which takes the three scores
> and makes the final decision.

**Q6. Why does Layer 1 block before the models run?**
> Two reasons. It saves latency — no point running 300 trees and a neural network
> on a request already known to be an attack. And it removes a chance to be wrong
> about something already certain. Sending a confirmed `UNION SELECT` to a
> statistical model can only make the answer worse.

**Q7. Then why have machine learning at all?**
> Because rules only catch what we anticipated. The rules missed nothing in our
> test set, but that set contains attacks we chose. The models exist for the
> attacks nobody wrote a rule for — which is exactly what the zero-day
> measurement tests.

**Q8. Which layer makes the final decision?**
> Layer 4, always, for anything that reaches it. Layers 1–3 only produce scores.
> This is enforced by a unit test: the reported probability must equal the
> meta-learner's output, not any other detector's.

**Q9. How is the system backend-agnostic?**
> No feature encodes which endpoint was called. The features measure request
> shape — path depth, entropy, body character ratios, encoding density — and
> client behaviour. Those mean the same thing on any HTTP API. A test asserts
> that no path-valued or one-hot-path feature exists.

**Q10. What happens if the backend is down?**
> The gateway returns 502, or 504 on timeout. It does not invent a response.

**Q11. What if Redis goes down?**
> Rate limiting degrades — counters return zero — but requests keep flowing and
> the signature and model layers still apply. The decision is marked `degraded`
> in the log so it is not silently trusted.

**Q12. What if the model crashes on a request?**
> It fails **closed** — the request is blocked. Failing open would be an
> exploitable bypass: an attacker would just send whatever crashes the extractor.

---

## 3 · Machine learning design

**Q13. Why Isolation Forest?**
> It detects anomalies by random partitioning — points that isolate in few splits
> are rare. It needs no attack labels and is fast at inference.

**Q14. Why an Autoencoder?**
> It learns to reconstruct normal traffic. Attack traffic, being off the normal
> manifold, reconstructs badly, and that reconstruction error becomes the anomaly
> score. Like Isolation Forest, it needs no attack labels.

**Q15. Why train on normal data only?**
> Because a model trained on labelled attacks can only recognise attack types it
> was shown. Training on normal only means anything that deviates is suspicious,
> including attacks that did not exist when we trained. That is what makes
> zero-day detection possible at all.

**Q16. Why Logistic Regression as the meta-learner, not XGBoost or a neural net?**
> It takes only three inputs. At that size a gradient-booster adds variance and
> opacity for no measurable gain. Logistic regression gives interpretable
> coefficients — and that mattered in practice: a negative Isolation Forest
> coefficient is exactly how we detected a data leak in our earlier pipeline.

**Q17. Your autoencoder is NumPy, not PyTorch. Is that still deep learning?**
> Yes. It is a multi-layer network — 34→32→12→32→34 — trained by mini-batch
> backpropagation with the Adam optimiser and early stopping. Nothing about the
> method is compromised. PyTorch was dropped because at this size NumPy is faster
> to load, has no CUDA dependency, and keeps the container small.

**Q18. Why 34 features? How did you choose them?**
> They fall into four groups: body shape (size, entropy, character ratios), path
> shape (depth, entropy, encoding density), query structure, and client behaviour.
> We removed features that were attacker-controlled or unstable — header count and
> user-agent fields are trivially spoofed, and rate magnitude conflicted with
> Layer 1's own policy. Removing them *improved* every metric.

**Q19. What is the bottleneck size and why 12?**
> 12 units. It must be small enough to force compression — otherwise the network
> learns an identity function and reconstructs attacks equally well — but large
> enough to represent normal traffic. 12 from 34 is roughly a third.

---

## 4 · Data and methodology *(expect the hardest questions here)*

**Q20. How did you generate your dataset?**
> A Python generator sends traffic through the live gateway. Normal traffic uses
> four client profiles — human browsing, dashboard fan-out, server integration
> and health pollers — with randomised identifiers, search terms, body lengths
> and pacing. Attacks span 10 families with mutated and obfuscated payloads.
> 35,496 labelled events in total.

**Q21. How do you avoid data leakage?**
> Four separate guarantees:
> 1. Sessions are grouped — we split by client, not by row, so near-identical
>    requests from one session cannot land on both sides.
> 2. The base detectors are fitted on a pool that is disjoint from the pool used
>    to train the meta-learner, so meta-features are out-of-sample by
>    construction.
> 3. All normalisation statistics come from training data only.
> 4. The test pool is read exactly once, at the very end.

**Q22. Why not k-fold out-of-fold stacking?**
> Because we do not need it. OOF exists to stop base models from scoring their
> own training rows. Our base models are unsupervised and need no labels, so we
> can simply fit them on a disjoint pool — that gives the same guarantee
> directly, without folds.

**Q23. What are the four pools and their sizes?**
> base 3,695 (normal only — fits scaler, forest, autoencoder), meta 3,611
> (trains the meta-learner), validation 2,031 (chooses the threshold), test 2,127
> (final evaluation, used once).

**Q24. How is the threshold chosen?**
> On the validation pool only, maximising F1 subject to a 1% false-positive
> budget. The final value is 0.685. The test set plays no part in choosing it.

**Q25. Was there anything wrong with your earlier version?** *(be honest — this earns marks)*
> Yes, and finding it was the most valuable part of the project. The earlier
> version reported F1 0.988. When we audited the data we found 11,474 rows
> containing only **31 distinct** feature vectors — a 99.7% duplicate rate. The
> generator sampled a fixed list of hardcoded requests, and `http_path` was
> one-hot encoded, so the model had learned "path equals /wp-admin means attack".
> It was a lookup table. We rebuilt the data generation and the feature set.

**Q26. Is your data realistic?**
> Partly. It is synthetic, generated by us, and that is our main limitation. We
> made it as realistic as we could — varied payloads, four legitimate client
> profiles including bursty ones, and obfuscated attacks. But we have not
> validated on production traffic or a public benchmark such as CSIC 2010, and we
> say so explicitly.

---

## 5 · Metrics and evaluation

**Q27. Give your results.**
> Accuracy 0.9520, precision 0.9611, recall 0.8989, F1 0.9290, ROC-AUC 0.9926,
> PR-AUC 0.9863 on a held-out test set of 2,127 unseen sessions.

**Q28. Read out your confusion matrix.**
> True negatives 1358, false positives 27, false negatives 75, true positives 667.
> So 27 legitimate requests were wrongly blocked and 75 attacks were missed.

**Q29. Why is accuracy not enough?**
> Because classes are imbalanced. If 90% of traffic is normal, a system that
> allows everything scores 90% accuracy while catching nothing. For security the
> two numbers that matter are recall — how many attacks we catch — and the
> false-positive rate — how many real users we wrongly block.

**Q30. Why report both ROC-AUC and PR-AUC?**
> ROC-AUC can look optimistic when the negative class dominates, because a large
> true-negative count inflates it. PR-AUC focuses on the positive class and is the
> more honest measure under imbalance. We report both: 0.9926 and 0.9863.

**Q31. Did you check whether your results depend on the random seed?**
> Yes, and it mattered. We retrained 10 times. F1 fell from 0.929 to a mean of
> 0.854 [0.812–0.891] and zero-day recall from 0.887 to 0.598 [0.445–0.749].
> Precision, FPR and ROC-AUC stayed tight. So the system is reliably precise, but
> its coverage varies — and we report the interval rather than our best run.

**Q32. Why does recall vary so much across seeds?**
> The seed changes which sessions land in the test pool, and therefore which
> attack families appear and in what proportion. The withheld-family sample is
> only about 229 requests, so small-sample variation dominates. More sessions
> would tighten it.

**Q33. How do you prove the ensemble is better than one model?**
> We evaluated each detector alone on identical test rows under the same 1% FPR
> budget: rate 0.515 F1, Isolation Forest 0.406, autoencoder 0.870, stack 0.929.
> Then McNemar's test on paired predictions: the stack beats rate at p = 2.9e-70,
> the forest at p = 3.1e-96, and the autoencoder at p = 8.4e-12.

**Q34. What does McNemar's test actually test?**
> Whether two classifiers make *asymmetric* errors on the same samples. It uses
> only the discordant pairs — cases where one is right and the other wrong. The
> null hypothesis is that both counts are equal.

**Q35. Why is McNemar appropriate here, and when would it not be?**
> It is appropriate because our comparisons are paired — the same test rows,
> binary correct/incorrect outcomes. It would be **inappropriate** for comparing
> results from different splits or different seeds, because those are not paired.
> For across-seed comparison you would use confidence intervals or a paired
> t-test / Wilcoxon signed-rank instead.

**Q36. Why did you use the exact binomial version in some cases?**
> When the number of discordant pairs is small — under 25 — the chi-square
> approximation is unreliable and anti-conservative. The exact binomial test is
> correct there. Our implementation switches automatically.

**Q37. What is your zero-day result, honestly?**
> The single best run gave 0.887, but the 10-seed mean is 0.598 with a 95%
> interval of 0.445 to 0.749 and a range from 0.219 to 1.000. The interval is
> wide, so we present it as evidence that the mechanism works rather than a
> precise performance claim.

---

## 6 · Security

**Q38. Which attacks do you detect?**
> SQL injection, XSS, path traversal, command injection, SSRF, template
> injection, scanner and secret-file probing, brute force, request flooding,
> data exfiltration by enumeration, and oversized payloads.

**Q39. How do you handle encoded or obfuscated attacks?**
> Every payload is percent-decoded up to four times, HTML-entity decoded,
> Unicode NFKC-folded, stripped of control characters and case-folded *before*
> any rule runs. A double-encoded traversal like `%252e%252e%252f` is still
> caught — we demonstrate that live.

**Q40. How do you avoid blocking legitimate users who look suspicious?**
> Rules match structure, not single characters. A bare apostrophe is FLAG
> severity, not BLOCK, because it appears in `O'Brien`. Our regression suite
> includes deliberately awkward legitimate requests — `?q=admin`, `?q=100%`,
> `european union`, `use the -- flag` — and asserts none is blocked. Layer 1
> measured zero false positives across 1,200 legitimate requests.

**Q41. Can an attacker bypass the gateway?**
> Not by network path — only port 5000 is published; the backend and Redis have
> no host mapping, which we verify. Earlier the backend was exposed on 8000,
> which made the gateway decorative; that is fixed.

**Q42. Can an attacker spoof their identity to evade rate limiting?**
> No. `X-Forwarded-For` is ignored unless the operator declares how many trusted
> proxy hops sit in front. An integration test rotates the header across 80
> requests and asserts the limiter still engages.

**Q43. Do you store sensitive data?**
> No. The event log stores a numeric feature vector and a SHA-256-truncated
> client id. Raw bodies are never written. We verified this by grepping the full
> 35,000-event corpus for passwords, tokens and cookies — zero matches, despite
> thousands of login requests.

**Q44. What is the risk of loading pickled models?**
> Pickle is arbitrary code execution. Anyone who can write the model directory
> owns the gateway process. We mount the model volume read-only in production,
> and the gateway refuses to load a model whose feature contract does not match.

---

## 7 · Engineering

**Q45. Is it really under 20 ms?**
> At the median, yes: 10.96 ms detection, 14.83 ms end-to-end, with 93.4% of
> requests under 20 ms. But p95 is 23.4 ms and p99 is 52.8 ms, so the honest
> claim is "median under 20 ms" on our hardware — Docker Desktop for Windows,
> single worker, under concurrent load.

**Q46. Why FastAPI?**
> Async I/O suits a proxy that spends most of its time waiting on the upstream.
> It also gives typed request handling and a small dependency surface.

**Q47. Why Redis?**
> Rate limiting needs shared state across workers with millisecond access and
> automatic expiry. Sorted sets give exact sliding windows; HyperLogLog counts
> distinct endpoints in constant memory, which is how we detect scanning.

**Q48. Model inference is synchronous. Doesn't that block the async loop?**
> It would, so we run it in a thread pool. We also use one pooled HTTP client for
> the whole process — the earlier version created a new client per request, which
> threw away connection reuse.

**Q49. How do you know the code works?**
> 92 automated tests covering rule detection, the legitimate-traffic corpus,
> feature contracts, fail-closed behaviour, hostile input, and live end-to-end
> checks. The suite found a real bug: `/.git/config` was slipping past a rule
> whose regex consumed the trailing slash.

---

## 8 · Limitations *(rehearse these — they are the most likely questions)*

**Q50. What is your biggest weakness?**
> The ML layers were trained on synthetic traffic and do not transfer to a
> different client population. Against a different legitimate traffic source they
> produced a 24.65% false-positive rate. That is why they ship advisory-only.

**Q51. So your system does not actually block with AI right now?**
> Correct, and that is deliberate. The default mode is `enforce-l1`: the
> deterministic rules block — they measured zero false positives — while the ML
> layers log the decision they would have made. You promote to full enforcement
> after retraining on traffic captured from the real deployment. That is standard
> practice for anomaly-based security products; you never enable automatic
> blocking on day one.

**Q52. Why didn't calibration fix it?**
> It cannot. About 8% of that foreign traffic saturates the anomaly score at
> 0.999 or above, where it is inseparable from attacks at *any* threshold.
> Calibration moves the cut-off; it cannot separate points that already share a
> value. Our tool detects this and refuses to write a threshold rather than
> silently disabling the detector.

**Q53. What would you do with three more months?**
> Collect real traffic and retrain on it — that fixes the root cause. Validate on
> CSIC 2010 for a number that is not self-generated. Collect more sessions to
> tighten the zero-day interval. Add authentication to the admin endpoints. Run
> adversarial evasion tooling against Layer 1.

**Q54. Is this production-ready?**
> Layer 1 is. It is deterministic, measured zero false positives, and blocks 31
> of 31 attack patterns. Layers 2 to 4 need training on the target deployment's
> real traffic before they can be trusted to block. We are explicit about that
> split rather than claiming the whole system is ready.

---

## 9 · Trap questions

**Q55. Your accuracy is 95%. Isn't 99% better?**
> Not necessarily. A higher accuracy usually means a higher threshold, which
> means missing more attacks. What matters is the balance: we catch 89.9% of
> attacks while wrongly blocking 1.95% of legitimate traffic. Chasing accuracy
> alone would make the system worse at its job.

**Q56. Your zero-day recall dropped from 0.887 to 0.598. Did your system get worse?**
> No — our *measurement* got more honest. 0.887 was one run. When we repeated the
> experiment 10 times the average was 0.598. The system did not change; we stopped
> quoting our best result.

**Q57. Isn't 27 false positives a lot?**
> Out of 1,385 legitimate test requests, that is 1.95%. For comparison the
> deterministic layer had zero. It is why the ML layer runs advisory-only until
> retrained on real traffic — we treat that figure as too high, not acceptable.

**Q58. Why should the panel believe your numbers?**
> Because everything is reproducible: `train.py` with a fixed seed, `validate.py`
> for the confidence intervals, `compare.py` for the significance test, and
> `pytest` for the behaviour. And because we report the numbers that make us look
> worse — the 10-seed averages, the 24.65% false-positive rate, and the seed
> variance — alongside the ones that look good.

**Q59. What did *you* personally implement?**
> *(Answer honestly and specifically — name your files and your part of the
> pipeline. A vague answer here undoes a good presentation.)*

---

## If you are asked something you do not know

> "I don't have that measurement — I'd rather not guess. What I can tell you is
> [the closest thing you did measure]."

That answer costs you almost nothing. A confident wrong answer costs you the
rest of the viva.
