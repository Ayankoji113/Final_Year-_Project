# MicroAPI Guard — Project Review Script

**For a 3-person team. Simple words. ~15 minutes + questions.**

| Who | Part | Time |
|---|---|---|
| Person A | The problem and what we built | 4 min |
| Person B | Live demo | 6 min |
| Person C | Results, honest limits, future work | 5 min |
| All | Questions | 5 min |

---

## Before you start (do this 10 minutes early)

Run these. Do not skip. If any step fails you still have time to fix it.

```powershell
cd D:\Final_Year_Project\src

# 1. Start everything
docker compose up -d

# 2. Wait ~20 seconds, then check it is alive
curl.exe http://localhost:5000/__guard/health
```

You should see `"status":"healthy"` and `"models_loaded":true`.

**Dashboard is NOT part of the demo.** Start it only as a backup in case a
panel member asks to see live monitoring:

```powershell
docker compose -f docker-compose.yml -f docker-compose.lab.yml up -d dashboard
```

**Checklist before the panel walks in:**

- [ ] `health` shows `healthy`
- [ ] Terminal font size is BIG (panel must read it from a distance)
- [ ] Metrics table printed or on a second screen for Q&A
- [ ] `docs/` folder open in case they ask for the report
- [ ] Backup screenshots ready (see "If the demo breaks")

---

## PERSON A — The problem and what we built (4 min)

### Say this

> "Today almost every app talks to a backend through APIs. Attackers know this,
> so APIs are now a main target.
>
> There are two normal ways to protect an API, and both have a problem.
>
> First, **fixed rules**. You write patterns like 'block anything containing
> DROP TABLE'. This is fast and exact. But it only catches attacks you already
> know about. A new attack walks straight through.
>
> Second, **machine learning**. It can catch new attacks. But it makes mistakes,
> and blocking real users is very costly.
>
> Our project, **MicroAPI Guard**, uses both together. It sits in front of any
> backend like a security guard at a gate. Every request must pass it first."

### Draw or show this

```
Client  ->  MicroAPI Guard  ->  Backend
                 |
                 |-- Layer 1: fixed rules + speed limit   (certain)
                 |-- Layer 2: Isolation Forest            (learns normal)
                 |-- Layer 3: Autoencoder (deep learning) (learns normal)
                 |-- Layer 4: Logistic Regression         (makes the decision)
```

### Explain the layers in simple words

> "**Layer 1** knows attack patterns. If it sees a clear attack, it blocks
> immediately. No need to ask the AI.
>
> **Layer 2 and Layer 3** never see any attacks during training. We only show
> them normal traffic. They learn what normal looks like. Then anything that
> does not look normal becomes suspicious. This is how we can catch attacks we
> have never seen before.
>
> **Layer 4** is the boss. Layers 1, 2 and 3 each give it a score. Layer 4
> looks at all three scores and makes the final decision."

### One important point to make

> "The gateway does not know anything about the backend. It does not know the
> URLs, the framework or the language. So you can put it in front of any API
> without changing that API's code."

**Hand over:** *"Now [Person B] will show it running."*

---

## PERSON B — Live demo (6 min · 7 steps)

**Golden rule: run one command, wait, explain what happened. Do not rush.**

### ⚠ Read this first — PowerShell, not bash

Type **`curl.exe`**, never plain `curl`. In PowerShell `curl` is an alias for
`Invoke-WebRequest`, which does not understand curl's flags — it will stop and
ask you for `Uri:` in the middle of your demo. If that happens, press
**Ctrl+C** and retype with `.exe`.

Every command below was tested in PowerShell and produces the output shown.

---

### Demo 1 — Normal traffic passes

```powershell
curl.exe -i "http://localhost:5000/api/products?page=1&limit=3"
```

**Result:**
```
HTTP/1.1 200 OK
content-type: application/json
x-guard-action: allow
```

> "This is a normal request. Status **200**. The header says
> `x-guard-action: allow`. The gateway checked it and let it through to the
> backend."

---

### Demo 2 — SQL injection is blocked

```powershell
curl.exe -G --data-urlencode "q=' UNION SELECT password FROM users --" "http://localhost:5000/api/search"
```

**Result:**
```json
{"error": "Request blocked by MicroAPI Guard",
 "layer": "L1-rules",
 "reason": "sqli.union: UNION SELECT is never emitted by a legitimate API client",
 "categories": ["sqli"]}
```

> "Blocked. And notice it tells us **why** and **which layer** did it.
> `L1-rules` means the fixed rules caught it. It never reached the backend."

---

### Demo 3 — A hidden attack is still caught

```powershell
curl.exe "http://localhost:5000/api/files/%252e%252e%252f%252e%252e%252fetc%252fpasswd"
```

**Result:** `traversal.dotdot: parent-directory escape`

> "This is the same attack — trying to read the server's password file — but the
> attacker has encoded it **twice** to hide it. Many simple filters miss this.
>
> We decode the request repeatedly before checking it, so we still catch it."

---

### Demo 4 — An attack inside a JSON body

PowerShell mangles quotes when passing JSON directly to `curl.exe`, so write the
body to a file first. **Two lines, then the request.**

```powershell
$body = '{"text":"<script>alert(1)</script>","product_id":1,"rating":5}'
$body | Set-Content "$env:TEMP\demo.json" -Encoding utf8 -NoNewline
curl.exe -X POST -H "Content-Type: application/json" -d "@$env:TEMP\demo.json" "http://localhost:5000/api/comments"
```

**Result:** `xss.script_tag: inline <script> tag` → **403**

> "The attack is hidden inside the JSON body, not the URL. We inspect the body
> too, so it is blocked."

---

### Demo 5 — The hard part: NOT blocking real users

**This is the most important demo. Slow down here.**

```powershell
curl.exe -s -o NUL -w "status=%{http_code}`n" "http://localhost:5000/api/search?q=admin"
```

> "A user searching for the word **admin**. A bad filter would block this.
> We return **200**."

```powershell
$ok = '{"username":"sean_ob","name":"Sean O''Brien","password":"secret123","email":"s@x.com"}'
$ok | Set-Content "$env:TEMP\demo.json" -Encoding utf8 -NoNewline
curl.exe -s -o NUL -w "status=%{http_code}`n" -X POST -H "Content-Type: application/json" -d "@$env:TEMP\demo.json" "http://localhost:5000/api/users/register"
```

> "This person's real name is **O'Brien**. It has an apostrophe, which also
> appears in SQL injection. The old version of our project would block this
> customer. We return **200**.
>
> We tested 1,200 normal requests. **Zero** were wrongly blocked."

*(In PowerShell, `''` inside a single-quoted string means one apostrophe. If you
re-run this, change `sean_ob` to a new name or you will get 409 "already
exists".)*

---

### Demo 6 — Speed limit (too many requests)

```powershell
1..45 | ForEach-Object { curl.exe -s -o NUL -w "%{http_code} " http://localhost:5000/api/products }
```

**Result:** about 38–40 × `200`, then `403 403 403 ...`

> "One client sending 45 requests very fast. The first 40 are allowed. After
> that the gateway starts blocking. Our limit is 40 requests in 5 seconds."

> ⚠ **Important:** after this demo your machine stays blocked for about
> 5 seconds. This is correct behaviour, not a bug. If the panel asks you to
> repeat an earlier demo, **count to six first**. To clear it instantly:
>
> ```powershell
> docker exec microapi-redis redis-cli FLUSHALL
> ```

---

### Demo 7 — Dashboard (OPTIONAL — only if they ask)

Do **not** open this by default. Go straight to the metrics with Person C.
If a panel member asks to see live monitoring, then switch to
`http://localhost:8501` and say:

> "The dashboard shows live traffic. Importantly, the **DECISION** column is
> Layer 4 — the boss. The **EVIDENCE** columns are the three detectors shown
> separately, so nobody thinks one detector decided on its own."

---

### If the demo breaks

Stay calm. Say: *"Let me show you the recorded results instead."*

Then open your backup screenshots. **Take these the night before.**

| Problem | Fix |
|---|---|
| It asks for `Uri:` | You typed `curl` not `curl.exe`. Ctrl+C, retype |
| `connection refused` | `docker compose restart gateway`, wait 20 s |
| Everything returns 403 | Rate limit from testing. `docker exec microapi-redis redis-cli FLUSHALL` |
| `models_loaded: false` | `docker compose restart gateway` |
| POST returns 422 | The JSON got mangled — use the `Set-Content` file method above |
| Dashboard blank | Send some traffic first, then refresh |

**Hand over:** *"Now [Person C] will explain our results."*

---

## PERSON C — Results and honest limits (5 min)

### Start with the biggest finding

> "The most important thing we found was in **our own earlier version**.
>
> The old version reported 98.8% F1 score. That looked excellent. But when we
> checked the data properly, we found the whole dataset had only **31 different
> requests**, copied thousands of times. The model had simply memorised 31
> answers. It had learned nothing useful.
>
> We rebuilt the data properly. Now we have 35,000 real varied requests."

### Show the results

**Say the confusion matrix first — panels always want it.**

**Confusion Matrix** (held-out test set, 2,127 requests):

|  | Predicted Normal | Predicted Attack |
|---|---|---|
| **Actual Normal** | 1358 | 27 |
| **Actual Attack** | 75 | 667 |

> "27 legitimate requests were wrongly blocked, and 75 attacks were missed, out
> of 2,127 test requests the model had never seen."

**Performance metrics:**

| Metric | Test set | 10 seeds (95% CI) |
|---|---|---|
| Accuracy | 0.9520 | — |
| Precision | 0.9611 | 0.978 [0.970 – 0.985] |
| Recall | 0.8989 | 0.764 [0.700 – 0.828] |
| F1-Score | 0.9290 | 0.854 [0.812 – 0.891] |
| ROC-AUC | 0.9926 | 0.987 [0.980 – 0.993] |
| PR-AUC | 0.9863 | 0.978 [0.968 – 0.986] |
| False Positive Rate | 0.0195 | 0.0099 [0.006 – 0.015] |
| False Negative Rate | 0.1011 | — |
| Zero-Day Recall | 0.8865 | 0.598 [0.445 – 0.749] |

**How to explain the two columns — this is the part that impresses a panel:**

> "The left column is one run. But one run can be lucky, so we repeated the
> whole training **10 times** with different random splits. The right column is
> the average with a 95% confidence interval.
>
> Precision, false-positive rate and ROC-AUC stay almost the same every time —
> those results are **stable**.
>
> Recall and zero-day detection move a lot. So we report the range honestly
> instead of only our best run."

**Layer 1 (the rules layer) — separate and much stronger:**

| | Result |
|---|---|
| Attack patterns blocked | 31 / 31 |
| False positives | 0 out of 1,200 |
| Median detection time | 10.96 ms |

**Explain why accuracy alone is not enough** (a panel may test you on this):

> "Accuracy is 95.2%, but accuracy can mislead in security. If 90% of traffic is
> normal, a system that allows everything already scores 90%.
>
> That is why we look at **recall** — how many attacks we catch — and the
> **false-positive rate** — how many real users we wrongly block. Those two
> matter far more than accuracy."

### Prove the ensemble was worth building

> "A panel could fairly ask: do you really need four layers? Maybe one is enough.
>
> So we tested each layer alone, and compared using **McNemar's test**."

| Model alone | F1 |
|---|---|
| Speed limit only | 0.515 |
| Isolation Forest only | 0.406 |
| Autoencoder only | 0.870 |
| **All four combined** | **0.929** |

*(These four numbers come from one single split. McNemar's test needs the exact
same test rows for every model, so it cannot be averaged over 10 runs. If a
panel member notices these differ from the averages above, that is the reason —
say so, it shows you understand the test.)*

> "The combination is better than every single part, and the test says this is
> statistically real, not luck. The p-value against the strongest single part is
> 0.000000000008."

### Be honest about the limit (this earns marks)

> "We must be honest about one thing.
>
> Our AI layers were trained on traffic we generated ourselves. When we tested
> them against a **different** kind of normal traffic, they wrongly blocked
> about 1 in 4 real requests. That is far too many.
>
> So we did not hide it. We changed the default setting.
>
> Right now the system runs in **enforce-l1** mode. The fixed rules block
> attacks — they are exact and safe. The AI layers only **watch and report**.
> They do not block anyone yet.
>
> Once the system runs on a real API for a few days, you retrain it on that real
> traffic, and then you switch the AI layers on.
>
> This is how real security products are deployed. You never turn on automatic
> blocking on day one."

### Finish with future work

> "Next steps:
> 1. Collect more traffic so the zero-day measurement becomes stable — right now
>    its range is too wide to make a strong claim.
> 2. Test against a public dataset like CSIC 2010.
> 3. Retrain on real API traffic and switch the AI layers to blocking mode."

---

## Likely panel questions — short answers

**Q: Why not just use one good model?**
> We tested that. Each single model scored much lower. We proved the combination
> is better using McNemar's test.

**Q: Why train on normal data only?**
> Because then we do not need examples of attacks. That is what lets us flag
> attacks nobody has seen before. We measured it by removing three attack types
> from training: average 59.8% caught, ranging from 44.5% to 74.9%.

**Q: Did you check if your results depend on the random split?**
> Yes. We ran it 10 times. Precision and false-alarm rate stayed stable. Recall
> and zero-day detection moved a lot, so we report the range, not one number.
> Our best single run looked much better, and we chose not to quote it.

**Q: How do you avoid cheating in your test?**
> We split by user session, not by row. The models that learn normal never see
> the test data. And we only look at the test set once, at the very end.

**Q: Why Logistic Regression and not something stronger?**
> It only takes 3 inputs. A bigger model adds no benefit at that size, and
> Logistic Regression lets us read the weights and check the model is sensible.

**Q: Is it really under 20 milliseconds?**
> At the middle value, yes — about 11 ms for detection. But we must be honest:
> the slowest 5% take longer, around 23 ms. So we say "median under 20 ms".

**Q: Why is the AI not blocking?**
> A safety choice. It was trained on generated traffic, and on different traffic
> it made too many mistakes. We turn it on after retraining on real traffic.

**Q: Does it work with any backend?**
> Yes. We removed anything backend-specific from the model. It only looks at the
> shape and speed of requests, not the URL names.

**Q: What if the AI part fails?**
> It blocks the request instead of allowing it. Failing open would let an
> attacker bypass us just by crashing the model.

---

## Things NOT to say

- ❌ "Our accuracy is 99%." — Do not lead with accuracy. Say recall and false positives.
- ❌ "It stops all attacks." — Say what we measured.
- ❌ "It is ready for production." — Say Layer 1 is ready; the AI needs real traffic first.
- ❌ Never hide the false-positive problem. **Explaining it is a strength.** It shows you tested properly.

---

## One-line summary if you only get 30 seconds

> "MicroAPI Guard is a security gate for APIs. It combines fixed rules with
> three machine learning layers. The rules block known attacks with zero false
> alarms in our tests, and the machine learning layers add detection for attacks
> we never trained on — measured over 10 runs, so the numbers are averages, not
> a best case."
