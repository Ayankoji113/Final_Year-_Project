# Report on Intellectual Property Rights and Patents
### With reference to the project *MicroAPI Guard — A Backend-Agnostic ML API Security Gateway*

---

## i) What is IPR?

**Intellectual Property Rights (IPR)** are the legal rights granted to a person or
organisation over the creations of their mind — inventions, designs, literary and
artistic works, symbols, names and images used in commerce. Intellectual property is
*intangible* property: unlike a machine or a building, it can be copied at near-zero
cost, so the law creates an artificial, time-limited monopoly to give creators an
incentive to invent and to disclose.

The main categories of IPR are:

| Type | Protects | Typical Term (India) | Governing Act |
|---|---|---|---|
| **Patent** | New, inventive, industrially applicable technical inventions | 20 years from filing | Patents Act, 1970 |
| **Copyright** | Original literary, dramatic, musical, artistic works — **including computer source code** | Life of author + 60 years | Copyright Act, 1957 |
| **Trademark** | Brand names, logos, marks distinguishing goods/services | 10 years, renewable indefinitely | Trade Marks Act, 1999 |
| **Industrial Design** | Aesthetic shape, configuration, ornamentation of an article | 10 + 5 years | Designs Act, 2000 |
| **Trade Secret** | Confidential business/technical information | Unlimited, while secrecy lasts | Contract / common law |
| **Geographical Indication** | Goods originating from a specific region | 10 years, renewable | GI Act, 1999 |

At the international level IPR is coordinated by **WIPO** (World Intellectual Property
Organization) and harmonised by the **TRIPS Agreement** under the WTO, to which India is
a signatory.

**Relevance to this project.** The source code of MicroAPI Guard is automatically
protected by **copyright** the moment it is written. The name and logo could be protected
as a **trademark**. The *technical method* — the four-layer cascade of signature rules,
Isolation Forest, autoencoder and meta-learner with an FPR-budgeted threshold — is the
part that would be the subject of a **patent**.

---

## ii) What is a Patent?

A **patent** is an exclusive right granted by the State to an inventor, for a limited
period, in exchange for a full public disclosure of the invention. It gives the patentee
the right to **exclude** others from making, using, selling, offering for sale or
importing the invention without permission. It is a *negative* right — it does not by
itself grant the right to practise the invention, only to stop others.

### Conditions of patentability (Sections 2(1)(j), 2(1)(ja), 3 and 4, Patents Act, 1970)

1. **Novelty** — the invention must not form part of the "prior art", i.e. not published,
   used or disclosed anywhere in the world before the priority date.
2. **Inventive Step / Non-obviousness** — it must involve a technical advance or economic
   significance that is not obvious to a *person skilled in the art*.
3. **Industrial Applicability** — it must be capable of being made or used in industry.
4. **Not falling under Sections 3 and 4** — the excluded categories.

### The critical exclusion for a software project — Section 3(k)

Section 3(k) bars *"a mathematical or business method or a computer programme per se or
algorithms."* This is the single biggest hurdle for a software patent in India. The
**CRI Guidelines (Computer Related Inventions, 2017)** clarify that a claim is allowable
if the software produces a **technical effect** or works in combination with **novel
hardware** — for example improving the security, throughput, memory usage or reliability
of a computing system, rather than merely automating a mental or business process.

For MicroAPI Guard, a claim drafted as *"a machine-learning algorithm for classifying
requests"* would be refused under 3(k). A claim drafted as *"a gateway apparatus that
reduces intrusion-detection false positives while sustaining sub-15 ms inference latency
by cascading a signature stage with a stacked unsupervised ensemble"* asserts a concrete
**technical effect on the operation of the computer and the network**, and is far more
defensible.

**Types of patent applications:** Ordinary, Provisional, Complete, Convention, PCT
National Phase, Divisional, and Patent of Addition.

---

## iii) What is the Need of a Patent?

1. **Exclusivity and protection from copying.** Without a patent, a competitor who sees
   the deployed gateway can reimplement the four-layer pipeline and sell it, and the
   inventor has no remedy — copyright protects only the *expression* (the code as
   written), not the *idea or method*, which can be freely re-coded.
2. **Return on R&D investment.** Building, training, tuning and validating a detection
   pipeline costs time, compute and expertise. A 20-year monopoly is the mechanism by
   which that investment is recovered.
3. **Commercialisation instruments.** A patent is a transferable asset. It can be
   **licensed** (royalty income), **assigned** (sold outright), or contributed to a joint
   venture. Start-ups are frequently valued on their patent portfolio.
4. **Attracting investment.** Venture-capital and incubator due diligence explicitly
   examines IP ownership; even a filed provisional materially improves valuation and
   credibility.
5. **Defensive value and freedom to operate.** A portfolio deters infringement suits and
   provides cross-licensing leverage against larger competitors.
6. **Public disclosure and knowledge diffusion.** In return for the monopoly the
   invention is published, so society gains a searchable technical record; after 20 years
   it enters the public domain.
7. **Establishing priority.** In a first-to-file system the filing date fixes ownership.
   Publishing a paper *before* filing destroys novelty worldwide.
8. **Academic and institutional credit.** For a final-year project, a filed patent
   strengthens the originality claim and the institution's IPR record.

---

## iv) What is the Significance of a Patent?

### To the inventor
- A legally enforceable monopoly for 20 years from the date of filing.
- Formal recognition of authorship and technical contribution.
- Convertible into revenue through licensing, assignment or a product business.

### To industry and the economy
- Encourages sustained R&D spending by making innovation profitable.
- Creates a **technology market**: patents can be traded, pooled and cross-licensed.
- The published patent database is one of the largest technical literatures in the world
  — a large share of the technical information disclosed in patents appears nowhere else,
  so patent searching prevents duplicated research effort.

### To society
- Guarantees eventual free public access once the term expires (generic medicines being
  the classic example).
- Enforces disclosure: the *quid pro quo* of patent law is that secrecy is traded for
  protection, so knowledge is not lost when a company folds.

### In the specific context of cyber-security software
- Security methods are easy to reverse-engineer from observable behaviour, so trade
  secrecy alone is weak; patents are one of the few durable protections.
- A patent lets the method be **published and peer-reviewed** — important for a
  scientific security claim — without surrendering commercial rights, *provided filing
  precedes publication*.
- **Caution:** patenting also means full disclosure of the detection logic, which an
  attacker can read. Many security vendors therefore patent the *architecture* while
  keeping the *specific rule set, thresholds and trained weights* as trade secrets. That
  hybrid strategy suits MicroAPI Guard: patent the cascade and the calibration mechanism;
  keep the 26 L1 signatures and the learned model parameters confidential.

---

## v) Five Patents Related to Our Project

The following granted patents constitute the closest located prior art to MicroAPI Guard.
They were found by keyword search on Google Patents and USPTO Patent Public Search.

**1. US 8,990,942 B2 — "Methods and systems for API-level intrusion detection"**
Closest match in *domain*: detects intrusions at the API/application layer rather than the
packet layer, with IDS rules coded alongside the application.
*Distinction:* rule-driven and application-coupled. MicroAPI Guard is **backend-agnostic**
— a reverse proxy requiring no change to the protected application — and layers
unsupervised ML above the rules.

**2. US 10,270,788 B2 — "Machine learning based anomaly detection"**
Constructs activity models on a per-tenant and per-user basis using an **online streaming
machine learner**, scoring deviations from the learned profile.
*Distinction:* a single behavioural model. Ours is a **stacked four-layer cascade**
(signature rules → Isolation Forest → autoencoder → supervised meta-learner) with an
explicit false-positive budget governing the decision threshold.

**3. US 11,934,563 B2 — "Anomaly detection apparatus, anomaly detection method, and
computer-readable medium"**
Computes an anomaly score for network data using the **Isolation Forest** — directly
overlapping our L2 stage.
*Distinction:* claims Isolation-Forest scoring generally; does not cover combining it with
a reconstruction-error autoencoder under a learned meta-classifier, nor HTTP/API request
feature extraction.

**4. US 10,911,468 B2 — "Sharing of machine learning model state between batch and
real-time processing paths for detection of network security issues"**
Addresses the train/serve split — the same class of problem our shared `common/` feature
module solves (train–serve symmetry).
*Distinction:* concerned with synchronising model state across two pipelines. Ours
enforces symmetry through a **feature contract validated at model-load time** (the gateway
refuses to start on a feature mismatch) and adds an offline **calibration** step that
adapts to a new backend without retraining.

**5. US 7,424,744 B1 — "Signature based network intrusion detection system and method"**
Corresponds to our L1 stage: deterministic signature matching against known attack
patterns.
*Distinction:* purely signature-based and therefore blind to zero-day attacks. Our L1
exists only as a fast pre-filter; L1-blocked requests are excluded from the ML stages, and
**withheld novel attack families** (`cmdi`, `exfil`, `ssti`) are used to measure genuine
zero-day recall.

### Interpretation of the search

| Prior-art element | Covered by | Present in our work |
|---|---|---|
| API-layer intrusion detection | US 8,990,942 | Yes — but backend-agnostic |
| Behavioural ML anomaly scoring | US 10,270,788 | Yes — as one of four layers |
| Isolation Forest scoring | US 11,934,563 | Yes — L2 only |
| Train/serve model-state consistency | US 10,911,468 | Yes — via feature contract |
| Signature matching | US 7,424,744 | Yes — L1 pre-filter |
| **All five combined + FPR-budgeted, session-partitioned calibration** | **none located** | **Yes** |

No single located patent claims the combination of (a) a backend-agnostic reverse-proxy
gateway, (b) a four-stage cascade of signature rules → Isolation Forest → autoencoder →
supervised meta-learner, (c) a decision threshold selected on a held-out validation split
under an explicit false-positive-rate budget, and (d) an offline re-calibration procedure
that adapts the baseline to a new backend *without* retraining the base detectors. That
combination is the plausible **novelty and inventive step**. A formal patentability search
by a registered patent agent would still be required before filing, since this search
covered only English-language full-text databases.

---

## vi) Procedure to File a Patent (India — Patents Act, 1970)

### Step 0 — Patentability / prior-art search
Search **InPASS** (Indian Patent Advanced Search System, `ipindiaservices.gov.in/publicsearch`),
**Google Patents**, **Espacenet**, **USPTO Patent Public Search** and **WIPO PATENTSCOPE**.
Confirm novelty, inventive step and industrial applicability, and check that the invention
escapes Section 3(k). *Do not publish, demonstrate or open-source the invention before
filing.*

### Step 1 — Drafting the specification
A **provisional specification** (title, field, description of the invention) may be filed
first to secure an early priority date at low cost; the **complete specification** — title,
field, background, summary, brief description of drawings, detailed description,
**claims**, abstract — must then be filed **within 12 months**. The **claims** define the
legal scope and are the most critical part; they are normally drafted with a registered
patent agent.

### Step 2 — Filing the application
File online at the **IP India e-filing portal** (`ipindiaservices.gov.in/efiling`) with
one of the four patent offices — **Delhi, Mumbai, Kolkata (HQ) or Chennai** — determined
by the applicant's place of residence or business.

| Form | Purpose |
|---|---|
| **Form 1** | Application for grant of patent |
| **Form 2** | Provisional / Complete specification |
| **Form 3** | Statement and undertaking regarding foreign applications (Sec. 8) |
| **Form 5** | Declaration as to inventorship (with complete specification) |
| **Form 9** | Request for early publication (optional) |
| **Form 18** | **Request for Examination (RFE)** — mandatory |
| **Form 26** | Power of Attorney, if filed through an agent |
| **Form 28** | Claim for small-entity / startup / MSME status (fee concession) |

**Fees (indicative, e-filing):** natural person / startup / small entity ≈ ₹1,600;
large entity ≈ ₹8,000, plus excess-claim and excess-page fees. Students, individual
inventors and DPIIT-recognised startups qualify for the concessional slab, and the
**SIPP scheme** (Startups Intellectual Property Protection) provides a government-funded
facilitator.

### Step 3 — Publication
The application is published in the **Official Journal of the Patent Office** **18 months**
after the priority date (Sec. 11A). Filing **Form 9** requests early publication (about one
month), which starts provisional rights sooner.

### Step 4 — Request for Examination (Form 18)
Must be filed **within 31 months** of the priority date. Examination does **not** start
automatically — if the RFE is not filed in time the application is **deemed withdrawn**.
**Expedited examination (Form 18A)** is available to startups, small entities, female
applicants and PCT cases where India was the ISA/IPEA.

### Step 5 — Examination and the First Examination Report (FER)
The Controller issues an **FER** raising objections on novelty, inventive step, Section 3
exclusions, clarity and formalities. The applicant must **put the application in order for
grant within 6 months** of the FER (extendable by 3 months on Form 4) by filing a written
reply with amended claims if required.

### Step 6 — Hearing
If objections are not resolved on paper, the Controller offers a **hearing**; written
submissions follow within 15 days of it.

### Step 7 — Grant
On satisfaction the patent is **granted**, assigned a patent number, entered in the
Register of Patents and published in the Official Journal.

### Step 8 — Opposition
- **Pre-grant opposition (Sec. 25(1))** — by any person, after publication and before grant.
- **Post-grant opposition (Sec. 25(2))** — by an interested person within **12 months** of
  publication of the grant.

### Step 9 — Maintenance
**Renewal fees** are payable annually from the **3rd year** onward, and **Form 27**
(statement of working) must be filed periodically. Non-payment causes the patent to
**lapse**. The term is **20 years from the date of filing**, non-renewable.

### Filing abroad
- Under **Section 39**, an Indian resident must obtain **foreign filing permission** from
  the Controller, or wait six weeks after the Indian filing, before filing abroad.
- The **PCT (Patent Cooperation Treaty)** route allows one international application within
  12 months of the Indian priority date, deferring the choice of countries (the "national
  phase") to **30/31 months** from priority.
- The **Paris Convention** route allows direct filing in member countries within 12 months
  of priority.

### Indicative timeline

```
Day 0        Provisional filing — priority date secured
+12 months   Complete specification (Form 2) must be filed
+18 months   Automatic publication (or ~1 month via Form 9)
+31 months   Deadline for Request for Examination (Form 18)
~2-4 years   First Examination Report -> reply within 6 (+3) months
~3-5 years   Grant
3rd year on  Annual renewal fees; term ends 20 years from filing date
```

---

## Conclusion

Intellectual property rights convert an intangible technical contribution into a
defensible, tradeable asset. For **MicroAPI Guard** the source code is already protected by
copyright, but that protection is thin — it stops copying of the code, not
reimplementation of the method. The prior-art survey in Section (v) shows that API-level
intrusion detection, Isolation-Forest scoring, streaming behavioural anomaly models,
train/serve model-state consistency and signature-based IDS are each individually patented,
but the specific **backend-agnostic four-layer cascade with an FPR-budgeted,
session-partitioned evaluation and an offline recalibration path** does not appear to be
claimed by any single one of them. That combination is therefore the appropriate subject of
a patent claim, drafted to emphasise the **technical effect** on the computing system so as
to survive Section 3(k). The recommended strategy is a **provisional filing first** — cheap,
fast, fixes priority, and permits publication of the project paper afterwards — followed by
a complete specification within twelve months, with the trained model parameters and the
signature rule set retained as trade secrets.

---

### Sources

- [US8990942B2 — Methods and systems for API-level intrusion detection](https://patents.google.com/patent/US8990942B2/en)
- [US10270788B2 — Machine learning based anomaly detection](https://patents.google.com/patent/US10270788B2/en)
- [US11934563 — Anomaly detection apparatus, anomaly detection method, and computer-readable medium](https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/11934563)
- [US10911468 — Sharing of machine learning model state between batch and real-time processing paths](https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/10911468)
- [US7424744B1 — Signature based network intrusion detection system and method](https://patents.google.com/patent/US7424744B1/en)
- [US11916944 — Network anomaly detection and profiling](https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/11916944) — additional background
- [US20060037077A1 — Network IDS with application inspection and anomaly detection](https://patents.google.com/patent/US20060037077A1/en) — additional background
