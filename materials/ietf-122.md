footer: IETF 122, Bangkok - RATS WG
slidenumbers: true
autoscale: true
theme: Plain Thomas

# AR4SI and EAR

## [draft-ietf-rats-ar4si](https://datatracker.ietf.org/doc/draft-ietf-rats-ar4si)
## [draft-fv-rats-ear](https://datatracker.ietf.org/doc/draft-fv-rats-ear)

### IETF 122, Bangkok - RATS WG

---

# Quick Recap

* AR4SI: Info and data model for Attestation Results
* EAR: EAT profile for Attestation Results based on AR4SI

For more details see:

* [Presentation @ CoCo](https://people.linaro.org/~thomas.fossati/preso/ear@coco-03212024.pdf)

---

# What's New in AR4SI

^devel paused for a while

Added CBOR and JSON data model to AR4SI

```
3.  Data Model
3.1.  Trustworthiness Vector
3.2.  Trustworthiness Tiers
3.3.  Verifier ID
3.4.  Consolitated CDDL
```

^so that actual AR formats can share core AR4SI types

---

# What's New in AR4SI (cont.)

Hot topics:

* "Executables" bucket split: boot-time and run-time [#28](https://github.com/ietf-rats-wg/draft-ietf-rats-ar4si/issues/28)
* Better Verifier identification [#30](https://github.com/ietf-rats-wg/draft-ietf-rats-ar4si/issues/30)
^finer-grained identification of the verifier

---

# What's New in EAR

^application domains that have been exercised: confidential computing, attestation in IoT, network equipment

EAR is adopted in some major open source verifiers, including Veraison, CoCo Trustee, and Keylime (WIP)

OSS implementations in Rust, C, Golang and Python (WIP)

Collecting claim names from different attesters - WIP by Yogesh 

^to come to a shared understanding between verifiers and RPs

---

# Next Steps

Continue collecting requirements and feedback re: TV claims

Please review §2.3.4 of AR4SI and send your comments

^refing the info model
^your feedback is critical, please review §2.3.4 of AR4SI

---

# [fit] adopt :ear:?

^discussion on the ML
^Kathleen, Carl and MCR were positive

---

# FIN
