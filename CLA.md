# Defuse Contributor License Agreement

> **DRAFT — NOT YET REVIEWED BY A LAWYER.**
>
> This document was drafted to be clear rather than to be authoritative, and
> nobody qualified has checked it. It is here so the repository is not accepting
> contributions on no terms at all, which is the worse of the two states. Have a
> lawyer read it before you rely on it for a commercial licence sale, and see
> *Before this is final* at the bottom for what to give them.

## Why this exists

Defuse is released under **AGPL-3.0-only**. Copyright is currently held in one
place, which is what makes it possible to also offer a commercial licence to
organisations that cannot accept AGPL terms — chiefly because AGPL section 13
requires anyone who modifies the software and serves it over a network to
publish their source.

That arrangement only works while every line in the project can be licensed
both ways. A contribution accepted on no terms belongs to its author under AGPL
alone, and from that moment the project can no longer offer the whole of itself
under any other licence without going back to ask that person.

This agreement keeps that door open. **You keep your copyright.** You are
granting a licence, not signing your work away.

## What you are agreeing to

By submitting a contribution — a pull request, a patch, a fixture, or code in
any other form — you agree to the following.

**1. You have the right to contribute it.**
The contribution is your original work, or you have sufficient rights to submit
it under these terms. If your employer has rights to work you produce, you have
their permission, or they have waived those rights.

**2. You grant a copyright licence.**
You grant the project owner a perpetual, worldwide, non-exclusive, royalty-free
and irrevocable copyright licence to reproduce, modify, publicly display,
publicly perform, distribute and prepare derivative works of your contribution,
**and to sublicense these rights through multiple tiers**.

> That last clause is the operative one. Everything else in this document is
> ordinary housekeeping; the right to sublicense is the specific thing that lets
> your contribution be included in a commercially licensed copy alongside the
> AGPL one. A Developer Certificate of Origin — the `git commit -s` sign-off
> some projects use — does **not** grant it, which is why this project asks for
> a CLA instead.

**3. You grant a patent licence.**
You grant a perpetual, worldwide, non-exclusive, royalty-free and irrevocable
patent licence to make, use, sell, offer to sell, import and otherwise transfer
your contribution, covering only those patent claims you own or control that
are necessarily infringed by your contribution alone or by its combination with
the project.

**4. Your contribution stays yours.**
You retain all right, title and interest in your contribution. Nothing here is
an assignment of copyright. You may use, sell, license or contribute your own
work anywhere else, on any terms you like.

**5. It comes as-is.**
Unless required by law or agreed in writing, you provide your contribution
without warranties or conditions of any kind. You are not expected to provide
support for it.

**6. Tell us if something changes.**
If any statement above stops being accurate — for example, you discover you did
not have the rights you believed you had — please say so.

## How to sign

Sign once; it covers your future contributions too.

**Until automated signing is set up**, add this line to your first pull request
description, with your own details:

```
I have read CLA.md and I agree to it.
Name: <your full name>
GitHub: @<your username>
Date: <YYYY-MM-DD>
```

**Once automated**, [CLA Assistant](https://github.com/cla-assistant/cla-assistant)
will comment on your pull request with a link, record your signature against
your GitHub account, and mark the check green. It is free and open source, and
it is the usual way projects handle this.

## If you would rather not

That is a completely reasonable position and plenty of good developers hold it.

Open an issue instead. A clear bug report, a minimal reproducer, or a failing
fixture with an explanation is genuinely valuable to this project and carries no
agreement of any kind. Documentation corrections and typo fixes will not be
turned away over paperwork either.

## Before this is final

For whoever reviews this, the specifics that matter:

- The intent is **open-core with dual licensing**: AGPL-3.0-only publicly, with
  a separate commercial licence for organisations that cannot accept section 13.
- The sublicensing grant in clause 2 is the clause the commercial licence
  depends on. If it has to change, the business model changes with it.
- Two established templates to adapt rather than starting from this draft: the
  **Apache Individual Contributor License Agreement (ICLA)**, which most
  dual-licensed projects base theirs on, and the **Harmony Agreements**, which
  were designed specifically for this situation and come in both a licence
  variant (HA-CLA-I) and an assignment variant (HA-CA-I).
- Worth asking specifically: how enforceable a "by opening a pull request you
  agree" acceptance is in the relevant jurisdiction, versus a recorded
  click-through signature. This draft assumes the second is stronger, which is
  why CLA Assistant is the intended destination.
- Also worth asking: whether corporate contributors need a separate entity-level
  agreement (a CCLA) rather than relying on clause 1.
