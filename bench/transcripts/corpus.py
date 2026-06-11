"""
Generate synthetic meeting transcripts with gold-standard PII annotations.
Gold annotations: list of {start, end, label, text} dicts (char offsets).
Must-not-touch spans: code blocks, inline code, URLs inside code.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Tuple


@dataclass
class Span:
    start: int
    end: int
    label: str
    text: str


@dataclass
class Transcript:
    name: str
    content: str
    pii: List[Span]           # must-redact
    safe: List[Span]          # must-NOT-redact (code blocks, inline code, URLs in code)


def _find_all(haystack: str, needle: str) -> List[Tuple[int, int]]:
    results = []
    start = 0
    while True:
        idx = haystack.find(needle, start)
        if idx == -1:
            break
        results.append((idx, idx + len(needle)))
        start = idx + 1
    return results


def _span(doc: str, needle: str, label: str) -> Span:
    idx = doc.find(needle)
    if idx == -1:
        raise ValueError(f"PII token {needle!r} not found in document")
    return Span(idx, idx + len(needle), label, needle)


def _spans(doc: str, tokens: List[Tuple[str, str]]) -> List[Span]:
    result = []
    for token, label in tokens:
        try:
            result.append(_span(doc, token, label))
        except ValueError:
            print(f"WARNING: {token!r} not found - skipping")
    return result


def _safe_spans(doc: str, tokens: List[str]) -> List[Span]:
    result = []
    for token in tokens:
        for start, end in _find_all(doc, token):
            result.append(Span(start, end, "SAFE_CODE", token))
    return result


TRANSCRIPT_1 = """\
# Project Kick-off — Geneva Tech Freedom Initiative
**Date:** 2026-06-10  **Facilitator:** Moderator A

---

**Alice Nguyen:** Good morning everyone. Let's get started. I'm Alice Nguyen, lead
counsel at Walsh & Partners. My direct line is (415) 882-3310 if anyone needs
to reach me outside this call.

**Bob Okonkwo:** Bob Okonkwo here, from the Zurich office. My email is
b.okonkwo@ztech.ch if you prefer async.

**Alice Nguyen:** Great. First agenda item: the data-processing agreement. Bob,
can you share the draft?

**Bob Okonkwo:** Sure. I sent it to a.nguyen@walshandpartners.com last Tuesday.
The vendor's registered address is 14 Bahnhofstrasse, Zürich, CH-8001.

**Alice Nguyen:** Got it. Their data-protection officer is listed as Priya
Chandrasekaran. Do we have her contact?

**Bob Okonkwo:** Yes — p.chandrasekaran@vendor.io. Her office number is
+41 44 555 01 23.

**Alice Nguyen:** Perfect. Let's also note that the payment will be wired to
IBAN CH93 0076 2011 6238 5295 7, reference Walsh-ZTF-2026.

**Moderator A:** Any other business?

**Bob Okonkwo:** One flag: the vendor asked for our company VAT number. It's
CHE-123.456.789.

**Alice Nguyen:** Thanks. Meeting adjourned.
"""

TRANSCRIPT_2 = """\
# Engineering Sync — Authentication Refactor
**Date:** 2026-06-09  **Host:** DevOps lead

---

**Sam Rivera:** Hey team. Before we dive in — quick heads up, I'll be on holiday
from June 20. Reach me at sam.rivera@corp.example.com or cell five five five
two two four seven eight nine zero if urgent.

**Dev 2 (Jordan):** Got it Sam. Jordan Park here. We merged the auth PR yesterday.
The new token endpoint is at `/api/v1/auth/token`.

**Sam Rivera:** Nice. Anyone know if the OIDC config needs updating? The client
secret for prod is currently stored in Vault at `secret/prod/oidc/client_secret`.

**Jordan:** No — environment-level. Here's the relevant snippet from the config:

```yaml
oidc:
  client_id: "app-prod-1234"
  issuer: "https://auth.example.com"
  redirect_uri: "https://app.example.com/callback"
```

**Sam Rivera:** Perfect. One thing — the legacy code still has the old admin
password hardcoded. That password is hunter2 (I know, I know — removing it
this sprint).

**Jordan:** Yikes. Also, the on-call rotation: Sam Rivera is week 1, I'm week 2,
then Mia Tanaka week 3. Mia's pager number is 555-0134.

**Sam Rivera:** Thanks Jordan. Let's wrap. My home address for the hardware
shipment is 308 Negra Arroyo Lane, Albuquerque, NM 87104.
"""

TRANSCRIPT_3 = """\
# HR Interview — New Hire Onboarding
**Date:** 2026-06-08

---

**HR Rep (Chen Wei):** Welcome! I'm Chen Wei from HR. So let's start with your
background check details. Full legal name?

**Candidate:** Marcus Elliot Beaumont.

**Chen Wei:** Date of birth?

**Candidate:** March fourteenth, nineteen ninety-one. That's 1991-03-14.

**Chen Wei:** Social security number?

**Candidate:** 432-18-6792.

**Chen Wei:** Home address?

**Candidate:** 77 Orchard Street, Apartment 4B, Brooklyn, New York, 11211.

**Chen Wei:** Personal email?

**Candidate:** m.beaumont@gmail.com. And my cell is (718) 554-0987.

**Chen Wei:** We'll also need your bank details for payroll direct deposit.

**Candidate:** Routing number zero two six zero zero nine five nine three,
account four four seven eight eight two one zero three.

**Chen Wei:** Great. And we'll need a scan of your passport — number
US9876543. We also have your emergency contact on file: your sister
Laura Beaumont, reachable at laura.beaumont@outlook.com.

**Chen Wei:** Perfect. I'll send the offer letter to m.beaumont@gmail.com
today.
"""

TRANSCRIPT_4 = """\
# Board Meeting Notes — Finance Review
**Date:** 2026-06-07

---

**CFO (Dmitri Volkov):** Good afternoon. I'm presenting the Q2 figures.

**Board Chair:** Thanks Dmitri. Could you also confirm the wire details for the
dividend payment?

**Dmitri Volkov:** Yes. Corporate account at First National: ABA routing
021000021, account number 1234567890. The payment goes to Yuki Yamazaki —
she's our liaison at the Tokyo office. Her contact is yuki.yamazaki@fnb.co.jp,
+81 3 5555 7890.

**Board Member (Rosa Chen):** What about the European entity? We need the
IBAN for the tax authority filing.

**Dmitri Volkov:** That's DE89 3704 0044 0532 0130 00. And our European
entity's tax ID is DE 123456789.

**Rosa Chen:** Great. The auditor confirmed our last four credit card digits
for the corporate card: the full number is 4916338506082832. They Luhn-checked it.

**Dmitri Volkov:** One more thing — the Swiss regulatory filing requires my
personal address: Seefeldstrasse 47, 8008 Zürich, Switzerland.

**Board Chair:** Thank you Dmitri. Anything else?

**Rosa Chen:** Rosa Chen signing off. My direct line remains +1 (212) 555-0193.

---

*These minutes are confidential — do not distribute.*
"""

TRANSCRIPT_5 = """\
# Legal Hold Notice — Case Matter 2026-4417
**Date:** 2026-06-06  **Prepared by:** Paralegal team

---

**Lead Attorney (Sarah O'Brien):** Team, this is a legal hold meeting for
matter 2026-4417.

**Paralegal (Devon Marsh):** Devon Marsh here. The custodian list includes:

- Thomas Grunewald, tgrunewald@respondent.com, ext. 4421
- Amara Diallo, a.diallo@respondent.com, mobile +33 6 12 34 56 78
- Ingrid Svensson, isvensson@respondent.com

**Sarah O'Brien:** Thanks Devon. Thomas Grunewald's personal address for
service is 12 rue de la Paix, 75002 Paris, France.

**Devon Marsh:** Noted. The matter also involves a payment of €45,000
via IBAN FR76 3000 6000 0112 3456 7890 189.

**Sarah O'Brien:** And the corporate credit card used in the alleged transaction:
5105105105105100. That's a Mastercard, Luhn-valid.

**Devon Marsh:** One technical note — the forensic image is stored at the
following hash, for chain of custody:

```
SHA-256: e3b0c44298fc1c149afb4c8996fb92427ae41e4649b934ca495991b7852b855
```

**Sarah O'Brien:** Do not confuse that hash with any personal identifier — it
is a file hash, not a document ID. Proceeding with the hold.

**Devon Marsh:** One more: the opposing counsel's contact is
james.harrington@litigatelaw.com, (617) 555-2298.

**Sarah O'Brien:** Good. Sarah O'Brien, sign-off. My bar number is
BBO#682341, Massachusetts.
"""

TRANSCRIPT_6 = """\
# Security Incident Debrief — Ticket INC-2026-8812
**Date:** 2026-06-05

---

**Security Lead (Felix Hartmann):** We're debriefing INC-2026-8812. I'm
Felix Hartmann, CISO.

**Analyst (Priya Singh):** Priya Singh, incident response. The attacker's
egress IP was 203.0.113.45. The affected account credential belonged to
a contractor — I'll refer to her by case ID CR-441. Her personal email
on file: nadia.hassan@contractor.io.

**Felix Hartmann:** What was the exfiltrated data?

**Priya Singh:** Partial employee records — names, SSNs. The sample we
recovered includes one entry: James Okafor, SSN 567-89-0123.

**Felix Hartmann:** Notify James Okafor at his HR email j.okafor@corp.example.com
and personal j.okafor.personal@gmail.com. His cell from HR records: (312) 555-8741.

**Priya Singh:** The attacker used the following exploit chain in the PoC:

```python
payload = b'\\x90' * 100 + shellcode  # NOP sled + shellcode
# Target IP: 10.0.0.1 (internal — do not redact)
sock.connect(('10.0.0.1', 4444))
```

**Felix Hartmann:** 10.0.0.1 is internal lab — correct, do not redact that.
Felix Hartmann's direct mobile for escalations: +49 89 555 0276.

**Priya Singh:** Also flagged: the compromised AWS key ID was AKIAIOSFODNN7EXAMPLE.
It's been rotated, but log it for audit.
"""

TRANSCRIPT_7 = """\
# Sales Discovery Call — Prospect: NovaMed Inc.
**Date:** 2026-06-04

---

**AE (Grace Liu):** Thanks for joining. I'm Grace Liu, account executive at
DataGuard Pro. My email is grace.liu@dataguardpro.com.

**Prospect (Oliver Prentiss):** Oliver Prentiss, VP of IT at NovaMed.
oliver.prentiss@novamed.com, direct: (206) 555-7734.

**Grace Liu:** Happy to meet you Oliver. Can you tell me more about your
current PII handling workflow?

**Oliver Prentiss:** Sure. We process patient records — names, DOBs, insurance
IDs. Our chief compliance officer is Dr. Helena Krause —
h.krause@novamed.com, +1 (206) 555-8811.

**Grace Liu:** We'd need a data-processing addendum. The billing contact
should be your AP team.

**Oliver Prentiss:** That's accounts@novamed.com. Wire payments go to:
routing 121000248, account 7654321098.

**Grace Liu:** One patient record we'd use as a test case in the sandbox —
redacted per HIPAA, but worth noting the format: patient ID MRN-449012,
DOB 1978-11-22, insurance member ID UHC-884-22-9971.

**Oliver Prentiss:** Right. And my personal cell for urgent matters:
+1 (206) 555 1337, or personal email oliver@prentiss-family.net.

**Grace Liu:** Perfect. I'll send a follow-up to oliver.prentiss@novamed.com.
"""

TRANSCRIPT_8 = """\
# Weekly All-Hands — Remote Team
**Date:** 2026-06-03

---

**CEO (Martina Bauer):** Good morning everyone. Martina Bauer speaking.
Quick announcements:

First — congratulations to Kwame Asante on his promotion. Kwame, your new
title is Senior Engineer, effective June 15. Your new contact will be
k.asante@company.com.

**Kwame Asante:** Thanks Martina! Really excited.

**Martina Bauer:** Second — IT reminder. For VPN access, the shared secret
in our docs is `vpn-shared-secret-DO-NOT-LOG`. Nobody log that.
Actually let me correct: the real passphrase is stored at `secret/vpn/psk`
in Vault. The example in our runbook uses a placeholder:

```bash
openssl s_client -connect vpn.company.com:443 -psk "PLACEHOLDER_SECRET"
```

That PLACEHOLDER_SECRET is not the real value — it's a template.

**Kwame Asante:** Got it. Also: the new developer webhook token is in the
environment: `WEBHOOK_TOKEN=abc123secretXYZ`. Please don't hardcode that —
it's already rotated as of this morning.

**Martina Bauer:** Right. Our mailing address for legal correspondence remains
999 Market Street, Suite 800, San Francisco, CA 94103.

**Kwame Asante:** My home office address for equipment delivery:
52 Juniper Lane, Austin, TX 78704.

**Martina Bauer:** Good stuff. Anything else before we break?

**Kwame Asante:** Just one — my personal cell for the on-call rotation:
+1 512 555 0148.
"""

TRANSCRIPT_9 = """\
# Contract Negotiation — Software License
**Date:** 2026-06-02

---

**Vendor Rep (Elaine Park):** Hi, I'm Elaine Park, senior account manager.
elaine.park@vendorcorp.com, +82 2 555 3344.

**Customer (Raj Patel):** Raj Patel, procurement lead at ClientCo.
raj.patel@clientco.com, (650) 555-2211.

**Elaine Park:** The license fee is €120,000 per year. Payment via IBAN:
NL91 ABNA 0417 1643 00.

**Raj Patel:** We'll also need a DPA. Our DPO is Fatima Al-Rashid —
f.alrashid@clientco.com.

**Elaine Park:** Understood. The contract signatory for our side is our
General Counsel, Viktor Novak — v.novak@vendorcorp.com,
registered address: Václavské náměstí 1, 110 00 Praha 1, Czech Republic.

**Raj Patel:** And our legal entity address: 1600 Amphitheatre Parkway,
Mountain View, CA 94043.

**Elaine Park:** The reference test environment uses a standard config. Here
is an excerpt for integration verification:

```json
{
  "vendor_id": "VEND-0042",
  "api_endpoint": "https://api.vendorcorp.com/v2",
  "api_key": "API_KEY_PLACEHOLDER",
  "timeout": 30
}
```

The `api_key` value shown is a placeholder — the actual key will be
provisioned in your tenant.

**Raj Patel:** Understood. My personal cell, off the record: (650) 555-0001.

**Elaine Park:** Thanks Raj. I'll send the redline to raj.patel@clientco.com.
"""

TRANSCRIPT_10 = """\
# Incident Response — Data Breach Notification
**Date:** 2026-06-01

---

**CISO (Aaron Feldmann):** Opening this call. Aaron Feldmann, CISO.

**Legal (Simone Beaumont):** Simone Beaumont, outside counsel at Reed & Bell.
s.beaumont@reedandbell.com, +1 (202) 555-0192.

**Aaron Feldmann:** We have a confirmed breach affecting approximately 2,300
customer records. Affected fields: full name, date of birth, email, and in
some cases social security number.

**Simone Beaumont:** We need to notify the state AG. The breach notification
contact at the AG's office is breachnotify@ag.state.gov — that's a public
address. The responsible regulator at NIST is Dr. Patricia Nguyen,
p.nguyen@nist.gov, +1 (301) 555-7788.

**Aaron Feldmann:** Sample affected record (anonymized for this call):
Customer ID C-2281, name Jane Thornton, DOB 1985-04-17,
email jane.thornton@personal.net, SSN 789-45-6123.

**Simone Beaumont:** The notification letter goes to Jane Thornton at
44 Maple Drive, Portland, OR 97201.

**Aaron Feldmann:** Remediation plan: all affected users will receive an
email to their registered address. The monitoring service we're engaging is
LifeGuard Identity, contact: admin@lifeguardid.com, 1-800-555-0100.

**Simone Beaumont:** My direct cell for press inquiries: (202) 555-9988.

**Aaron Feldmann:** Good. Aaron Feldmann signing off.
"""

TRANSCRIPT_11 = """\
# Product Roadmap — Q3 Planning
**Date:** 2026-05-31

---

**PM (Lena Fischer):** Morning all. Lena Fischer, product. Let's walk through Q3.

**Eng Lead (Hugo Martínez):** Hugo Martínez here. The main deliverable is
the new billing API. Docs will live at `https://docs.internal/billing/v3`.

**Lena Fischer:** Good. The external announcement goes through PR — contact
our PR lead Claudia Torres at c.torres@pr-agency.com or +1 (415) 555-0055.

**Hugo Martínez:** One infra note — the staging database connection string
is in Vault. For local dev, the example in our README uses:

```
DATABASE_URL=postgresql://dev_user:dev_pass@localhost:5432/app_dev
```

That `dev_pass` is only for localhost — never in production.

**Lena Fischer:** The customer advisory board contact is Noah Carpenter —
n.carpenter@advisoryboard.org, (888) 555-0234.

**Hugo Martínez:** One personal note — I'm relocating. New address for the
employee directory: Calle de Serrano 41, 28001 Madrid, Spain.

**Lena Fischer:** Noted. Let's also capture that the new entity's tax ID for
the Spanish subsidiary is ESB-12345678.

**Hugo Martínez:** And just to be thorough: my emergency contact is my wife
Carmen Martínez, +34 91 555 6677.

**Lena Fischer:** Great. Meeting notes go to the usual Confluence page.
"""

TRANSCRIPT_12 = """\
# Customer Support Escalation — VIP Account
**Date:** 2026-05-30

---

**Support Manager (Teo Nakamura):** This is an escalation call for account
VIP-4421. I'm Teo Nakamura, support manager.

**Customer (Evangeline Moss):** Evangeline Moss, COO of Moss & Associates.
evie.moss@mossassociates.com, direct (617) 555-6601.

**Teo Nakamura:** I understand the invoice for €8,400 hasn't cleared. Can
you confirm the payment method on file?

**Evangeline Moss:** We pay by card — last four digits 9871. The full number
is 3714 496353 98431, which is our corporate Amex.

**Teo Nakamura:** Got it. Our billing system shows the charge failed on
2026-05-28. We'll rerun it.

**Evangeline Moss:** If you need to reach our CFO for authorization, that's
Bertrand Lefebvre, b.lefebvre@mossassociates.com, +33 1 42 55 07 08.

**Teo Nakamura:** We'll sort this out. The refund, if applicable, would go
back to the same card. For wire transfers, our account is:
sort code 20-00-00, account 58110244 (Barclays UK).

**Evangeline Moss:** Perfect. One more — my personal mobile:
+44 7700 900 123. Please only use for true emergencies.

**Teo Nakamura:** Noted. Teo Nakamura signing off.
"""

TRANSCRIPT_13 = """\
# Clinical Trial Oversight — IRB Review
**Date:** 2026-05-29

---

**IRB Chair (Dr. Constance Yeh):** This session reviews protocol CTX-2026-11.
I'm Dr. Constance Yeh, IRB Chair.

**PI (Dr. Arjun Mehta):** Arjun Mehta, principal investigator.
arjun.mehta@meduniversity.edu, (617) 555-3390.

**Dr. Constance Yeh:** The subject consent forms list three participants
whose data we're examining today. Subject A: Rosa Elena Vargas, DOB
1952-07-04, MRN 884-22-019, contact: r.vargas@email.com.

**Dr. Arjun Mehta:** Subject B: participant declined to provide contact.
On file: SSN 234-56-7891, DOB 1965-11-30.

**Dr. Constance Yeh:** Subject C: George Whitfield, DOB 1948-02-14,
g.whitfield@retired.net, home phone (503) 555-0041.

**Dr. Arjun Mehta:** The genomic data files are hashed for integrity. The
reference checksum for batch CTX-B3 is:

```
MD5: d41d8cd98f00b204e9800998ecf8427e
```

This is a standard empty-file hash used as a placeholder in the protocol
document — not linked to any participant data.

**Dr. Constance Yeh:** Noted. My contact for any follow-up:
c.yeh@meduniversity.edu, +1 (617) 555-0099.

**Dr. Arjun Mehta:** Protocol documents are uploaded to the IRB portal at
`https://irb.meduniversity.edu/protocols/CTX-2026-11`.

**Dr. Constance Yeh:** Dr. Yeh signing off.
"""

TRANSCRIPT_14 = """\
# Partnership Agreement — Joint Venture
**Date:** 2026-05-28

---

**Party A Rep (Ingrid Holm):** Good day. Ingrid Holm, legal director at
NordAB. ingrid.holm@nordab.se, +46 8 555 2277.

**Party B Rep (Miguel Santos):** Miguel Santos, VP Strategy at SulCorp.
m.santos@sulcorp.com.br, +55 11 5555 8899.

**Ingrid Holm:** The JV entity will be incorporated in the Netherlands.
Our Dutch notary is Jan de Vries — j.devries@notarien.nl,
+31 20 555 0088. Registered office: Keizersgracht 123, 1015 CJ Amsterdam.

**Miguel Santos:** SulCorp's Brazilian tax ID for the JV filing: CNPJ
12.345.678/0001-95.

**Ingrid Holm:** The shareholders agreement lists capital contributions:
NordAB transfers €2,000,000 via IBAN SE45 5000 0000 0583 9825 7466.

**Miguel Santos:** SulCorp's contribution via SWIFT: agency code ITAUBRSP,
account 12345-6.

**Ingrid Holm:** Key man clause covers: Ingrid Holm (NordAB) and Miguel Santos
(SulCorp). Emergency contacts: my personal mobile +46 70 555 0049;
Miguel's personal cell +55 11 9 8888 7777.

**Miguel Santos:** For notarization, we'll also need my passport number:
BR9988776.

**Ingrid Holm:** Noted. I'll circulate the draft to m.santos@sulcorp.com.br
and copy our GC at gc@nordab.se.
"""

TRANSCRIPT_15 = """\
# IT Security Audit — Code Review Session
**Date:** 2026-05-27

---

**Auditor (Yolanda Brooks):** I'm Yolanda Brooks, lead security auditor.
y.brooks@auditfirm.com, +1 (212) 555-8833.

**Dev (Patrick Lam):** Patrick Lam, lead developer. p.lam@company.com.

**Yolanda Brooks:** Let's review the authentication module. Can you pull up
the relevant section?

**Patrick Lam:** Sure. Here's the current implementation:

```python
def authenticate(username, password):
    # TODO: move secret to env
    SECRET_KEY = "do-not-hardcode-me"
    token = jwt.encode({"user": username}, SECRET_KEY, algorithm="HS256")
    return token
```

**Yolanda Brooks:** That SECRET_KEY value is a placeholder — good, but it
needs to move to env. The actual secret is managed in AWS Secrets Manager
at `arn:aws:secretsmanager:us-east-1:123456789012:secret:jwt-secret-AbCdEf`.

**Patrick Lam:** Right, the real key rotates every 90 days. My work email
for the audit findings report: p.lam@company.com. Personal cell for OOO
coverage: (650) 555-7744.

**Yolanda Brooks:** The credit card we used in the test suite (not real):
4111111111111111 — standard Luhn-valid test number.

**Patrick Lam:** And the test SSN in the fixture files: 000-00-0000.
That's a known-invalid SSN per SSA.

**Yolanda Brooks:** Let's also flag: the dev environment has the following
user record in fixtures:

```json
{
  "name": "Test User",
  "email": "testuser@example.com",
  "ssn": "000-00-0000",
  "dob": "1990-01-01"
}
```

**Patrick Lam:** That fixture data is synthetic — no real PII.

**Yolanda Brooks:** Correct. But I'd still recommend masking even synthetic
SSNs and names in fixtures to prevent confusion.

**Patrick Lam:** Also — my home address for the equipment return form:
1802 Oak Street, Palo Alto, CA 94301.

**Yolanda Brooks:** Noted. The audit report goes to y.brooks@auditfirm.com
and a copy to our engagement partner at ep.chen@auditfirm.com.
"""


# Ambiguous-name stress test: every participant has a first name that is also a
# place (Savannah, Paris, Florence, Sydney) or a common word / verb / modal
# (Jack, Rose, Mark, Bill, Will). The doc deliberately mixes person uses with
# non-person distractors ("revenue rose 12%", "let's mark that", "the cloud
# bill came to", "the Savannah office", "customer in Austin", "Will follow up").
# Only the genuine person mentions are annotated as PERSON, so this measures
# whether each tool keeps catching a name when the surface form is ambiguous.
TRANSCRIPT_16 = """\
# Product Planning Sync — Atlas Release
**Date:** 2026-06-08  **Facilitator:** Savannah Okafor

---

**Savannah Okafor:** Morning all. Savannah here, I'll facilitate. Let's start with
the roadmap. Jack, can you walk us through the Q3 milestones?

**Jack Lindqvist:** Sure thing. Okay Jack, show me the cards — sorry, thinking
out loud. The big item is the Atlas migration. We slip two weeks if staging
isn't ready.

**Savannah Okafor:** Noted. Rose, did finance approve the extra headcount?

**Rose Tanaka:** They did. Revenue rose 12% last quarter so there was room. I'll
send the signed form to mark@atlas.example.com right after the call.

**Mark Delacroix:** Thanks Rose. And let's mark the hiring item as done. Bill,
what's the infra spend looking like?

**Bill Nakamura:** The cloud bill came to forty grand in May. Bill Nakamura, for
the record, thinks we can trim that. Paris flagged some idle instances.

**Paris Adeyemi:** Right, Paris here. We're also standing up the new Savannah
office next month, so there will be egress costs from the Savannah region.

**Savannah Okafor:** Two Savannahs on one call. Florence, you're on mobile?

**Florence Kim:** Yes, Florence Kim, calling in from the Florence co-working
space, of all places. I'll keep it short.

**Sydney Mbeki:** Sydney here. One thing: we promised the customer in Austin a
demo. Will can run it. Will, you free Thursday?

**Will Castellano:** I can, yeah. Will follow up with a calendar invite after.

**Savannah Okafor:** Great. Thanks everyone, let's wrap.
"""


def _build_t1():
    doc = TRANSCRIPT_1
    pii = _spans(doc, [
        ("Alice Nguyen", "PERSON"),
        ("Bob Okonkwo", "PERSON"),
        ("Priya\nChandrasekaran", "PERSON"),
        ("(415) 882-3310", "PHONE_NUMBER"),
        ("b.okonkwo@ztech.ch", "EMAIL_ADDRESS"),
        ("a.nguyen@walshandpartners.com", "EMAIL_ADDRESS"),
        ("p.chandrasekaran@vendor.io", "EMAIL_ADDRESS"),
        ("+41 44 555 01 23", "PHONE_NUMBER"),
        ("14 Bahnhofstrasse, Zürich, CH-8001", "LOCATION"),
        ("IBAN CH93 0076 2011 6238 5295 7", "IBAN_CODE"),
        ("CHE-123.456.789", "TAX_ID"),
    ])
    # Fix multi-line name
    fixed_pii = []
    for s in pii:
        if s.text == "Priya\nChandrasekaran":
            needle = "Priya\nChandrasekaran"
            idx = doc.find(needle)
            if idx == -1:
                needle = "Priya"
                idx = doc.find(needle)
                fixed_pii.append(Span(idx, idx+len(needle), "PERSON", needle))
            else:
                fixed_pii.append(Span(idx, idx+len(needle), "PERSON", needle))
        else:
            fixed_pii.append(s)
    return Transcript("t01_kickoff", doc, fixed_pii, [])


def _build_t2():
    doc = TRANSCRIPT_2
    pii = _spans(doc, [
        ("Sam Rivera", "PERSON"),
        ("Jordan Park", "PERSON"),
        ("Mia Tanaka", "PERSON"),
        ("sam.rivera@corp.example.com", "EMAIL_ADDRESS"),
        ("five five five\ntwo two four seven eight nine zero", "PHONE_NUMBER"),
        ("555-0134", "PHONE_NUMBER"),
        ("308 Negra Arroyo Lane, Albuquerque, NM 87104", "LOCATION"),
        ("hunter2", "PASSWORD"),
    ])
    safe = _safe_spans(doc, [
        "```yaml\noidc:\n  client_id: \"app-prod-1234\"\n  issuer: \"https://auth.example.com\"\n  redirect_uri: \"https://app.example.com/callback\"\n```",
        "secret/prod/oidc/client_secret",
    ])
    return Transcript("t02_eng_sync", doc, pii, safe)


def _build_t3():
    doc = TRANSCRIPT_3
    pii = _spans(doc, [
        ("Chen Wei", "PERSON"),
        ("Marcus Elliot Beaumont", "PERSON"),
        ("Laura Beaumont", "PERSON"),
        ("March fourteenth, nineteen ninety-one", "DATE_OF_BIRTH"),
        ("1991-03-14", "DATE_OF_BIRTH"),
        ("432-18-6792", "US_SSN"),
        ("77 Orchard Street, Apartment 4B, Brooklyn, New York, 11211", "LOCATION"),
        ("m.beaumont@gmail.com", "EMAIL_ADDRESS"),
        ("(718) 554-0987", "PHONE_NUMBER"),
        ("laura.beaumont@outlook.com", "EMAIL_ADDRESS"),
        ("zero two six zero zero nine five nine three", "BANK_ROUTING"),
        ("four four seven eight eight two one zero three", "BANK_ACCOUNT"),
        ("US9876543", "PASSPORT_NUMBER"),
    ])
    return Transcript("t03_hr_onboarding", doc, pii, [])


def _build_t4():
    doc = TRANSCRIPT_4
    pii = _spans(doc, [
        ("Dmitri Volkov", "PERSON"),
        ("Yuki Yamazaki", "PERSON"),
        ("Rosa Chen", "PERSON"),
        ("yuki.yamazaki@fnb.co.jp", "EMAIL_ADDRESS"),
        ("+81 3 5555 7890", "PHONE_NUMBER"),
        ("021000021", "BANK_ROUTING"),
        ("1234567890", "BANK_ACCOUNT"),
        ("DE89 3704 0044 0532 0130 00", "IBAN_CODE"),
        ("DE 123456789", "TAX_ID"),
        ("4916338506082832", "CREDIT_CARD"),
        ("Seefeldstrasse 47, 8008 Zürich, Switzerland", "LOCATION"),
        ("+1 (212) 555-0193", "PHONE_NUMBER"),
    ])
    return Transcript("t04_board_finance", doc, pii, [])


def _build_t5():
    doc = TRANSCRIPT_5
    pii = _spans(doc, [
        ("Sarah O'Brien", "PERSON"),
        ("Devon Marsh", "PERSON"),
        ("Thomas Grunewald", "PERSON"),
        ("Amara Diallo", "PERSON"),
        ("Ingrid Svensson", "PERSON"),
        ("tgrunewald@respondent.com", "EMAIL_ADDRESS"),
        ("a.diallo@respondent.com", "EMAIL_ADDRESS"),
        ("isvensson@respondent.com", "EMAIL_ADDRESS"),
        ("james.harrington@litigatelaw.com", "EMAIL_ADDRESS"),
        ("+33 6 12 34 56 78", "PHONE_NUMBER"),
        ("(617) 555-2298", "PHONE_NUMBER"),
        ("12 rue de la Paix, 75002 Paris, France", "LOCATION"),
        ("FR76 3000 6000 0112 3456 7890 189", "IBAN_CODE"),
        ("5105105105105100", "CREDIT_CARD"),
        ("BBO#682341", "LICENSE_NUMBER"),
    ])
    safe = _safe_spans(doc, [
        "e3b0c44298fc1c149afb4c8996fb92427ae41e4649b934ca495991b7852b855",
    ])
    return Transcript("t05_legal_hold", doc, pii, safe)


def _build_t6():
    doc = TRANSCRIPT_6
    pii = _spans(doc, [
        ("Felix Hartmann", "PERSON"),
        ("Priya Singh", "PERSON"),
        ("nadia.hassan@contractor.io", "EMAIL_ADDRESS"),
        ("James Okafor", "PERSON"),
        ("j.okafor@corp.example.com", "EMAIL_ADDRESS"),
        ("j.okafor.personal@gmail.com", "EMAIL_ADDRESS"),
        ("567-89-0123", "US_SSN"),
        ("(312) 555-8741", "PHONE_NUMBER"),
        ("+49 89 555 0276", "PHONE_NUMBER"),
        ("203.0.113.45", "IP_ADDRESS"),
        ("AKIAIOSFODNN7EXAMPLE", "AWS_KEY"),
    ])
    safe = _safe_spans(doc, [
        "10.0.0.1",
    ])
    return Transcript("t06_security_incident", doc, pii, safe)


def _build_t7():
    doc = TRANSCRIPT_7
    pii = _spans(doc, [
        ("Grace Liu", "PERSON"),
        ("Oliver Prentiss", "PERSON"),
        ("Dr. Helena Krause", "PERSON"),
        ("grace.liu@dataguardpro.com", "EMAIL_ADDRESS"),
        ("oliver.prentiss@novamed.com", "EMAIL_ADDRESS"),
        ("h.krause@novamed.com", "EMAIL_ADDRESS"),
        ("accounts@novamed.com", "EMAIL_ADDRESS"),
        ("oliver@prentiss-family.net", "EMAIL_ADDRESS"),
        ("(206) 555-7734", "PHONE_NUMBER"),
        ("+1 (206) 555-8811", "PHONE_NUMBER"),
        ("+1 (206) 555 1337", "PHONE_NUMBER"),
        ("121000248", "BANK_ROUTING"),
        ("7654321098", "BANK_ACCOUNT"),
        ("MRN-449012", "MEDICAL_RECORD"),
        ("1978-11-22", "DATE_OF_BIRTH"),
        ("UHC-884-22-9971", "INSURANCE_ID"),
    ])
    return Transcript("t07_sales_call", doc, pii, [])


def _build_t8():
    doc = TRANSCRIPT_8
    pii = _spans(doc, [
        ("Martina Bauer", "PERSON"),
        ("Kwame Asante", "PERSON"),
        ("k.asante@company.com", "EMAIL_ADDRESS"),
        ("999 Market Street, Suite 800, San Francisco, CA 94103", "LOCATION"),
        ("52 Juniper Lane, Austin, TX 78704", "LOCATION"),
        ("+1 512 555 0148", "PHONE_NUMBER"),
    ])
    safe = _safe_spans(doc, [
        'openssl s_client -connect vpn.company.com:443 -psk "PLACEHOLDER_SECRET"',
        "secret/vpn/psk",
        "PLACEHOLDER_SECRET",
    ])
    return Transcript("t08_allhands", doc, pii, safe)


def _build_t9():
    doc = TRANSCRIPT_9
    pii = _spans(doc, [
        ("Elaine Park", "PERSON"),
        ("Raj Patel", "PERSON"),
        ("Viktor Novak", "PERSON"),
        ("Fatima Al-Rashid", "PERSON"),
        ("elaine.park@vendorcorp.com", "EMAIL_ADDRESS"),
        ("raj.patel@clientco.com", "EMAIL_ADDRESS"),
        ("v.novak@vendorcorp.com", "EMAIL_ADDRESS"),
        ("f.alrashid@clientco.com", "EMAIL_ADDRESS"),
        ("+82 2 555 3344", "PHONE_NUMBER"),
        ("(650) 555-2211", "PHONE_NUMBER"),
        ("(650) 555-0001", "PHONE_NUMBER"),
        ("NL91 ABNA 0417 1643 00", "IBAN_CODE"),
        ("Václavské náměstí 1, 110 00 Praha 1, Czech Republic", "LOCATION"),
        ("1600 Amphitheatre Parkway,\nMountain View, CA 94043", "LOCATION"),
    ])
    safe = _safe_spans(doc, [
        '"vendor_id": "VEND-0042"',
        '"api_endpoint": "https://api.vendorcorp.com/v2"',
        '"api_key": "API_KEY_PLACEHOLDER"',
        "API_KEY_PLACEHOLDER",
    ])
    return Transcript("t09_contract_negotiation", doc, pii, safe)


def _build_t10():
    doc = TRANSCRIPT_10
    pii = _spans(doc, [
        ("Aaron Feldmann", "PERSON"),
        ("Simone Beaumont", "PERSON"),
        ("Dr. Patricia Nguyen", "PERSON"),
        ("Jane Thornton", "PERSON"),
        ("s.beaumont@reedandbell.com", "EMAIL_ADDRESS"),
        ("p.nguyen@nist.gov", "EMAIL_ADDRESS"),
        ("jane.thornton@personal.net", "EMAIL_ADDRESS"),
        ("breachnotify@ag.state.gov", "EMAIL_ADDRESS"),
        ("admin@lifeguardid.com", "EMAIL_ADDRESS"),
        ("+1 (202) 555-0192", "PHONE_NUMBER"),
        ("+1 (301) 555-7788", "PHONE_NUMBER"),
        ("(202) 555-9988", "PHONE_NUMBER"),
        ("1-800-555-0100", "PHONE_NUMBER"),
        ("1985-04-17", "DATE_OF_BIRTH"),
        ("789-45-6123", "US_SSN"),
        ("44 Maple Drive, Portland, OR 97201", "LOCATION"),
    ])
    return Transcript("t10_breach_notification", doc, pii, [])


def _build_t11():
    doc = TRANSCRIPT_11
    pii = _spans(doc, [
        ("Lena Fischer", "PERSON"),
        ("Hugo Martínez", "PERSON"),
        ("Claudia Torres", "PERSON"),
        ("Noah Carpenter", "PERSON"),
        ("Carmen Martínez", "PERSON"),
        ("c.torres@pr-agency.com", "EMAIL_ADDRESS"),
        ("n.carpenter@advisoryboard.org", "EMAIL_ADDRESS"),
        ("+1 (415) 555-0055", "PHONE_NUMBER"),
        ("(888) 555-0234", "PHONE_NUMBER"),
        ("+34 91 555 6677", "PHONE_NUMBER"),
        ("Calle de Serrano 41, 28001 Madrid, Spain", "LOCATION"),
        ("ESB-12345678", "TAX_ID"),
    ])
    safe = _safe_spans(doc, [
        "DATABASE_URL=postgresql://dev_user:dev_pass@localhost:5432/app_dev",
        "`https://docs.internal/billing/v3`",
    ])
    return Transcript("t11_product_roadmap", doc, pii, safe)


def _build_t12():
    doc = TRANSCRIPT_12
    pii = _spans(doc, [
        ("Teo Nakamura", "PERSON"),
        ("Evangeline Moss", "PERSON"),
        ("Bertrand Lefebvre", "PERSON"),
        ("evie.moss@mossassociates.com", "EMAIL_ADDRESS"),
        ("b.lefebvre@mossassociates.com", "EMAIL_ADDRESS"),
        ("(617) 555-6601", "PHONE_NUMBER"),
        ("+33 1 42 55 07 08", "PHONE_NUMBER"),
        ("+44 7700 900 123", "PHONE_NUMBER"),
        ("3714 496353 98431", "CREDIT_CARD"),
        ("58110244", "BANK_ACCOUNT"),
        ("20-00-00", "SORT_CODE"),
    ])
    return Transcript("t12_support_escalation", doc, pii, [])


def _build_t13():
    doc = TRANSCRIPT_13
    pii = _spans(doc, [
        ("Dr. Constance Yeh", "PERSON"),
        ("Dr. Arjun Mehta", "PERSON"),
        ("Rosa Elena Vargas", "PERSON"),
        ("George Whitfield", "PERSON"),
        ("arjun.mehta@meduniversity.edu", "EMAIL_ADDRESS"),
        ("r.vargas@email.com", "EMAIL_ADDRESS"),
        ("g.whitfield@retired.net", "EMAIL_ADDRESS"),
        ("c.yeh@meduniversity.edu", "EMAIL_ADDRESS"),
        ("(617) 555-3390", "PHONE_NUMBER"),
        ("(503) 555-0041", "PHONE_NUMBER"),
        ("+1 (617) 555-0099", "PHONE_NUMBER"),
        ("1952-07-04", "DATE_OF_BIRTH"),
        ("1965-11-30", "DATE_OF_BIRTH"),
        ("1948-02-14", "DATE_OF_BIRTH"),
        ("884-22-019", "MEDICAL_RECORD"),
        ("234-56-7891", "US_SSN"),
    ])
    safe = _safe_spans(doc, [
        "d41d8cd98f00b204e9800998ecf8427e",
    ])
    return Transcript("t13_clinical_trial", doc, pii, safe)


def _build_t14():
    doc = TRANSCRIPT_14
    pii = _spans(doc, [
        ("Ingrid Holm", "PERSON"),
        ("Miguel Santos", "PERSON"),
        ("Jan de Vries", "PERSON"),
        ("ingrid.holm@nordab.se", "EMAIL_ADDRESS"),
        ("m.santos@sulcorp.com.br", "EMAIL_ADDRESS"),
        ("j.devries@notarien.nl", "EMAIL_ADDRESS"),
        ("gc@nordab.se", "EMAIL_ADDRESS"),
        ("+46 8 555 2277", "PHONE_NUMBER"),
        ("+55 11 5555 8899", "PHONE_NUMBER"),
        ("+31 20 555 0088", "PHONE_NUMBER"),
        ("+46 70 555 0049", "PHONE_NUMBER"),
        ("+55 11 9 8888 7777", "PHONE_NUMBER"),
        ("Keizersgracht 123, 1015 CJ Amsterdam", "LOCATION"),
        ("SE45 5000 0000 0583 9825 7466", "IBAN_CODE"),
        ("12.345.678/0001-95", "TAX_ID"),
        ("BR9988776", "PASSPORT_NUMBER"),
    ])
    return Transcript("t14_jv_negotiation", doc, pii, [])


def _build_t15():
    doc = TRANSCRIPT_15
    pii = _spans(doc, [
        ("Yolanda Brooks", "PERSON"),
        ("Patrick Lam", "PERSON"),
        ("y.brooks@auditfirm.com", "EMAIL_ADDRESS"),
        ("p.lam@company.com", "EMAIL_ADDRESS"),
        ("ep.chen@auditfirm.com", "EMAIL_ADDRESS"),
        ("+1 (212) 555-8833", "PHONE_NUMBER"),
        ("(650) 555-7744", "PHONE_NUMBER"),
        ("1802 Oak Street, Palo Alto, CA 94301", "LOCATION"),
        ("4111111111111111", "CREDIT_CARD"),
    ])
    safe = _safe_spans(doc, [
        'SECRET_KEY = "do-not-hardcode-me"',
        '"name": "Test User"',
        '"email": "testuser@example.com"',
        '"ssn": "000-00-0000"',
        '"dob": "1990-01-01"',
        "000-00-0000",
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:jwt-secret-AbCdEf",
    ])
    return Transcript("t15_security_audit", doc, pii, safe)


def _build_t16():
    doc = TRANSCRIPT_16

    def ns(anchor: str, name: str, label: str = "PERSON") -> Span:
        i = doc.find(anchor)
        if i == -1:
            raise ValueError(f"anchor not found: {anchor!r}")
        if doc.find(anchor, i + 1) != -1:
            raise ValueError(f"anchor not unique: {anchor!r}")
        j = anchor.find(name)
        start = i + j
        return Span(start, start + len(name), label, name)

    pii = [
        # Full-name mentions (the easy control group)
        ns("**Savannah Okafor:** Morning", "Savannah Okafor"),
        ns("**Jack Lindqvist:** Sure", "Jack Lindqvist"),
        ns("**Rose Tanaka:** They", "Rose Tanaka"),
        ns("**Mark Delacroix:** Thanks", "Mark Delacroix"),
        ns("**Bill Nakamura:** The", "Bill Nakamura"),
        ns("**Paris Adeyemi:** Right", "Paris Adeyemi"),
        ns("**Florence Kim:** Yes", "Florence Kim"),
        ns("**Sydney Mbeki:** Sydney", "Sydney Mbeki"),
        ns("**Will Castellano:** I", "Will Castellano"),
        # Bare ambiguous first names used as people (the hard cases)
        ns("Savannah here, I'll", "Savannah"),
        ns("Jack, can you walk", "Jack"),
        ns("Okay Jack, show", "Jack"),
        ns("Rose, did finance", "Rose"),
        ns("Thanks Rose. And", "Rose"),
        ns("done. Bill,", "Bill"),
        ns("Paris flagged", "Paris"),
        ns("Paris here.", "Paris"),
        ns("Florence, you're", "Florence"),
        ns("Sydney here.", "Sydney"),
        ns("Will can run it", "Will"),
        ns("Will, you free", "Will"),
        # Non-person email for realism
        ns("mark@atlas.example.com right", "mark@atlas.example.com", "EMAIL_ADDRESS"),
    ]
    return Transcript("t16_ambiguous_names", doc, pii, [])


def load_all() -> List[Transcript]:
    return [
        _build_t1(), _build_t2(), _build_t3(), _build_t4(), _build_t5(),
        _build_t6(), _build_t7(), _build_t8(), _build_t9(), _build_t10(),
        _build_t11(), _build_t12(), _build_t13(), _build_t14(), _build_t15(),
        _build_t16(),
    ]


if __name__ == "__main__":
    transcripts = load_all()
    for t in transcripts:
        print(f"{t.name}: {len(t.pii)} PII spans, {len(t.safe)} safe spans")
        for s in t.pii:
            print(f"  [{s.label}] {s.text!r}")
