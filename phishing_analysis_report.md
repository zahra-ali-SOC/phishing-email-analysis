# Phishing Email Analysis Report

> **Note:** This report is based on a **simulated** phishing email made for practice. The domains use the `.example` ending, so they are not real sites. The attachment is a harmless file. Never open or click anything from a real phishing email.

## 1. Summary

An employee (`sara.ahmed@northwind-lab.example`) reported a suspicious email that said her Microsoft account would be suspended in 24 hours. The email pretends to be from "Microsoft Account Team", but it came from a lookalike domain, failed all email authentication checks, and had a link and an attachment built to trick the user.

**Verdict:** Phishing (malicious). **Severity:** Medium. No sign yet that the user clicked or opened anything.

## 2. Email Details

| Field | Value |
|---|---|
| Subject | URGENT: Your account will be suspended in 24 hours |
| Date | Sat, 24 Oct 2026 08:14:22 +0000 |
| Display name | "Microsoft Account Team" |
| From | `security-alert@micr0soft-support[.]example` |
| Return-Path | `bounce@mailer77[.]cheap-host[.]example` |
| Reply-To | `helpdesk.recovery.2026@freemail[.]example` |
| Sending IP | `198[.]51[.]100[.]23` |
| Mailer | MassMailer Pro 3.2 |

## 3. Analysis: Why This Is Phishing

| # | Finding | Why it matters |
|---|---|---|
| 1 | The domain is `micr0soft-support` (a zero instead of the letter o) | A lookalike domain, not Microsoft |
| 2 | SPF = **fail** | The sending IP is not allowed to send for this domain |
| 3 | DKIM = **none** | The email has no signature, so it cannot be verified |
| 4 | DMARC = **fail** | The domain's authentication check did not pass |
| 5 | Return-Path and Message-ID use `cheap-host.example` | The real sending system is a cheap host, not Microsoft |
| 6 | Reply-To is a free mailbox | Replies would go to the attacker, not to the sender address |
| 7 | The link text shows `account.microsoft.com`, but the real link goes to `micr0soft-support[.]example` | The text and the real link do not match, a classic phishing trick |
| 8 | Attachment is `Invoice_8841.pdf.html` | A double extension. It looks like a PDF but is an HTML file. HTML attachments are often used to steal passwords |
| 9 | "URGENT" and "suspended in 24 hours" | Pressure words, so the user acts without thinking |
| 10 | The X-Mailer is a mass mailing tool | Sent to many people, not a personal message |

## 4. Tools Used

| Tool | What I used it for |
|---|---|
| Notepad / VS Code | Read the raw headers safely, without opening the email |
| Python (hashlib) | Get the attachment's SHA-256 hash without opening the file |
| MXToolbox Header Analyzer | Check SPF, DKIM, DMARC, and the relay path |
| CyberChef | Defang the link so it is safe to share |
| VirusTotal | Look up the attachment hash |

## 5. Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| Domain | `micr0soft-support[.]example` |
| URL | `hxxp[://]micr0soft-support[.]example/login/verify?id=88412` |
| Sender email | `security-alert@micr0soft-support[.]example` |
| Reply-To | `helpdesk.recovery.2026@freemail[.]example` |
| Return-Path | `bounce@mailer77[.]cheap-host[.]example` |
| IP address | `198[.]51[.]100[.]23` |
| File name | `Invoice_8841.pdf.html` |
| SHA-256 | `0c806ebd84207382ac9bb7954749f2befea0df40c6bbef84794efce173f4fa84` |

**Note on VirusTotal:** The hash had no results. This does not mean the file is safe. It only means no one has reported this file before.

## 6. MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|---|---|---|
| Phishing: Spearphishing Attachment | T1566.001 | `Invoice_8841.pdf.html` attached |
| Phishing: Spearphishing Link | T1566.002 | Link that goes to the lookalike domain |
| Masquerading: Double File Extension | T1036.007 | `.pdf.html` |
| Acquire Infrastructure: Domains | T1583.001 | Lookalike domain `micr0soft-support` |
| User Execution | T1204 | Needed if the user opens the file or clicks the link |

## 7. Recommended Actions

1. **Contain:** Remove this email from all mailboxes (search by sender and subject).
2. **Block:** Block the domain, the sender, and the sending IP.
3. **Check the user:** Ask Sara if she clicked the link or opened the attachment.
4. **If she did:** Isolate her device, reset her password, end all her sessions, and check her sign-in logs for strange activity.
5. **Hunt:** Search web proxy and DNS logs for visits to `micr0soft-support[.]example`.
6. **Tell the team:** Warn users about this email. Praise the reporter.

## 8. Limits and Improvements

- The email is simulated, so the links were not live and the attachment was not detonated.
- Next step: run a real attachment in a sandbox such as ANY.RUN and add the result.
- Next step: write a SIEM search that finds users who visited the phishing domain.
