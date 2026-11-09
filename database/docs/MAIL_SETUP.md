# Connecting the mailbox that receives your Shadowserver reports

The pipeline reads the mailbox where Shadowserver sends your reports. It only reads: messages are never marked
read, moved or deleted. Choose the way that matches your mail system; the installer (`../install.sh`) asks for
these values, checks them with a real login, and writes them to `.env`.

| Your mail system | Use | What you need | Admin rights? |
|---|---|---|---|
| Gmail or Google Workspace | **A. App password** (simplest) | the address and an app password | no |
| Google Workspace | **B. Gmail API with a service account** (no password stored) | a JSON key file and the mailbox address | yes, Workspace super admin |
| Microsoft 365 / Exchange Online | **C. Microsoft Graph** | tenant ID, client ID, client secret, mailbox | yes, Entra admin |
| Any other mail server (cPanel, Zimbra, Roundcube, Dovecot...) | **D. IMAP** | server, login, password | no |

**No Shadowserver reports yet?** Sign up your CSIRT for the free daily reports:
https://www.shadowserver.org/what-we-do/network-reporting/ . Shadowserver also works with national CSIRTs
(https://www.shadowserver.org/partner-with-us/). A dedicated mailbox (for example `shadowserver@your-csirt.org`)
keeps the reports separate from people's mail.

---

## A. Gmail or Google Workspace with an app password

1. Turn on **2-Step Verification** for the account: https://myaccount.google.com/signinoptions/two-step-verification
2. Create an **app password** (name it "Looking Glass"): https://myaccount.google.com/apppasswords
   Google shows 16 letters once; that is the password the pipeline uses (spaces don't matter).
3. Google Workspace only: an administrator may need to allow IMAP for users
   (Admin console → Apps → Google Workspace → Gmail → End user access → POP and IMAP access:
   https://admin.google.com/ac/apps/gmail/enduseraccess) and allow app passwords / 2-Step Verification.

Settings (`.env`):
```
MAIL_PROVIDER=imap
IMAP_SERVER=imap.gmail.com
IMAP_USER=you@gmail.com            # or you@your-domain
IMAP_PASSWORD=<the 16-letter app password>
IMAP_FOLDER=INBOX                  # or a label, e.g. Shadowserver
IMAP_VERIFY_TLS=true
```
Folder and label names are used exactly as written, spaces included (`IMAP_FOLDER=Shadow Reports`, no quotes);
a nested label is written with a slash, e.g. `CSIRT/Shadowserver`.

## B. Google Workspace with the Gmail API (service account)

No mailbox password is stored; the service account may only read mail (scope `gmail.readonly`).

1. **Project:** create one (or use an existing one) at https://console.cloud.google.com/projectcreate
2. **Gmail API:** enable it in that project: https://console.cloud.google.com/apis/library/gmail.googleapis.com
3. **Service account:** https://console.cloud.google.com/iam-admin/serviceaccounts → *Create service account*
   (name "looking-glass", no roles needed) → open it → *Keys* → *Add key* → *JSON*. Keep the downloaded file safe:
   it is the credential. (If key creation is blocked, your organisation policy
   `iam.disableServiceAccountKeyCreation` must allow it for this project.)
   Note the service account's **Client ID** (a long number, on its *Details* tab).
4. **Domain-wide delegation** (Workspace super admin): https://admin.google.com/ac/owl/domainwidedelegation →
   *Add new* → the Client ID from step 3 → OAuth scope `https://www.googleapis.com/auth/gmail.readonly` → *Authorize*.
   It can take a few minutes to take effect.
5. Copy the JSON key to the server, into `database/secrets/` (the installer does this), mode 600.

Settings:
```
MAIL_PROVIDER=gmail_api
GMAIL_SERVICE_ACCOUNT_FILE=secrets/gmail-service-account.json
GMAIL_USER=shadowserver@your-domain    # the mailbox that receives the reports
GMAIL_LABEL=INBOX                      # or the label your reports get, e.g. Shadowserver
```

## C. Microsoft 365 / Exchange Online with Microsoft Graph

Microsoft has switched off passwords over IMAP (basic authentication) for Exchange Online, so Microsoft 365
mailboxes are read through Microsoft Graph with an app registration.

1. **Register an app:** Microsoft Entra admin center → *App registrations* → *New registration*:
   https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade
   Name "Looking Glass", *Accounts in this organizational directory only*, no redirect URI → *Register*.
   On its *Overview*, note the **Application (client) ID** and the **Directory (tenant) ID**.
2. **Permission:** *API permissions* → *Add a permission* → *Microsoft Graph* → *Application permissions* →
   **Mail.Read** → *Add permissions* → **Grant admin consent for <your organisation>**.
3. **Secret:** *Certificates & secrets* → *New client secret* (for example 24 months) → copy its **Value**
   (not the Secret ID); it is shown only once. Put a reminder in your calendar to renew it before it expires.
4. **Limit the app to the one mailbox (strongly recommended).** Mail.Read as an application permission can read
   every mailbox in the organisation until you restrict it. In Exchange Online PowerShell
   (https://learn.microsoft.com/powershell/exchange/connect-to-exchange-online-powershell):
   ```powershell
   New-ApplicationAccessPolicy -AppId <client ID> -PolicyScopeGroupId shadowserver@your-domain -AccessRight RestrictAccess -Description "Looking Glass reads only the Shadowserver mailbox"
   Test-ApplicationAccessPolicy -Identity shadowserver@your-domain -AppId <client ID>
   ```
   Microsoft's guide (and its newer *RBAC for Applications*):
   https://learn.microsoft.com/graph/auth-limit-mailbox-access

Settings:
```
MAIL_PROVIDER=microsoft_graph
MS_TENANT_ID=<Directory (tenant) ID>
MS_CLIENT_ID=<Application (client) ID>
MS_CLIENT_SECRET=<secret Value>
MS_MAILBOX=shadowserver@your-domain
MS_FOLDER=inbox                    # or the name of a folder, e.g. Shadowserver
```
Personal outlook.com / hotmail.com addresses cannot be used this way; use a Microsoft 365 work mailbox.

## D. Any other mail server (IMAP)

Ask your mail administrator (or look in your webmail's settings) for the **IMAP server name** (port 993, SSL/TLS).
Use the mailbox's normal login and password, or an app password if your provider offers them.

Settings:
```
MAIL_PROVIDER=imap
IMAP_SERVER=mail.your-domain
IMAP_USER=shadowserver@your-domain
IMAP_PASSWORD=<password>
IMAP_FOLDER=inbox
IMAP_VERIFY_TLS=true               # false only for a server with a self-signed certificate
```

---

## Checking it

```bash
.venv/bin/python shadowserver_pipeline.py --test-mail     # logs in and counts the last day's messages
shadowserver check                                       # the whole setup, including the mailbox
```
Typical answers and what to do:

| Message | Fix |
|---|---|
| `login refused ... (Gmail needs an app password ...)` | use an app password (A), not the account password |
| `Microsoft refused the app ... Value, not its Secret ID` | copy the secret's Value again |
| `... the client secret has expired` | create a new secret (C3) and update `MS_CLIENT_SECRET` |
| `... Mail.Read and grant admin consent` | C2, including *Grant admin consent* |
| `... a Conditional Access policy of your tenant blocks this app` (AADSTS53003) | ask the Entra admin to exclude the app from the policy (Conditional Access for workload identities) or to allow this server's public address |
| `... this app has no client secret` (AADSTS700026) | C3: create a client secret |
| `... the tenant ID is wrong` | check `MS_TENANT_ID`: the Directory (tenant) ID, or the organisation's domain |
| `... no app with this client ID in this tenant` | check `MS_CLIENT_ID` (C1) and that tenant and app belong together |
| `Google refused ... domain-wide delegation is missing` | B4 (and wait a few minutes) |
| `certificate of <server> is not trusted` | the server's certificate is self-signed: `IMAP_VERIFY_TLS=false` |

## How often it runs

`shadowserver schedule every 30m` (the installer's default) runs the pipeline every 30 minutes: Shadowserver sends
reports throughout the day, and each run only fetches e-mails and links it has not handled yet
(`.mail_state.sqlite`), so a run with nothing new takes a second or two. `shadowserver run --all` handles every
e-mail of the period again.
