# RG BC Checker add-on

Separate ServiceM8 Web Service Hosted Add-on for an Auckland-first, staff-managed BC watch list. This is a local implementation. It has not been deployed, connected to a ServiceM8 add-on registration, or run against live ServiceM8/Homes.co.nz data.

## First-version behaviour

- Add up to 50 ServiceM8 job numbers at a time by pasting numbers or loading a CSV. A `Job Number`, `Job ID`, or `generated_job_id` header can be in any column; without a header, the first column is used. Duplicates are ignored. A signed-in ServiceM8 staff member adds and reviews jobs.
- On the first check, record all consent events already present at the exact matched address as a **baseline**. Do not raise a new-candidate flag for those events.
- On later checks, identify consents by number (or a fallback event fingerprint when no number exists). A new event is marked **Needs review** once. An existing baseline application also moves to review when its status first appears as issued, approved, or granted.
- **Wrong BC** remembers the dismissal for that Job and consent number. Further observations of that number do not reopen it. **Right BC — stop checking** retains the decision and stops monitoring the Job. Staff may also stop a Job without confirming a BC.
- Re-adding a stopped Job starts a fresh baseline and clears that Job's old candidates. An already active Job is left unchanged.
- Address matching must be unique. An uncertain address or changed ServiceM8 Job address produces a visible check error; it does not attach another property's events.
- No email is sent. No ServiceM8 Job or Diary data is written.

The Homes timeline labels these as consent events. The add-on presents them as **candidates**, and staff confirm whether one is the right building consent for the ServiceM8 Job. A matching address alone does not establish that conclusion.

## Setup

1. Run on Node.js 24 or newer with PostgreSQL. `npm install` and `npm run db:migrate` apply the add-on's own schema to a dedicated database.
2. Configure the names in `.env.example` as host secrets. Generate a random 32-byte base64 `TOKEN_ENCRYPTION_KEY`; use independent random 32-character-or-longer values for `SESSION_SECRET` and `CRON_SECRET`. The ServiceM8 App ID/Secret and database must be separate from Office Assistant and Company Check.
3. Register a separate Web Service Hosted Add-on. Use `${APP_BASE_URL}/manifest.json` as manifest, `${APP_BASE_URL}/events` as event callback, `${APP_BASE_URL}/oauth/start` as activation URL, and `${APP_BASE_URL}/oauth/callback` as OAuth return URL. Grant only `vendor read_jobs`.
4. Start with `npm start`. Configure a trusted scheduler to POST `${APP_BASE_URL}/cron/check` every **Monday at 9:00 am Pacific/Auckland**, with header `Authorization: Bearer <CRON_SECRET>`. The database due date selects each Job every second Monday after its first check. Each invocation processes at most ten due Jobs; if the list grows, call the endpoint repeatedly with suitable spacing or raise the bounded batch size after measuring run time.
5. Verify one signed staff launch, a known Job with existing historical consents, a Job with no candidates, a newly appearing candidate, and the wrong/right BC controls before enabling regular checks. Keep the existing Address Check add-on's account-wide Homes rate budget in mind; this standalone add-on uses a 15-second gap between its own lookups but cannot coordinate that budget with another add-on.

The user stated that Royal Glass has written permission from Homes.co.nz covering scheduled commercial lookups. Retain that permission and its scope with the deployment record; the project does not include it.

## Local verification

Run `npm test` for matching, CSV parsing, and candidate state rules. `node --check src/*.mjs` can be run on each file for syntax. Live ServiceM8 OAuth, signed menu launch, Homes data shape, scheduler timing, and database behaviour require staging verification with separate credentials and representative Jobs. No migration or outbound call was made in this local build.
# bc-checker
