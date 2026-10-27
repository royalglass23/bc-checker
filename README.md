# RG BC Checker add-on

Separate ServiceM8 Web Service Hosted Add-on for an Auckland-first, staff-managed BC watch list. This is a local implementation. It has not been deployed, connected to a ServiceM8 add-on registration, or run against live ServiceM8/Homes.co.nz data.

## First-version behaviour

- Add up to 50 ServiceM8 job numbers at a time by pasting numbers or loading a CSV. A `Job Number`, `Job ID`, or `generated_job_id` header can be in any column; without a header, the first column is used. Duplicates are ignored. A signed-in ServiceM8 staff member adds and reviews jobs.
- On the first check, record all consent events already present at the exact matched address as a **baseline**. Do not raise a new-candidate flag for those events.
- On later checks, identify consents by number (or a fallback event fingerprint when no number exists). A new event is marked **Needs review** once. An existing baseline application also moves to review when its status first appears as issued, approved, or granted.
- **Wrong BC** remembers the dismissal for that Job and consent number. Further observations of that number do not reopen it. **Right BC — stop checking** retains the decision and stops monitoring the Job. Staff may also stop a Job without confirming a BC.
- Re-adding a stopped Job starts a fresh baseline and clears that Job's old candidates. An already active Job is left unchanged.
- Address matching must be unique. An uncertain address or changed ServiceM8 Job address produces a visible check error; it does not attach another property's events.
- Each monitored Job appears as one compact row. Details expand to show candidates and the stop control; pagination and page size sit below the list.
- **Check this address now** runs an immediate address check. After a successful check, it adds the matched-address summary and candidate counts to that Job's ServiceM8 Notes and Job Diary. It does not confirm a candidate as the right BC. If either ServiceM8 write fails, the result is shown in BC Checker; do not repeat the button just to retry a partial write, because a second Diary post creates another item.
- No email is sent. Scheduled checks continue to update BC Checker only; they do not create Job Notes or Diary items.
- The Add-ons menu renders BC Checker directly in ServiceM8's add-on canvas. The signed staff session travels in the add-on's forms, including pagination and review actions; it does not require a separate browser tab or a third-party cookie.

The Homes timeline labels these as consent events. The add-on presents them as **candidates**, and staff confirm whether one is the right building consent for the ServiceM8 Job. A matching address alone does not establish that conclusion.

## Setup

### Vercel

Select **Node** as the framework preset and **Node.js 24.x** as the runtime. Keep the project root at this folder. Vercel detects the root `server.ts` as the Node server entry point; locally, `npm start` uses the same entry point. Leave the Build Command and Output Directory overrides off, as shown in the Vercel project settings.

Set the variables in `.env.example` in Vercel Project Settings for the environment being deployed. The local `.env` is ignored by Git and is not uploaded by importing the project. `APP_BASE_URL` must be the final HTTPS deployment URL and must agree with the ServiceM8 add-on registration. The database and app base URL alone are insufficient to start the server: the ServiceM8 credentials, allowed account UUID, and three secrets are also required.

No Vercel Cron Job is configured yet. Enabling it would start live Homes checks; add and verify the scheduler after OAuth, database migration, and a manual baseline check have been tested. Vercel Cron invokes a GET endpoint on a UTC schedule, while the current `/cron/check` endpoint expects an authenticated POST, so the scheduler route must be adapted before using Vercel Cron.

1. Run on Node.js 24 or newer with PostgreSQL. `npm install` and `npm run db:migrate` apply the add-on's own schema to a dedicated database. The npm scripts load a local `.env` when present; Vercel supplies the variables through Project Settings.
2. Configure the names in `.env.example` as host secrets. Generate a random 32-byte base64 `TOKEN_ENCRYPTION_KEY`; use independent random 32-character-or-longer values for `SESSION_SECRET` and `CRON_SECRET`. The ServiceM8 App ID/Secret and database must be separate from Office Assistant and Company Check.
3. Register a separate Web Service Hosted Add-on. The source manifest is `public/manifest.json`, served at `${APP_BASE_URL}/manifest.json`; its PNG icon is `public/icon.png`. Use `${APP_BASE_URL}/events` as event callback, `${APP_BASE_URL}/oauth/start` as activation URL, and `${APP_BASE_URL}/oauth/callback` as OAuth return URL. Grant `vendor read_jobs publish_job_notes publish_diary_items`. Existing OAuth connections must be reauthorised for the two new write scopes before the manual check can update ServiceM8.
4. Start with `npm start`. Configure a trusted scheduler to POST `${APP_BASE_URL}/cron/check` every **Monday at 9:00 am Pacific/Auckland**, with header `Authorization: Bearer <CRON_SECRET>`. The database due date selects each Job every second Monday after its first check. Each invocation processes at most ten due Jobs; if the list grows, call the endpoint repeatedly with suitable spacing or raise the bounded batch size after measuring run time.
5. Verify that one signed staff launch remains inside the ServiceM8 canvas, including add, pagination, manual check, wrong/right BC and stop controls. Then verify a known Job with existing historical consents, a Job with no candidates, and a newly appearing candidate before enabling regular checks. Keep the existing Address Check add-on's account-wide Homes rate budget in mind; scheduled batches use a 15-second gap, while manual checks and another add-on do not share that pacing.

The user stated that Royal Glass has written permission from Homes.co.nz covering scheduled commercial lookups. Retain that permission and its scope with the deployment record; the project does not include it.

## Local verification

Run `npm test` for matching, CSV parsing, and candidate state rules. `node --check src/*.mjs` can be run on each file for syntax. Live ServiceM8 OAuth, embedded signed menu launch and navigation, Homes data shape, scheduler timing, and database behaviour require staging verification with separate credentials and representative Jobs. No migration or outbound call was made in this local build.
# bc-checker
