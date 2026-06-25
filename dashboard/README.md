# ActionTrust Dashboard

React + Vite dashboard for categorizing GitHub Actions risk.

## Features

- Loads the latest dataset assessment from the Go backend.
- Categorizes actions by risk level, entity type, and search terms.
- Shows top risky actions, workflows, repositories, business units, and software classes.
- Supports a modern dark UI optimized for analysis.

## Run locally

1. Start the Go backend.
2. From this folder, install frontend dependencies:
   - npm install
3. Start the dashboard:
   - npm run dev

If needed, set `VITE_API_BASE_URL` to point at the backend.
