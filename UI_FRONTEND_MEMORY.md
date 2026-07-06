# CyberDeep UI Frontend Memory

> Canonical frontend-only project memory. Read this before changing any CyberDeep user interface.
>
> Scope: HTML, CSS, browser JavaScript, visual design, interaction patterns, client-side state, responsive behavior, and the API response shapes consumed by the UI.
>
> Out of scope: packet parsing, enrichment algorithms, threat-feed implementation, databases, exports, server internals, and other backend behavior.

## 1. Frontend Identity

CyberDeep is a dark, information-dense digital investigation dashboard. It is an operational tool, not a marketing website. The interface prioritizes scanning, filtering, evidence comparison, and repeated investigation workflows.

Core visual characteristics:

- Near-black and dark navy surfaces.
- Cyan (`#00d2ff`) as the main dashboard accent.
- Red and orange reserved for risk, errors, and warnings.
- Compact cards, tables, badges, toolbars, and side panels.
- Lucide icons for interface actions and tool identities.
- Inter is the only project font.
- Desktop-first investigation workspace with responsive mobile fallbacks.

Do not redesign the project into a landing page, oversized hero composition, decorative card gallery, or single-color gradient theme.

## 2. Runtime UI Surfaces

| Route / file | Purpose | Frontend ownership |
|---|---|---|
| `/` / `index.html` | Main CyberDeep single-page dashboard and tool launcher | `index.html`, `style.css`, `app.js` |
| `/tool` | Standalone IP Intelligence investigation workspace | `app/templates/index.html`, `app/static/css/styles.css`, `app/static/js/app.js` |
| `/police_station_finder/` | Standalone police station finder | `police_station_finder/index.html`, `styles.css`, `app.js` |
| `/police_station_finder/google_maps.html` | Google Maps variant of the station finder | `google_maps.html`, `google_maps_app.js`, shared police CSS |

The FastAPI server serves the main dashboard at `/`, the standalone IP tool at `/tool`, and static assets from the project root and `/static`.

## 3. Frontend Technology

- Plain HTML5.
- Vanilla JavaScript; no React, Vue, Angular, or build step.
- Tailwind CSS loaded from CDN on the main dashboard.
- Project CSS layered after Tailwind for branded components and overrides.
- Bootstrap 5.3 CSS on the standalone IP Intelligence page only.
- Lucide icons loaded from CDN.
- Native browser APIs: Fetch, FormData, FileReader, Blob downloads, Canvas, Dialog, Geolocation, and Local Storage.
- Google Maps JavaScript API is loaded dynamically by the Google Maps station finder.

Because there is no bundler, keep browser code compatible with direct script loading and avoid package-only imports.

## 4. Canonical Frontend Files

### Main dashboard

- `index.html`: application shell, sidebar, top navigation, dashboard screen, tool screen, footer, and API credential modal.
- `style.css`: CyberDeep colors, cards, buttons, inputs, tables, modal styling, embedded IP Intelligence styles, and responsive rules.
- `app.js`: tool registry, all embedded tool templates, UI state, rendering, event binding, API requests, and dashboard controller.

### Shared design system

- `app/static/css/typography.css`: single source of truth for font family and typography scale.

### Standalone IP Intelligence

- `app/templates/index.html`: static workspace structure.
- `app/static/css/styles.css`: standalone layout and component styles.
- `app/static/js/app.js`: evidence upload, filters, tables, analytics band, details drawer, tabs, packets, and exports.

### Police Station Finder

- `police_station_finder/index.html`: standard finder.
- `police_station_finder/google_maps.html`: Google Maps finder.
- `police_station_finder/styles.css`: both finder layouts, light/dark themes, cards, filters, dialogs, and print behavior.
- `police_station_finder/app.js`: CSV ingestion, filters, canvas map, pagination, detail dialog, nearest-location logic, and export.
- `police_station_finder/google_maps_app.js`: Google Maps markers, search, filters, nearest station, and list synchronization.

## 5. Typography System

The only font is **Inter**.

Source of truth:

```css
app/static/css/typography.css
```

Tokens:

| Role | Size | Weight | Line height |
|---|---:|---:|---:|
| Page title | 32px | 600 | 1.2 |
| Section title | 24px | 600 | 1.3 |
| Card title | 18px | 500 | 1.4 |
| Body | 14px | 400 | 1.5 |
| Small | 12px | 400 | 1.4 |

Rules:

- Letter spacing is `0`.
- `font-mono` and `font-sans` both resolve to Inter for compatibility with existing Tailwind classes.
- Do not reintroduce JetBrains Mono, monospace, Segoe UI, system-ui, Arial, Consolas, or independent font stacks.
- Canvas text must explicitly use Inter because canvas does not inherit CSS.
- Use `.type-page-title`, `.type-section-title`, `.type-card-title`, `.type-body`, and `.type-small` for new semantic UI.

## 6. Main Dashboard Design Tokens

Defined in `style.css`:

```css
--bg-primary: #04060a;
--bg-secondary: #0a0e17;
--bg-tertiary: #101622;
--accent-lime: #00d2ff;
--accent-blue: #00d2ff;
--accent-red: #ff3366;
--accent-orange: #ff9900;
--text-primary: #f8fafc;
--text-secondary: #94a3b8;
--text-muted: #64748b;
```

Despite the legacy variable name `--accent-lime`, its current value is cyan. Preserve the variable for compatibility unless performing an intentional, project-wide migration.

Primary reusable classes:

- `.cyber-card`
- `.cyber-card-glow`
- `.cyber-input`
- `.cyber-btn`
- `.cyber-btn-secondary`
- `.cyber-btn-danger`
- `.cyber-badge`
- `.cyber-table`
- `.cyber-modal-overlay`

New controls should reuse these classes and Tailwind layout utilities rather than inventing unrelated component styling.

## 7. Main Dashboard Architecture

The main dashboard is a client-rendered SPA with two principal screens:

1. `#dashboard-screen`: overview, search, statistics, tool cards, recent activity, and command console.
2. `#tool-screen`: active tool header and injected tool content.

The global controller is `CyberDeepApp`, instantiated on `DOMContentLoaded`.

Important dashboard state:

- Selected category.
- Tool search query.
- Favorite tools.
- Recent activity.
- API credentials.
- High-contrast mode.
- Active tool.

The sidebar is fixed on desktop and slide-in on mobile. Tool cards are rendered from `TOOLS_REGISTRY`.

### Tool lifecycle

Each registry item normally contains:

```js
{
  id,
  name,
  category,
  icon,
  status,
  badgeType,
  description,
  placeholderHtml,
  initLogic
}
```

When opening a tool:

1. Hide the dashboard screen.
2. Show the tool screen.
3. Populate active tool title, icon, category, and template.
4. Insert `placeholderHtml` into `#active-tool-content`.
5. Run the tool's `initLogic`.
6. Call `lucide.createIcons()` after dynamic HTML insertion.

Always guard element lookups because tool templates are inserted and destroyed dynamically.

## 8. Registered Main Dashboard Tools

Current registry:

| ID | Name | Category |
|---|---|---|
| `ifsc-lookup` | IFSC Lookup | Financial |
| `police-finder` | Police Station Finder | OSINT |
| `ncrp-intelligence` | NCRP Intelligence | Law Enforcement |
| `mcc-mbs-lookup` | MCC-MBS Lookup | Financial Intelligence |
| `ip-sentinel` | Destination IP Mapping | Network Intelligence |
| `sms-header-analyzer` | SMS Header Analyzer | Intelligence |
| `ip-intel-analyzer` | IP Intelligence | Network Forensics |
| `subdomain-scanner` | Subdomain Scanner | Network Intelligence |

Add new tools through `TOOLS_REGISTRY`; do not hard-code additional dashboard cards separately.

## 9. Local Storage Contract

The main dashboard currently uses:

| Key | Purpose |
|---|---|
| `cd_favorites` | Favorite tool IDs |
| `cd_recents` | Recent tool activity |
| `cd_api_keys` | API credential form values |
| `cd_high_contrast` | High-contrast preference |
| `policeFinderRows` | Cached embedded police station records |

Treat existing keys as persistent public UI state. Avoid renaming them without a migration.

The standalone police finder also persists its theme preference.

## 10. Dynamic Rendering Rules

Much of the project uses template literals and `innerHTML`.

Required practices:

- Escape untrusted strings before inserting them into HTML.
- Rebind event listeners after replacing a container's `innerHTML`.
- Call `lucide.createIcons()` after inserting markup containing `data-lucide`.
- Preserve loading, empty, success, warning, and error states.
- Disable command buttons while asynchronous work is in progress.
- Restore button labels and enabled state in success and failure paths.
- Avoid global IDs that can collide across simultaneously visible tools.
- Prefer small render functions over adding more giant inline template blocks.

## 11. IP Intelligence UI

There are **two IP Intelligence frontend implementations**:

1. Embedded implementation inside `app.js`, launched from the main dashboard.
2. Standalone implementation in `app/templates/index.html` and `app/static/js/app.js`.

This duplication is the most important frontend maintenance risk.

When changing IP Intelligence UI behavior, check whether both versions require the same update. Shared concepts include:

- Evidence upload and progress.
- Summary cards.
- Host inventory.
- Session reconstruction.
- Flow diagram.
- Protocol summary.
- VoIP analysis.
- Destination Intelligence table.
- Search, scope, role, service, threat, and port filters.
- Selected destination detail.
- Overview, timeline, threat, WHOIS, DNS, ASN, correlation, report, flows, packets, and notes tabs.
- PDF, Excel, CSV, and JSON export links.

### Destination presentation

For STUN/TURN evidence:

- `192.168.x.x` direct peers may be marked as `Primary Direct Peer`.
- Infrastructure servers must remain labeled as STUN/TURN infrastructure.
- Background traffic is hidden in the default session scope but retained under all captured traffic.
- The selected first row should remain the primary destination when supplied by the API.

### Main consumed response fields

The UI expects these top-level fields where available:

```text
id
filename
rows
packet_rows
summary
hosts
sessions
flow_diagram
protocol_summary
voip_analysis
timeline
anomalies
correlation
session_focus
evidence_files
raw_connection_count
raw_packet_count
```

Rows contain destination identity, service, role, ASN, geography, threat, timing, packet totals, and raw connection evidence.

Do not silently rename response properties in frontend rendering code.

## 12. Police Station Finder UI

The standard finder supports:

- CSV upload and automatic local CSV loading.
- Global search.
- State and district filters.
- Coordinate and confidence filtering.
- Sorting and pagination.
- Canvas map.
- Clickable map points.
- Native detail dialog.
- Browser geolocation and manual coordinate search.
- Filtered CSV export.
- Dark mode and print layout.

The Google Maps variant supports:

- Runtime API key entry.
- Marker limits.
- Search, state, and district filters.
- Synchronized result list and map markers.
- Nearest-station lookup.
- Filtered CSV export.

CSV-facing UI should tolerate missing optional fields and display explicit fallback text rather than `undefined`.

## 13. Responsive Behavior

### Main dashboard

- Sidebar is hidden off-canvas below the Tailwind `md` breakpoint.
- Tool cards move from two columns to one on small screens.
- Dashboard statistics move from three columns to one.
- Main content uses `lg` layouts for wider tool and activity columns.

### Standalone IP Intelligence

- At `1240px`, overview and content grids collapse to one column.
- At `860px`, headers and toolbars stack; filters and summaries become two columns.
- At `560px`, filters and summary cards become one column.
- Packet workspace intentionally expands the packet/detail area on desktop.

### Police finder

- At `980px`, hero and finder layout collapse to one column.
- At `560px`, controls stack and spacing is reduced.
- Google Maps switches from sidebar plus map to a single column at `960px`.

Do not remove stable grid constraints from dense tables, packet workspaces, or filter toolbars without testing desktop and mobile overflow.

## 14. Accessibility and Interaction

Preserve:

- Semantic `button`, `input`, `select`, `table`, `dialog`, and heading elements.
- Keyboard-accessible native controls.
- Visible hover and focus feedback.
- Text labels for critical actions.
- Sufficient contrast against dark panels.
- `aria-label` usage on maps and appropriate control regions.
- High-contrast mode behavior.
- Loading and disabled states for async commands.

Do not replace native buttons with clickable `div` elements.

## 15. External UI Dependencies

- Tailwind CDN.
- Lucide CDN.
- Bootstrap CSS CDN on `/tool`.
- Google Fonts for Inter.
- Google Maps JavaScript API for the map variant.

External data calls visible from the browser include IFSC lookup, postal PIN lookup, optional IP geolocation, and local CyberDeep API endpoints.

Any new externally transmitted user input must be explicit in the UI and handled as a real network action.

## 16. Frontend Change Checklist

Before completing a frontend change:

1. Confirm which UI surface owns the feature.
2. Check for a duplicated embedded and standalone implementation.
3. Reuse Inter and shared typography tokens.
4. Reuse existing colors and component classes.
5. Preserve layout and responsive breakpoints unless the request requires changes.
6. Include loading, empty, success, and error states.
7. Escape dynamic strings inserted with `innerHTML`.
8. Re-run Lucide icon hydration after dynamic rendering.
9. Validate all edited JavaScript with `node --check`.
10. Test the live route and required API calls.
11. Check desktop and mobile layouts when browser tooling is available.
12. Do not modify backend behavior during a frontend-only task.

## 17. Preferred Future Refactors

These are safe directions when explicitly requested:

- Split the large root `app.js` into one module per tool.
- Extract shared IP Intelligence renderers used by embedded and standalone pages.
- Replace repeated inline styles in JavaScript templates with named CSS classes.
- Extract shared UI primitives for loading states, badges, empty states, tables, and detail rows.
- Add a local Inter asset only if offline font loading becomes a requirement.
- Add lightweight frontend tests for registry rendering, filters, selected rows, and local-storage state.

Do not perform these refactors incidentally during a narrow feature change.

## 18. Verification Commands

```powershell
node --check app.js
node --check app\static\js\app.js
node --check police_station_finder\app.js
node --check police_station_finder\google_maps_app.js
```

Live routes:

```text
http://127.0.0.1:8000/
http://127.0.0.1:8000/tool
http://127.0.0.1:8000/police_station_finder/
http://127.0.0.1:8000/police_station_finder/google_maps.html
```

## 19. Non-Negotiable UI Invariants

- Inter remains the only font.
- CyberDeep remains an operational investigation interface.
- Existing colors, layout density, and information hierarchy remain recognizable.
- Lucide remains the icon source.
- Tool workflows remain usable without a frontend build process.
- The main dashboard remains registry-driven.
- Background evidence must not be presented as a primary destination.
- Frontend-only changes must not alter backend analysis semantics.
