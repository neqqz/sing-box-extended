import {
  Alert,
  Badge,
  Box,
  Button,
  Checkbox,
  Chip,
  CircularProgress,
  Collapse,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  IconButton,
  LinearProgress,
  MenuItem,
  Paper,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TablePagination,
  TableRow,
  TableSortLabel,
  TextField,
  Tooltip,
  Typography,
  useMediaQuery,
  useTheme,
} from "@mui/material";
import AddIcon from "@mui/icons-material/Add";
import ArrowDownwardIcon from "@mui/icons-material/ArrowDownward";
import ArrowUpwardIcon from "@mui/icons-material/ArrowUpward";
import AutorenewIcon from "@mui/icons-material/Autorenew";
import CalendarTodayIcon from "@mui/icons-material/CalendarToday";
import DeleteIcon from "@mui/icons-material/Delete";
import EditIcon from "@mui/icons-material/Edit";
import FilterAltIcon from "@mui/icons-material/FilterAlt";
import FilterAltOffIcon from "@mui/icons-material/FilterAltOff";
import InboxRoundedIcon from "@mui/icons-material/InboxRounded";
import KeyboardArrowDownIcon from "@mui/icons-material/KeyboardArrowDown";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import RefreshIcon from "@mui/icons-material/Refresh";
import RestartAltIcon from "@mui/icons-material/RestartAlt";
import SearchIcon from "@mui/icons-material/Search";
import UnfoldMoreIcon from "@mui/icons-material/UnfoldMore";
import { DateTimePicker } from "@mui/x-date-pickers/DateTimePicker";
import dayjs, { type Dayjs } from "dayjs";
import {
  forwardRef,
  memo,
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
  type ReactNode,
} from "react";
import type { Listable } from "../api/types";
import { notifyApiError, useNotify } from "../notifications/NotificationsProvider";
import { PageHeader } from "./PageHeader";

export type FieldType = "text" | "number" | "select" | "multiselect" | "ids" | "uuid" | "string-list";

// FILTER_WIDTH is the fixed CSS width (px) of a single filter cell in the
// filter panel. FILTER_GAP is the flex gap between cells (matches the
// `gap: 1.5` on the wrapping Box: MUI 8 px spacing × 1.5 = 12 px).
const FILTER_WIDTH = 240;
const FILTER_GAP = 12;
// "wide" filter cells (datetime-range, or any text/select cell with
// `wide: true`) span 1.5 "slots" of the grid. A 1-slot stretch across
// the gap accounts for half a gap (because skipping ½ a slot also skips
// ½ of its trailing gap), so the resulting outer box width snaps cleanly
// to the half-grid line.
const WIDE_FILTER_WIDTH = FILTER_WIDTH * 1.5 + FILTER_GAP * 0.5;

// generateUUID returns an RFC 4122 v4 UUID. Browsers > 2022 expose
// crypto.randomUUID; older ones get a manual implementation backed by
// crypto.getRandomValues (always available where fetch is).
export function generateUUID(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6]! & 0x0f) | 0x40; // version 4
  bytes[8] = (bytes[8]! & 0x3f) | 0x80; // variant 10xxxxxx
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export interface FieldSpec<TValue = unknown> {
  name: string;
  label: string;
  type: FieldType;
  required?: boolean;
  options?: { value: string; label?: string }[];
  helperText?: string;
  // Used by select/multiselect to render labels.
  defaultValue?: TValue;
  // If set, only show in create form / only in edit form.
  only?: "create" | "update";
  // Optional dynamic visibility — receives the current form values, returns
  // false to hide the field. Hidden fields are not rendered and not
  // submitted. Mirrors `FieldOnChooseOptionsHide` from the legacy admin.
  visibleWhen?: (form: Record<string, unknown>) => boolean;
  // When this field's value changes, every name listed here is reset to its
  // empty default. Used e.g. on the user `type` select to wipe credential
  // fields when the type changes.
  clears?: string[];
  // Async option loader, fired once when the dialog opens. The resolved list
  // takes precedence over `options` while rendering. Used by squad_ids on
  // every page so the multi-select is populated from GET /squads.
  optionsLoader?: () => Promise<{ value: string; label?: string }[]>;
  // For `multiselect` fields: render the chosen values as an ordered
  // pipeline (`User → Destination → IP`) rather than as independent
  // chips. Used by ordered/queue-style fields like `flow_keys`.
  displayAsChain?: boolean;
}

// emptyValueForField returns the canonical "empty" value for a given field
// spec, matching what `emptyForm` would produce.
function emptyValueForField(f: FieldSpec): unknown {
  if (f.defaultValue !== undefined) return f.defaultValue;
  if (f.type === "multiselect" || f.type === "string-list") return [];
  return "";
}

export interface ColumnSpec<TEntity> {
  key: keyof TEntity | string;
  label: string;
  render?: (row: TEntity) => ReactNode;
  // Whether the user can click the column header to sort by this column.
  // Defaults to `true` — pages explicitly opt-out for non-comparable
  // columns like `squad_ids` (array) or `status` (computed remote field).
  sortable?: boolean;
}

// RowActionSpec is a per-row IconButton rendered in the actions column,
// to the *left* of the built-in Edit / Delete buttons. Pages use it for
// row-scoped operations that aren't a direct field edit — e.g. the
// Traffic Limiters page exposes a "reset traffic" action this way.
//
// `onClick` receives a small context object with `reload`, the same
// callback CrudPage uses internally after Create / Edit / Delete; calling
// it after the action completes refreshes the table so the new row state
// (e.g. `usage` ticked back to 0) appears without forcing the user to
// hit Refresh.
export interface RowActionSpec<TEntity> {
  // Stable identifier — used as the React key for the rendered button so
  // toggling `visible` on / off doesn't churn the DOM.
  key: string;
  // Tooltip text and aria-label for the button.
  label: string;
  // Icon node, e.g. `<RestartAltIcon />`.
  icon: ReactNode;
  // Hover tint preset. "default" matches the EditIcon button (primary
  // hover), "danger" matches the DeleteIcon button (red hover).
  variant?: "default" | "danger";
  // Optional predicate; when supplied, the button is hidden for rows
  // that fail the check. Defaults to "always show".
  visible?: (row: TEntity) => boolean;
  // Optional confirmation step. When provided, clicking the action
  // opens a centred Dialog (same chrome as the Delete one) with the
  // returned title / description and a primary button labelled
  // `confirmLabel`. If omitted, `onClick` runs immediately on click.
  confirm?: (row: TEntity) => {
    title: string;
    description: string;
    // Primary button label. Defaults to `action.label`.
    confirmLabel?: string;
    // Label shown while `onClick` is in flight. Defaults to
    // `confirmLabel + "…"`.
    busyLabel?: string;
    // MUI palette for the primary button. Defaults to "primary".
    // `"error"` matches the destructive Delete dialog so dangerous
    // actions can reuse the same red treatment.
    color?: "primary" | "warning" | "error";
  };
  // The action callback. May be async — pages typically await the API
  // request and then call `ctx.reload()` to refresh the table. When
  // `confirm` is set, this only runs after the user clicks the
  // primary button in the dialog.
  onClick: (row: TEntity, ctx: { reload: () => Promise<void> }) => Promise<void> | void;
}

// FilterSpec describes a column filter rendered above the table.
//
// The filter value is sent as a query parameter on the list() call. For
// `datetime-range` two parameters are sent: `${name}_start` / `${name}_end`.
export type FilterType = "text" | "select" | "datetime-range";
export interface FilterSpec {
  name: string;
  label: string;
  type: FilterType;
  options?: { value: string; label?: string }[];
  placeholder?: string;
  // Render the filter cell at 1.5× the regular width — same slot size as
  // a `datetime-range` cell. Useful for inputs whose typical content is
  // long enough that the default 240 px feels cramped (e.g. a 36-char
  // UUID or a long URL). The slot still aligns with the half-grid line
  // so the surrounding flex-wrap layout stays tidy.
  wide?: boolean;
}

// optionLabel maps a raw select value to its human-readable label, matching
// service/admin_panel/tables/utils.go's optionLabelDisplay. Falls back to
// the raw stringified value when no option matches (e.g. unknown enum
// returned by the API).
export function optionLabel(
  options: { value: string; label?: string }[] | undefined,
  value: unknown,
): string {
  if (value === null || value === undefined) return "";
  const v = String(value);
  const found = options?.find((o) => o.value === v);
  return found?.label ?? v;
}

// renderOptionLabel returns a `render` function for a ColumnSpec that maps
// the row's single-value field to its option label. Use on `select`-type
// columns so the table shows "Hysteria" instead of "hysteria".
export function renderOptionLabel<TEntity>(
  key: keyof TEntity | string,
  options: { value: string; label?: string }[],
): (row: TEntity) => ReactNode {
  return (row: TEntity) => {
    const v = (row as Record<string, unknown>)[key as string];
    if (v === null || v === undefined || v === "") return "";
    return optionLabel(options, v);
  };
}

// Module-level style constants shared by every TableRow so React doesn't
// allocate fresh sx objects (and emotion doesn't re-hash CSS classes) on
// every row render. Theme tokens (text.secondary, action.active) are
// used instead of hardcoded white-with-alpha so the row reads correctly
// in both dark and light mode.
// Body cells inherit their column's width from the header under
// `tableLayout: fixed`. We clip overflow with ellipsis so a value longer
// than the user's chosen column width doesn't bleed into the next column.
const BODY_CELL_SX = {
  overflow: "hidden",
  textOverflow: "ellipsis",
  whiteSpace: "nowrap" as const,
};
const ID_CELL_SX = {
  fontFamily:
    '"JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace',
  fontSize: 12.5,
  color: "text.secondary",
  overflow: "hidden",
  textOverflow: "ellipsis",
  whiteSpace: "nowrap" as const,
} as const;
// Actions are pinned to the right edge of the table so the Edit /
// Delete buttons stay reachable no matter how wide the data columns
// grow or how far the user has scrolled the table horizontally.
// `position: sticky` + `right: 0` glues the cell to the right edge
// of its scroll container; the z-index hierarchy (header > body >
// data columns) makes the pinned column win overlap so the data
// columns slide visually under it.
//
// To avoid showing the scrolled-under column text through the
// pinned cell, the body / header cells need an opaque background
// that matches whatever colour the surrounding row / head currently
// renders. The theme paints solid colours for each state (see
// theme.ts):
//
//   - resting body row → `--sb-surface`     (Table backgroundColor)
//   - hovered body row → `--sb-elevated2`   (TableRow `:hover` !important)
//   - header row       → `--sb-elevated`    (MuiTableHead bg)
//
// Selected (no hover) is the only state MUI itself paints with a
// translucent accent overlay rather than a custom solid; we mimic
// it with `color-mix` so the sticky cell ends up at the same final
// pixel colour as the surrounding cells. Selected + hover is back
// to solid `--sb-elevated2` because the `:hover` override in the
// theme uses `!important` and wins over `Mui-selected`.
// Soft inset-style shadow on the left edge of the pinned Actions
// column. The negative spread (-4px) clips the blur to a thin band
// near the boundary, so it reads as a subtle separator when other
// content sits to the left without bleeding far into the cell.
const ACTIONS_CELL_SHADOW = "-4px 0 6px -4px rgba(0,0,0,0.18)";
const ACTIONS_CELL_SX = {
  paddingLeft: "8px",
  paddingRight: "8px",
  whiteSpace: "nowrap" as const,
  position: "sticky" as const,
  right: 0,
  zIndex: 2,
  backgroundColor: "var(--sb-surface)",
  boxShadow: ACTIONS_CELL_SHADOW,
  // Mirror the timing curve of `MuiTableRow` (`background-color 0.14s
  // ease` in theme.ts). Without this the sticky cell snaps to its new
  // background instantly while the rest of the row eases in, which
  // reads as a brief asymmetric flash on hover / unhover.
  transition: "background-color 0.14s ease",
  "tr:hover &": {
    backgroundColor: "var(--sb-elevated2)",
  },
  "tr.Mui-selected &": {
    backgroundColor:
      "color-mix(in srgb, var(--sb-accent) 8%, var(--sb-surface))",
  },
  "tr.Mui-selected:hover &": {
    backgroundColor: "var(--sb-elevated2)",
  },
};
const ACTIONS_HEADER_CELL_SX = {
  width: 92,
  paddingLeft: "8px",
  paddingRight: "8px",
  textAlign: "center" as const,
  position: "sticky" as const,
  right: 0,
  zIndex: 3,
  backgroundColor: "var(--sb-elevated)",
  boxShadow: ACTIONS_CELL_SHADOW,
};
// Filler cell — the only auto-width cell in each row. Padding stripped
// so it can collapse cleanly to 0 px width once the fixed columns
// overflow the viewport (any padding would otherwise add width that
// `tableLayout: fixed` can't fully reclaim). The default
// `border-bottom` from MuiTableCell is preserved on purpose so the
// row's horizontal divider extends across the empty span — without
// it the rule would visually break wherever the filler sits.
const FILLER_CELL_SX = {
  padding: 0,
} as const;
const EDIT_BTN_SX = { width: 28, height: 28 } as const;
const DELETE_BTN_SX = {
  width: 28,
  height: 28,
  color: "text.secondary",
  "&:hover": {
    color: "error.main",
    backgroundColor: "rgba(239,68,68,0.12)",
  },
} as const;

// renderOptionChain renders an array of option values as an ordered queue,
// e.g. `User → Destination → IP` rather than a set of independent chips.
// The order of the array is preserved verbatim, so a column rendered with
// this helper visualises "first match wins" behaviour for fair-queue /
// pipeline style fields.
export function renderOptionChain<TEntity>(
  key: keyof TEntity | string,
  options: { value: string; label?: string }[],
): (row: TEntity) => ReactNode {
  return (row: TEntity) => {
    const raw = (row as Record<string, unknown>)[key as string];
    if (!Array.isArray(raw) || raw.length === 0) return "";
    return (
      <Box
        sx={{
          display: "flex",
          flexWrap: "wrap",
          alignItems: "center",
          rowGap: 0.5,
          columnGap: 0.5,
          maxWidth: "100%",
        }}
      >
        {raw.map((v, i) => (
          <Box
            key={i}
            component="span"
            sx={{ display: "inline-flex", alignItems: "center", gap: 0.5 }}
          >
            {i > 0 && (
              <Box
                component="span"
                sx={{
                  color: "text.secondary",
                  fontSize: 12,
                  userSelect: "none",
                }}
              >
                →
              </Box>
            )}
            <Chip label={optionLabel(options, v)} size="small" />
          </Box>
        ))}
      </Box>
    );
  };
}

export interface CrudConfig<TEntity, TCreate, TUpdate> {
  title: string;
  subtitle?: string;
  // Icon shown next to the page title.
  icon?: ReactNode;
  idKey: keyof TEntity;
  columns: ColumnSpec<TEntity>[];
  fields: FieldSpec[];
  // Optional filter bar. Each entry becomes an input rendered above the
  // table; the applied values are forwarded to `list()` as query params.
  filters?: FilterSpec[];
  // Optional per-row IconButtons rendered before Edit/Delete in the
  // actions column. See RowActionSpec for the contract.
  rowActions?: RowActionSpec<TEntity>[];
  // list receives the applied filter query (+ any extra query params you add
  // to defaults later). Matches the signature of the generated API client.
  list: (query?: Listable) => Promise<TEntity[]>;
  // Optional total-row count. When provided, the table renders a pagination
  // bar at the bottom and pages through the data via `offset` + `limit`. The
  // count is fetched alongside `list` so the displayed range stays in sync.
  count?: (query?: Listable) => Promise<number>;
  create: (body: TCreate) => Promise<TEntity>;
  update: (id: string | number, body: TUpdate) => Promise<TEntity>;
  remove: (id: string | number) => Promise<TEntity>;
  toCreate: (form: Record<string, unknown>) => TCreate;
  toUpdate: (form: Record<string, unknown>, original: TEntity) => TUpdate;
  // Optionally derive form values from the row when editing.
  fromEntity?: (row: TEntity) => Record<string, unknown>;
  rowKey?: (row: TEntity) => string;
  // Default sort applied on first render. `field` is the column key; the
  // direction maps to `sort_asc` / `sort_desc` query params.
  defaultSort?: { field: string; dir: "asc" | "desc" };
  // Initial / fallback page size; defaults to 10.
  defaultPageSize?: number;
  // Fired after every successful `list()` response, with the rows that
  // are about to be rendered. Pages use it to fetch auxiliary data that
  // is only needed for what is on screen — e.g. squad names for the
  // rows in view — instead of pre-fetching the full catalog on mount.
  // If the callback returns a promise, `reload` awaits it before
  // publishing the new row set, so the table never flashes raw ids
  // before the friendly labels arrive. The callback is best-effort:
  // errors thrown (or rejections) are caught so a misbehaving observer
  // can't break the table refresh.
  onRowsChange?: (rows: TEntity[]) => void | Promise<void>;
}

// formatDatetimeForFilter converts a `<input type="datetime-local">` value
// ("YYYY-MM-DDTHH:MM" or "...:SS") into the "YYYY-MM-DD HH:MM:SS" shape the
// manager API expects.
//
// The repository stores TIMESTAMP columns as text like
// "2025-01-15 14:30:00.123456789+03:00" (modernc/sqlite's default time
// serialization) and the backend compares filter values to that text
// lexicographically. ISO-8601 strings ("...T...Z") sort *after* the
// space-separated stored values so any > filter would (incorrectly) match
// nothing — sending the value with a literal space here mirrors what the
// legacy admin_panel sends and is what makes the date filter actually work.
function formatDatetimeForFilter(input: string): string {
  if (!input) return input;
  const padded = input.length === 16 ? `${input}:00` : input;
  return padded.replace("T", " ");
}

// buildFilterQuery takes the raw filter-state object and turns it into a
// Listable query suitable for the API client: empty strings are dropped,
// datetime-range fields are split into _start / _end params.
function buildFilterQuery(
  specs: FilterSpec[],
  values: Record<string, unknown>,
): Listable {
  const out: Record<string, string | number | string[] | undefined> = {};
  for (const f of specs) {
    const raw = values[f.name];
    if (f.type === "datetime-range") {
      const r = (raw ?? {}) as { start?: string; end?: string };
      if (r.start) out[`${f.name}_start`] = formatDatetimeForFilter(r.start);
      if (r.end) out[`${f.name}_end`] = formatDatetimeForFilter(r.end);
      continue;
    }
    if (typeof raw === "string" && raw.trim() !== "") {
      out[f.name] = raw.trim();
    }
  }
  return out;
}

function countActiveFilters(
  specs: FilterSpec[],
  values: Record<string, unknown>,
): number {
  let n = 0;
  for (const f of specs) {
    const raw = values[f.name];
    if (f.type === "datetime-range") {
      const r = (raw ?? {}) as { start?: string; end?: string };
      if (r.start || r.end) n++;
      continue;
    }
    if (typeof raw === "string" && raw.trim() !== "") n++;
  }
  return n;
}

// filterValuesEqual compares two filter-state objects by spec, ignoring key
// insertion order. JSON.stringify-based equality used to false-positive
// "dirty" simply because the user typed filters in a different order, even
// when the canonical applied set matched the draft.
function filterValuesEqual(
  specs: FilterSpec[],
  a: Record<string, unknown>,
  b: Record<string, unknown>,
): boolean {
  for (const f of specs) {
    const av = a[f.name];
    const bv = b[f.name];
    if (f.type === "datetime-range") {
      const ar = (av ?? {}) as { start?: string; end?: string };
      const br = (bv ?? {}) as { start?: string; end?: string };
      if ((ar.start ?? "") !== (br.start ?? "")) return false;
      if ((ar.end ?? "") !== (br.end ?? "")) return false;
      continue;
    }
    const as = typeof av === "string" ? av : "";
    const bs = typeof bv === "string" ? bv : "";
    if (as !== bs) return false;
  }
  return true;
}

function emptyForm(fields: FieldSpec[], mode: "create" | "update"): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const f of fields) {
    if (f.only && f.only !== mode) continue;
    if (f.defaultValue !== undefined) {
      out[f.name] = f.defaultValue;
    } else if (f.type === "multiselect") {
      out[f.name] = [];
    } else if (f.type === "ids") {
      out[f.name] = "";
    } else if (f.type === "number") {
      out[f.name] = "";
    } else {
      out[f.name] = "";
    }
  }
  return out;
}

function parseIds(v: unknown): number[] {
  if (Array.isArray(v)) {
    return v
      .map((x) => Number(x))
      .filter((n) => Number.isFinite(n));
  }
  if (typeof v === "string") {
    return v
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
      .map((s) => Number(s))
      .filter((n) => Number.isFinite(n));
  }
  return [];
}

// fieldVisible reports whether a field should be displayed (and submitted)
// given the current mode + form values. Static `only` and dynamic
// `visibleWhen` rules are both honoured.
function fieldVisible(
  f: FieldSpec,
  mode: "create" | "update",
  form: Record<string, unknown>,
): boolean {
  if (f.only && f.only !== mode) return false;
  if (f.visibleWhen && !f.visibleWhen(form)) return false;
  return true;
}

// isFieldEmpty reports whether the user has provided no value for a field.
// The semantics match what the API would otherwise complain about: blank
// strings, missing selections, and empty arrays for multi-select / ids.
function isFieldEmpty(f: FieldSpec, value: unknown): boolean {
  if (value === undefined || value === null) return true;
  if (f.type === "multiselect" || f.type === "ids" || f.type === "string-list") {
    if (Array.isArray(value)) return value.length === 0;
    if (typeof value === "string") return value.trim() === "";
    return true;
  }
  if (f.type === "number") {
    if (value === "") return true;
    return !Number.isFinite(Number(value));
  }
  if (typeof value === "string") return value.trim() === "";
  return false;
}

// validateRequired returns a `{ field name -> message }` map describing
// every visible required field that the user has not filled in. The dialog
// uses this to block submit + render inline errors instead of letting the
// server reject the request.
export function validateRequired(
  fields: FieldSpec[],
  form: Record<string, unknown>,
): Record<string, string> {
  const errors: Record<string, string> = {};
  for (const f of fields) {
    if (!f.required) continue;
    if (isFieldEmpty(f, form[f.name])) errors[f.name] = "This field is required";
  }
  return errors;
}

export function normalizeFormForSubmit(
  fields: FieldSpec[],
  mode: "create" | "update",
  form: Record<string, unknown>,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const f of fields) {
    if (!fieldVisible(f, mode, form)) continue;
    const raw = form[f.name];
    if (f.type === "ids") {
      const arr = parseIds(raw);
      if (arr.length > 0 || f.required) out[f.name] = arr;
      continue;
    }
    if (f.type === "number") {
      if (raw === "" || raw === undefined || raw === null) {
        if (f.required) out[f.name] = 0;
        continue;
      }
      const n = Number(raw);
      out[f.name] = Number.isFinite(n) ? n : 0;
      continue;
    }
    if (f.type === "multiselect") {
      const arr = Array.isArray(raw) ? raw.filter(Boolean) : [];
      if (arr.length > 0 || f.required) out[f.name] = arr;
      continue;
    }
    if (typeof raw === "string") {
      const trimmed = raw.trim();
      if (trimmed === "" && !f.required) continue;
      out[f.name] = trimmed;
      continue;
    }
    if (raw !== undefined && raw !== null) out[f.name] = raw;
  }
  return out;
}

// shallowEqualRow reports whether two row objects describe the same data.
// Scalars are compared with `Object.is`; arrays are compared element-wise
// (still by `Object.is`) since every entity returned by the admin API
// uses flat fields with at most one level of array (e.g. `squad_ids`).
// The comparison is intentionally conservative — when in doubt we return
// false and let the row re-render rather than risk masking a real change.
function shallowEqualRow(
  a: Record<string, unknown>,
  b: Record<string, unknown>,
): boolean {
  if (a === b) return true;
  const ak = Object.keys(a);
  const bk = Object.keys(b);
  if (ak.length !== bk.length) return false;
  for (const k of ak) {
    const av = a[k];
    const bv = b[k];
    if (Object.is(av, bv)) continue;
    if (Array.isArray(av) && Array.isArray(bv)) {
      if (av.length !== bv.length) return false;
      let same = true;
      for (let i = 0; i < av.length; i++) {
        if (!Object.is(av[i], bv[i])) {
          same = false;
          break;
        }
      }
      if (!same) return false;
      continue;
    }
    return false;
  }
  return true;
}

// reconcileRows preserves the previous row reference for any entity whose
// content is structurally identical to the freshly fetched one. The
// memoised <CrudRow> uses `prev.row === next.row` as part of its
// equality check, so handing back the *same* reference for unchanged rows
// means a refresh that returns identical data does no row-level re-render
// at all — the table simply stays put. When *no* row has changed (length
// equal, every reconciled entry === the previous entry) we hand back the
// previous array verbatim so React's setState bail-out kicks in and the
// parent doesn't re-render either.
function reconcileRows<T extends Record<string, unknown>>(
  prev: T[],
  next: T[],
  idKey: keyof T,
): T[] {
  if (prev.length === 0) return next;
  const prevById = new Map<unknown, T>();
  for (const r of prev) prevById.set(r[idKey] as unknown, r);
  let allSame = prev.length === next.length;
  const out: T[] = new Array(next.length);
  for (let i = 0; i < next.length; i++) {
    const row = next[i]!;
    const old = prevById.get(row[idKey] as unknown);
    if (old && shallowEqualRow(old, row)) {
      out[i] = old;
      if (allSame && prev[i] !== old) allSame = false;
    } else {
      out[i] = row;
      allSame = false;
    }
  }
  return allSame ? prev : out;
}

// useColumnWidths — Excel-style resizable column state.
//
// Returns the current width (in px) for each column key, plus a `setWidth`
// setter and a `startResize` helper that wires up a mousedown handler. The
// widths are persisted in localStorage under `${storageKey}` so they
// survive page reloads. Columns with no stored width fall back to the
// browser's auto distribution under `tableLayout: fixed`.
const COL_WIDTH_PREFIX = "sing-box-admin:colw:";
const MIN_COL_WIDTH = 60;
// Default width assigned to a data column that the user hasn't resized
// yet and whose label is shorter than this. Every data column always
// gets an explicit width (this default, or a wider measured natural
// minimum, or the user's stored value) so the only auto-sized cell in
// the row is the trailing "filler" cell that absorbs any leftover
// horizontal space — that's what stops resizing one column from
// rebalancing the others under `tableLayout: fixed`.
const DEFAULT_DATA_COL_WIDTH = 160;
function useColumnWidths(storageKey: string) {
  const fullKey = COL_WIDTH_PREFIX + storageKey;
  const [widths, setWidths] = useState<Record<string, number>>(() => {
    try {
      const raw = localStorage.getItem(fullKey);
      if (raw) {
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed === "object") return parsed;
      }
    } catch {
      /* ignore */
    }
    return {};
  });

  const persist = useCallback(
    (next: Record<string, number>) => {
      try {
        localStorage.setItem(fullKey, JSON.stringify(next));
      } catch {
        /* ignore */
      }
    },
    [fullKey],
  );

  // Imperative setter used by the drag handler. We update the React state
  // *and* mirror to localStorage from a single place so both stay in sync.
  const setWidth = useCallback(
    (key: string, w: number) => {
      const clamped = Math.max(MIN_COL_WIDTH, Math.round(w));
      setWidths((prev) => {
        if (prev[key] === clamped) return prev;
        const next = { ...prev, [key]: clamped };
        persist(next);
        return next;
      });
    },
    [persist],
  );

  // Batched setter — used at resize-drag start to lock in the live widths
  // of every previously-unstored column in a single state update. Without
  // this lock-in, columns without a `stored` width auto-distribute under
  // `tableLayout: fixed`, so growing the dragged column would also shrink
  // every unstored neighbour by their share of the leftover (rubber-band
  // resize). Storing each column's current rendered width turns the
  // unstored neighbours into fixed-width columns for the duration of
  // the drag, so only the dragged column changes width while the others
  // stay pixel-stable. The cap from `getColumnMaxWidth` then keeps the
  // total table width ≤ the visible viewport, so no column ever ends up
  // tucked behind the sticky Actions cell.
  const setManyWidths = useCallback(
    (entries: Record<string, number>) => {
      setWidths((prev) => {
        let changed = false;
        const next = { ...prev };
        for (const k in entries) {
          const clamped = Math.max(MIN_COL_WIDTH, Math.round(entries[k]));
          if (prev[k] !== clamped) {
            next[k] = clamped;
            changed = true;
          }
        }
        if (!changed) return prev;
        persist(next);
        return next;
      });
    },
    [persist],
  );

  // Wipe every stored column width and drop the localStorage entry.
  // After this the table reverts to the same first-render layout new
  // users see: each data column falls back to `DEFAULT_DATA_COL_WIDTH`
  // (or its measured natural minimum, whichever is larger), and the
  // trailing filler cell soaks up the leftover space again. Used by
  // the toolbar's "Reset column widths" button.
  const resetWidths = useCallback(() => {
    setWidths((prev) => (Object.keys(prev).length === 0 ? prev : {}));
    try {
      localStorage.removeItem(fullKey);
    } catch {
      /* ignore */
    }
  }, [fullKey]);

  return { widths, setWidth, setManyWidths, resetWidths };
}

// usePersistedAppliedFilters — applied (submitted) filter values, persisted
// per-page in localStorage. `appliedFilters` is what's actually sent to the
// API; persisting it means a reload restores the user's last "Search"
// without forcing them to re-enter every filter. The draft state
// (`filterValues`) is left in component-local useState — half-typed inputs
// shouldn't survive a refresh.
const FILTERS_PREFIX = "sing-box-admin:filters:";
function usePersistedAppliedFilters(
  storageKey: string,
): [Record<string, unknown>, (next: Record<string, unknown>) => void] {
  const fullKey = FILTERS_PREFIX + storageKey;
  const [values, setValuesRaw] = useState<Record<string, unknown>>(() => {
    try {
      const raw = localStorage.getItem(fullKey);
      if (raw) {
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
          return parsed as Record<string, unknown>;
        }
      }
    } catch {
      /* ignore */
    }
    return {};
  });
  const setValues = useCallback(
    (next: Record<string, unknown>) => {
      setValuesRaw(next);
      try {
        if (Object.keys(next).length === 0) {
          localStorage.removeItem(fullKey);
        } else {
          localStorage.setItem(fullKey, JSON.stringify(next));
        }
      } catch {
        /* ignore */
      }
    },
    [fullKey],
  );
  return [values, setValues];
}

// usePersistedFiltersOpen — whether the filter panel is expanded. Mirrors
// the useState API (supports `(prev) => next` updates) so the existing
// `setShowFilters((s) => !s)` toggle keeps working unchanged.
//
// Mount strategy depends on whether this is the *very first* CrudPage
// instance mounted by the running SPA:
//
//   - First app mount (cold reload, F5): the state initialises
//     synchronously with the persisted value. Collapse renders with
//     in=true on its first paint and the open animation is skipped —
//     no "filter panel slides into view, table jumps down" jolt
//     when the user reloads a page that had filters left open.
//
//   - Subsequent mounts (navigating between admin routes via the
//     sidebar): the state still starts at `false` and flips to the
//     persisted value in a post-mount effect. MUI's <Collapse>
//     observes a `false → true` transition on the second render and
//     animates open, matching the user's expectation that switching
//     to a page with persisted-open filters reads as a deliberate
//     "filters appearing" rather than a static layout swap.
//
// The "is this the first app mount" decision is a module-level flag
// flipped once by the very first hook instance to mount. localStorage
// is read synchronously in both branches; the flag only changes the
// initial render's `in` value, not what's persisted.
const FILTERS_OPEN_PREFIX = "sing-box-admin:filters-open:";
let filtersFirstAppMount = true;
function readPersistedFiltersOpen(fullKey: string): boolean {
  try {
    return localStorage.getItem(fullKey) === "1";
  } catch {
    return false;
  }
}
function usePersistedFiltersOpen(
  storageKey: string,
): [
  boolean,
  (next: boolean | ((prev: boolean) => boolean)) => void,
  // `willAnimateOpen` — true iff the panel will transition from
  // closed to open after first paint on this mount. Captured once
  // at mount and never changes. CrudPage uses this to gate the
  // very first reload() so the table doesn't pop rows in mid-
  // animation when the user navigates between admin pages with
  // persisted-open filters. False on cold mounts (the panel is
  // committed already-open without animation) and on subsequent
  // mounts where filters were left closed (no animation will play).
  boolean,
] {
  const fullKey = FILTERS_OPEN_PREFIX + storageKey;
  // `useRef` so the "first ever hook instance" decision is stable
  // across re-renders of *this* CrudPage (without it, a re-render
  // before the post-mount effect runs would re-read
  // `filtersFirstAppMount` *after* it had been flipped, and treat
  // this same instance as a "subsequent mount").
  const isFirstMountRef = useRef(filtersFirstAppMount);
  const [open, setOpenRaw] = useState<boolean>(() =>
    isFirstMountRef.current ? readPersistedFiltersOpen(fullKey) : false,
  );
  // Captured once at mount alongside the initial state so cold vs
  // animated branches stay in sync (we evaluate the same flag and
  // the same persisted value, so a later localStorage change can't
  // make the two disagree on this mount).
  const willAnimateOpenRef = useRef(
    !isFirstMountRef.current && readPersistedFiltersOpen(fullKey),
  );
  useEffect(() => {
    if (isFirstMountRef.current) {
      // The first-ever CrudPage in the SPA already committed with the
      // persisted value applied — no second-render flip needed, and
      // no open animation should play. Just record that we're done
      // with the cold-load path so any later route change (which
      // mounts a fresh CrudPage instance) takes the animated branch.
      filtersFirstAppMount = false;
      return;
    }
    if (readPersistedFiltersOpen(fullKey)) setOpenRaw(true);
  }, [fullKey]);
  const setOpen = useCallback(
    (next: boolean | ((prev: boolean) => boolean)) => {
      setOpenRaw((prev) => {
        const resolved = typeof next === "function" ? next(prev) : next;
        try {
          localStorage.setItem(fullKey, resolved ? "1" : "0");
        } catch {
          /* ignore */
        }
        return resolved;
      });
    },
    [fullKey],
  );
  return [open, setOpen, willAnimateOpenRef.current];
}

// usePersistedPageSize — TablePagination rows-per-page, persisted per-page
// in localStorage so the user's choice (10/25/50/100) survives reloads.
// Falls back to `defaultSize` when nothing is stored or the stored value
// is corrupted.
const PAGE_SIZE_PREFIX = "sing-box-admin:pagesize:";
function usePersistedPageSize(
  storageKey: string,
  defaultSize: number,
): [number, (next: number) => void] {
  const fullKey = PAGE_SIZE_PREFIX + storageKey;
  const [size, setSizeRaw] = useState<number>(() => {
    try {
      const raw = localStorage.getItem(fullKey);
      if (raw) {
        const n = Number(raw);
        if (Number.isFinite(n) && n > 0) return n;
      }
    } catch {
      /* ignore */
    }
    return defaultSize;
  });
  const setSize = useCallback(
    (next: number) => {
      setSizeRaw(next);
      try {
        localStorage.setItem(fullKey, String(next));
      } catch {
        /* ignore */
      }
    },
    [fullKey],
  );
  return [size, setSize];
}

// usePersistedSort — active sort column + direction, persisted per-page in
// localStorage so the user's chosen ordering survives reloads and tab
// switches between admin pages. Both slices are stored together as a
// single JSON blob (`{ field, dir }`) so the two-stage "set field, then
// set dir" updates in `handleSort` and the mobile sort dropdown can never
// land in a half-written intermediate state on disk. Setters mirror the
// `useState` API (each accepts either a value or an updater) so the
// existing `setSortDir((d) => …)` toggle keeps working unchanged.
//
// Falls back to `defaultSort` (or `null` / `"asc"`) only when nothing is
// stored — once the user has touched the sort, an explicit "no sort"
// state (`field === null`) is preserved across reloads too.
const SORT_PREFIX = "sing-box-admin:sort:";
type SortDir = "asc" | "desc";
function usePersistedSort(
  storageKey: string,
  defaultSort: { field: string; dir: SortDir } | undefined,
): [
  string | null,
  (next: string | null | ((prev: string | null) => string | null)) => void,
  SortDir,
  (next: SortDir | ((prev: SortDir) => SortDir)) => void,
] {
  const fullKey = SORT_PREFIX + storageKey;
  const [state, setState] = useState<{ field: string | null; dir: SortDir }>(
    () => {
      try {
        const raw = localStorage.getItem(fullKey);
        if (raw) {
          const parsed = JSON.parse(raw);
          if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
            const field =
              typeof parsed.field === "string" || parsed.field === null
                ? parsed.field
                : null;
            const dir: SortDir = parsed.dir === "desc" ? "desc" : "asc";
            return { field, dir };
          }
        }
      } catch {
        /* ignore */
      }
      return {
        field: defaultSort?.field ?? null,
        dir: defaultSort?.dir ?? "asc",
      };
    },
  );

  const persist = useCallback(
    (next: { field: string | null; dir: SortDir }) => {
      try {
        localStorage.setItem(fullKey, JSON.stringify(next));
      } catch {
        /* ignore */
      }
    },
    [fullKey],
  );

  const setField = useCallback(
    (next: string | null | ((prev: string | null) => string | null)) => {
      setState((prev) => {
        const resolved = typeof next === "function" ? next(prev.field) : next;
        if (resolved === prev.field) return prev;
        const updated = { ...prev, field: resolved };
        persist(updated);
        return updated;
      });
    },
    [persist],
  );

  const setDir = useCallback(
    (next: SortDir | ((prev: SortDir) => SortDir)) => {
      setState((prev) => {
        const resolved = typeof next === "function" ? next(prev.dir) : next;
        if (resolved === prev.dir) return prev;
        const updated = { ...prev, dir: resolved };
        persist(updated);
        return updated;
      });
    },
    [persist],
  );

  return [state.field, setField, state.dir, setDir];
}

// ResizeHandle is the thin invisible bar that lives at the right edge of
// each resizable header cell. Mousedown captures the cursor + the header
// cell's current width, then mousemove updates the column width on every
// frame as the cursor drags. The handle paints a faint accent-coloured
// guide while dragging so the user can see exactly which column they're
// adjusting.
function ResizeHandle({
  columnKey,
  getCurrentWidth,
  setWidth,
  getMinWidth,
  getMaxWidth,
  onResizeStart,
  clipToCell = false,
}: {
  columnKey: string;
  getCurrentWidth: () => number;
  setWidth: (key: string, w: number) => void;
  // Per-column lower bound, measured from the actual header content so the
  // column can never be dragged narrower than its label + sort icon + cell
  // padding (otherwise the contents would overflow into the neighbouring
  // column). Falls back to the global `MIN_COL_WIDTH` if not provided.
  getMinWidth?: () => number;
  // Per-column upper bound. CrudPage passes a getter that keeps the sum
  // of all column widths ≤ the visible scroll viewport, so a column's
  // right edge can never travel past the sticky Actions column. Without
  // it the drag is unconstrained on the upper end.
  getMaxWidth?: () => number;
  // Fires once at the start of a drag, before `getCurrentWidth` is read
  // and before any mousemove listener is attached. CrudPage uses this to
  // lock in the live widths of every previously-unstored data column so
  // dragging one column doesn't rubber-band the unstored neighbours by
  // their share of the auto-distributed leftover; instead, only the
  // dragged column changes width and the cap from `getColumnMaxWidth`
  // keeps the total ≤ the visible viewport.
  onResizeStart?: () => void;
  // When true, the grab strip is clipped to the cell's own right edge
  // instead of overflowing 7 px into the neighbouring cell. Used for
  // the rightmost data column so the grab strip doesn't extend into
  // the sticky Actions column — its left edge should not feel
  // draggable.
  clipToCell?: boolean;
}) {
  const [active, setActive] = useState(false);

  const onMouseDown = useCallback(
    (e: React.MouseEvent<HTMLDivElement>) => {
      e.preventDefault();
      e.stopPropagation();
      // Run before reading `startW` so any width lock-in performed by
      // the parent (promoting auto-distributed columns to fixed widths)
      // is reflected in the layout the drag math anchors to. The DOM
      // read inside `getCurrentWidth` happens after this; even though
      // React hasn't re-rendered yet, the cell's bounding box is
      // unchanged (we lock in the *current* live widths), so the drag
      // anchor stays pixel-stable.
      onResizeStart?.();
      const startX = e.clientX;
      const startW = getCurrentWidth();
      setActive(true);
      const prevCursor = document.body.style.cursor;
      const prevSelect = document.body.style.userSelect;
      document.body.style.cursor = "col-resize";
      document.body.style.userSelect = "none";
      const onMove = (ev: MouseEvent) => {
        const target = startW + (ev.clientX - startX);
        const min = getMinWidth ? getMinWidth() : MIN_COL_WIDTH;
        const max = getMaxWidth ? getMaxWidth() : Number.POSITIVE_INFINITY;
        // Order matters: cap by max first, then floor by min, so that
        // when min > max (an over-tight container) the lower bound
        // wins and the column at least stays legible.
        setWidth(columnKey, Math.max(min, Math.min(max, target)));
      };
      const onUp = () => {
        setActive(false);
        document.body.style.cursor = prevCursor;
        document.body.style.userSelect = prevSelect;
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", onUp);
      };
      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
    },
    [columnKey, getCurrentWidth, setWidth, getMinWidth, getMaxWidth, onResizeStart],
  );

  // Double-click "resets" the column to the smallest size that still fits
  // its header content — same lower bound the drag handler enforces. With
  // a tighter natural minimum than the previous flat 60 px floor, the
  // reset never produces a column whose label spills into a neighbour.
  return (
    <Box
      onMouseDown={onMouseDown}
      onDoubleClick={(e) => {
        e.stopPropagation();
        const min = getMinWidth ? getMinWidth() : MIN_COL_WIDTH;
        setWidth(columnKey, min);
      }}
      sx={(t) => ({
        position: "absolute",
        top: 0,
        // Grab area is by default centred on the cell's right border
        // (right: -7, width: 14 → 7 px on each side of the boundary).
        // Wider than the previous 6 px strip so the column edge is
        // easy to hit without pixel-perfect aim, while still narrow
        // enough that it doesn't overlap any reasonable header
        // content.
        //
        // For the rightmost data column we instead clip the strip to
        // the cell's own right edge (right: 0, width: 7). That keeps
        // the boundary against the sticky Actions cell completely
        // dead — no col-resize cursor, no draggable strip — while
        // still giving the user 7 px to grab on the column's own
        // side of the boundary.
        right: clipToCell ? 0 : -7,
        bottom: 0,
        width: clipToCell ? 7 : 14,
        cursor: "col-resize",
        zIndex: 2,
        // The thin coloured guide that appears on hover and stays visible
        // while the user is actively dragging. Centred inside the grab
        // strip: (14 − 2) / 2 = 6 px from the left edge — or 5 px in
        // the clipped 7 px variant so the guide still sits flush with
        // the cell's right border.
        "&::after": {
          content: '""',
          position: "absolute",
          top: 8,
          bottom: 8,
          left: clipToCell ? 5 : 6,
          width: 2,
          borderRadius: 1,
          backgroundColor: active ? "var(--sb-accent)" : "transparent",
          transition: "background-color 0.12s ease",
        },
        "&:hover::after": {
          backgroundColor: active
            ? "var(--sb-accent)"
            : t.palette.action.selected,
        },
      })}
    />
  );
}

export function CrudPage<TEntity, TCreate, TUpdate>(props: { config: CrudConfig<TEntity, TCreate, TUpdate> }) {
  const { config } = props;
  // Responsive bits in this component (filter-cell widths, etc.) are
  // handled inline via `sx` breakpoint objects. Mobile-only full-screen
  // for the create/edit dialog is decided inside `CrudDialog` itself so
  // we don't have to thread a flag through every prop.
  //
  // Below `sm` (≤ 600 px) the data is rendered as a vertical list of
  // cards instead of a horizontally-scrolling table. On a phone the
  // table's narrow per-column widths make every value clip and force
  // the user to swipe sideways through the column set just to read a
  // single row — cards display every field of one row top-to-bottom
  // with a label/value layout, which reads naturally on touch and
  // keeps the entire row visible at once.
  const tableTheme = useTheme();
  const isMobile = useMediaQuery(tableTheme.breakpoints.down("sm"));
  const notify = useNotify();
  // entityLabel is the singular form of `config.title` ("Squads" → "Squad")
  // used in user-visible toast messages like "Squad created" / "3 Users
  // deleted". The slice handles the common plural-with-trailing-s pattern
  // every page in the admin uses today; pages whose title doesn't end in
  // "s" fall through unchanged.
  const entityLabel = useMemo(() => {
    const t = config.title;
    return t.endsWith("s") ? t.slice(0, -1) : t;
  }, [config.title]);
  const [rows, setRows] = useState<TEntity[]>([]);
  const [loading, setLoading] = useState(true);
  // `loadingVisible` is the user-facing loading flag — it lags behind
  // `loading` by ~180 ms so refreshes that finish quickly (e.g. on a
  // local network, where the round-trip is well under that threshold)
  // don't flash the LinearProgress or dim the table at all. The
  // refresh-icon spinner uses `loading` directly so the click still
  // gets immediate feedback; only the heavier visual treatment of the
  // table itself is deferred.
  const [loadingVisible, setLoadingVisible] = useState(false);
  useEffect(() => {
    if (!loading) {
      setLoadingVisible(false);
      return;
    }
    const id = window.setTimeout(() => setLoadingVisible(true), 180);
    return () => window.clearTimeout(id);
  }, [loading]);
  const [refreshSpinning, setRefreshSpinning] = useState(false);
  // `paginating` flips to `true` the moment the user changes page /
  // page size / sort / filters and stays true until the new data
  // arrives. We use it for two things:
  //
  //   (a) Fade just the row body to opacity 0 — desktop TableBody and
  //       mobile row-cards Stack — so the previous page's records
  //       don't visibly linger under the in-flight request. The
  //       column headers (desktop TableHead) and the mobile
  //       select-all + sort toolbar deliberately stay at full
  //       opacity, so the structure of the table remains legible
  //       while the data cells disappear.
  //
  //       Rows stay *mounted* during this fade — clearing them would
  //       collapse the table card to the bare empty-state height,
  //       which reads as a sudden snap; keeping them and just hiding
  //       them with opacity preserves the card's current height all
  //       the way through the round-trip. Once `reload` lands the
  //       new rows in `setRows`, the same gate fades the body back
  //       to opacity 1, so the new entries cross-fade into the slot
  //       the old ones were in.
  //
  //   (b) Suppress the "No data yet" empty-state placeholder so it
  //       doesn't flash between the moment the rows are hidden and
  //       the moment the new ones land — relevant when the previous
  //       page itself was empty and the user filtered / paginated
  //       to a different empty (or pending) result.
  const [paginating, setPaginating] = useState(false);

  // configRef holds the latest config without forcing `reload` to re-fire
  // when the parent's useMemo reidentifies it. Pages that do
  //
  //     const squads = useSquads(api);
  //     const config = useMemo(() => ({ ... }), [api, squads]);
  //
  // (Nodes / Users / *Limiters) get a *new* config object the moment the
  // /squads request resolves, even though `list` / `count` / `filters` are
  // structurally identical to the ones from the previous render. Reading the
  // CRUD callbacks via `configRef.current` inside the imperative reload
  // means a content-equivalent config swap doesn't trigger a second list +
  // count round-trip — fixing the "table loads twice" symptom on every
  // squad-aware page.
  //
  // The declarative paths (column rendering, filter chips, dialog fields)
  // keep reading `config` directly so they pick up the new render functions
  // / option lists on the next paint, which is what makes squad name chips
  // appear once /squads resolves.
  const configRef = useRef(config);
  configRef.current = config;

  // Filter state. Text/select entries are strings; datetime-range entries
  // are `{ start?: string; end?: string }` objects holding the raw value of
  // <input type="datetime-local" />.
  //
  // `filterValues` is the live "draft" — whatever is currently typed in the
  // panel. `appliedFilters` is what was actually submitted via Search. The
  // table re-fetches only when `appliedFilters` changes, so typing into a
  // text filter doesn't fire one request per keystroke.
  //
  // `filterSpecs` is memoised by the JSON of `config.filters` rather than by
  // its array reference. Pages declare `filters: [...]` inline inside their
  // `useMemo` factory, so the array literal is recreated whenever the
  // factory re-runs (e.g. when a `useSquads` catalog finishes loading). The
  // contents are unchanged, but a new reference would ripple through every
  // dep array that lists `filterSpecs` — including `reload`'s — and
  // re-fetch the table for no reason. JSON-stringifying the spec keeps the
  // memo stable across content-equivalent reidentifications. Filter specs
  // are tiny (`name`/`label`/`type` plus a few flags), so the stringify
  // cost is negligible.
  const filtersJSON = JSON.stringify(config.filters ?? []);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const filterSpecs = useMemo(() => config.filters ?? [], [filtersJSON]);
  // `appliedFilters` is persisted per-page in localStorage so the user's
  // last search survives reloads. The draft (`filterValues`) starts in
  // sync with the persisted applied set so the inputs render filled with
  // whatever was previously applied; subsequent typing stays
  // component-local until the user presses "Search" (or "Reset").
  const [appliedFilters, setAppliedFilters] = usePersistedAppliedFilters(
    config.title,
  );
  const [filterValues, setFilterValues] = useState<Record<string, unknown>>(
    () => appliedFilters,
  );
  const [showFilters, setShowFilters, filtersWillAnimateOpen] =
    usePersistedFiltersOpen(config.title);
  // `filtersFirstPaintReady` gates the very first reload() so the
  // table starts loading rows AFTER the filter panel has settled
  // into its initial state on this mount. Without this gate the
  // rows pop in before / during the panel's open animation when
  // the user navigates from the sidebar to a page with persisted-
  // open filters (subsequent CrudPage mount, panel transitions
  // from closed → open over ~180 ms).
  //
  // Initial value is true unless this mount is going to animate
  // the panel open — i.e. cold mounts, mounts with no filter
  // specs, and mounts where the panel was left closed are all
  // ready immediately. Subsequent flips happen via the Collapse's
  // `onEntered` callback (animation finished) or via a small
  // fallback timeout if the event was swallowed (e.g. the user
  // toggled the panel mid-animation).
  const [filtersFirstPaintReady, setFiltersFirstPaintReady] = useState(
    () => (config.filters?.length ?? 0) === 0 || !filtersWillAnimateOpen,
  );
  const activeFilterCount = useMemo(
    () => countActiveFilters(filterSpecs, appliedFilters),
    [filterSpecs, appliedFilters],
  );
  const draftFilterCount = useMemo(
    () => countActiveFilters(filterSpecs, filterValues),
    [filterSpecs, filterValues],
  );
  const filtersDirty = useMemo(
    () => !filterValuesEqual(filterSpecs, filterValues, appliedFilters),
    [filterSpecs, filterValues, appliedFilters],
  );

  // Pagination state. `page` is 0-indexed (MUI's TablePagination contract).
  // `total` is null until the count endpoint replies — when it's null the
  // pagination bar shows "1–N of more than N" so the user can still navigate.
  // `pageSize` is persisted per-page in localStorage so the user's chosen
  // rows-per-page survives reloads.
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = usePersistedPageSize(
    config.title,
    config.defaultPageSize ?? 10,
  );
  const [total, setTotal] = useState<number | null>(null);

  // Sort state. `field` mirrors the column key used by the API; the
  // direction is "asc" / "desc" → translated to `sort_asc` / `sort_desc`
  // query params, matching service/admin_panel/tables/*.go.
  //
  // Persisted per-page in localStorage (keyed off `config.title`, same
  // namespace as page size / filters / column widths) so switching
  // between admin tabs — or reloading the page — keeps whatever
  // column + direction the user last picked, including a deliberate
  // "no sort" choice (`sortField === null` after a third header click).
  const [sortField, setSortField, sortDir, setSortDir] = usePersistedSort(
    config.title,
    config.defaultSort,
  );

  // Each reload picks up a unique id; a response is only allowed to flip
  // state if its id still matches the latest. Without this guard a slow
  // prior reload could land *after* a newer one and overwrite the freshly
  // filtered rows with stale data.
  const reqRef = useRef(0);
  // Flips to `true` the first time a reload finishes (success or error).
  // The empty-state placeholder is rendered (and reserves its full
  // height) from mount onwards so the card never collapses to a
  // header-only strip while the first request is in flight; this flag
  // controls only its `visibility`, so the "No data yet" copy and CTA
  // never flash before we know whether the API actually has rows.
  const [hasFetched, setHasFetched] = useState(false);

  // Excel-style resizable column widths, persisted per page (keyed off the
  // page title). `headerCellRefs` tracks the live `<th>` element for each
  // column so the ResizeHandle can read the column's *actual* current
  // pixel width when the drag starts — that way the auto-distributed
  // widths from `tableLayout: fixed` on first render are honoured before
  // the user has touched anything.
  const {
    widths: columnWidths,
    setWidth: setColumnWidth,
    setManyWidths: setManyColumnWidths,
    resetWidths: resetColumnWidths,
  } = useColumnWidths(config.title);
  // True iff the user has resized at least one column away from its
  // default width — i.e. the localStorage entry would have a non-empty
  // payload. Drives the conditional render of the toolbar's "Reset
  // column widths" button so it only surfaces when there's actually
  // something to reset.
  const hasCustomColumnWidths = Object.keys(columnWidths).length > 0;
  const headerCellRefs = useRef<Record<string, HTMLTableCellElement | null>>({});
  // Inner ref to the inline-flex span that wraps each header's visible
  // content (label + sort caret). Measured to derive the per-column
  // natural minimum width — see `columnNaturalMins` below.
  const headerLabelRefs = useRef<Record<string, HTMLElement | null>>({});
  // Ref to the horizontally-scrolling container around the table. Used
  // to clamp column resize so a column's right edge can never travel
  // past the sticky Actions column — i.e. the total table width never
  // exceeds the visible scroll viewport width. Without this clamp the
  // user could grow a column wider than the viewport and end up with
  // the rightmost data columns hidden underneath the pinned Actions.
  const scrollContainerRef = useRef<HTMLDivElement | null>(null);
  const [tableViewportWidth, setTableViewportWidth] = useState<number | null>(
    null,
  );
  useEffect(() => {
    const el = scrollContainerRef.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(() => {
      setTableViewportWidth(el.clientWidth);
    });
    ro.observe(el);
    setTableViewportWidth(el.clientWidth);
    return () => ro.disconnect();
  }, []);
  const getColumnLiveWidth = useCallback(
    (key: string): number => {
      const stored = columnWidths[key];
      if (stored != null) return stored;
      const el = headerCellRefs.current[key];
      return el ? el.getBoundingClientRect().width : DEFAULT_DATA_COL_WIDTH;
    },
    [columnWidths],
  );

  // Promote every previously-unstored data column to a fixed width equal
  // to its current rendered width. Called once at the start of every
  // resize drag so the unstored neighbours don't rubber-band along with
  // the dragged column. Under `tableLayout: fixed`, columns without an
  // explicit width share the leftover horizontal space equally; without
  // this lock-in, growing the dragged column would shrink each unstored
  // neighbour by their share of the leftover instead of leaving them
  // alone. We snapshot live widths (not natural mins) so the visual
  // layout is byte-identical the instant the drag starts — the user
  // sees no jump.
  const lockInUnstoredColumnWidths = useCallback(() => {
    const entries: Record<string, number> = {};
    for (const c of config.columns) {
      const key = String(c.key);
      if (columnWidths[key] != null) continue;
      const el = headerCellRefs.current[key];
      if (!el) continue;
      entries[key] = el.getBoundingClientRect().width;
    }
    if (Object.keys(entries).length > 0) setManyColumnWidths(entries);
  }, [config.columns, columnWidths, setManyColumnWidths]);

  // columnNaturalMins is the smallest cell width that still fully shows a
  // column's header content (label text + sort caret) plus the cell's
  // horizontal padding. We measure the inner inline-flex wrapper after
  // each render — that node sizes itself to its content regardless of
  // the cell's enforced width, so it stays accurate even when the user
  // has resized the column smaller than its content.
  //
  // The state form (rather than a ref) is on purpose: when the natural
  // minimum changes (different label, font-load), we want React to
  // re-render so the cell's `width` is recomputed via the
  // `Math.max(stored, naturalMin)` rule below, and the visible column
  // can never be narrower than its content.
  const [columnNaturalMins, setColumnNaturalMins] = useState<
    Record<string, number>
  >({});
  // Buffer added on top of the measured label width — accounts for the
  // TableCell's left + right padding (16 px each in the size="small"
  // variant) plus a small safety margin so the resize handle's grab strip
  // never overlaps the last glyph of the label.
  const HEADER_PADDING_BUFFER = 32 + 8;
  useLayoutEffect(() => {
    const next: Record<string, number> = {};
    for (const c of config.columns) {
      const key = String(c.key);
      const el = headerLabelRefs.current[key];
      if (!el) continue;
      next[key] =
        Math.ceil(el.getBoundingClientRect().width) + HEADER_PADDING_BUFFER;
    }
    setColumnNaturalMins((prev) => {
      let same = Object.keys(next).length === Object.keys(prev).length;
      if (same) {
        for (const k in next) {
          if (prev[k] !== next[k]) {
            same = false;
            break;
          }
        }
      }
      return same ? prev : next;
    });
  });

  const getColumnNaturalMin = useCallback(
    (key: string): number => {
      const measured = columnNaturalMins[key];
      return measured != null ? Math.max(MIN_COL_WIDTH, measured) : MIN_COL_WIDTH;
    },
    [columnNaturalMins],
  );

  // tableMinWidth is the table's lower-bound width used to prevent column
  // overlap when the user resizes columns to a sum that exceeds the
  // container's width. With `tableLayout: fixed` and the default
  // `width: 100%`, a column that the user has dragged wider would
  // otherwise force the *other* columns to visually compress and overlap
  // their content (because the table itself can't grow past the
  // container). Setting `minWidth` to the actual sum of column widths
  // forces the table to grow when the columns no longer fit, which in
  // turn lets the surrounding `TableContainer` (which has
  // `overflow-x: auto`) provide a natural horizontal scrollbar.
  //
  // Each column contributes `max(stored, naturalMin)` so the lower bound
  // also covers cases where a previously-stored width is now narrower
  // than the column's measured content (e.g. the label text grew, or the
  // localStorage value predates this fix).
  const tableMinWidth = useMemo(() => {
    // checkbox column + actions column. The actions column starts at
    // 92 px (Edit + Delete) and grows by ~32 px per extra rowAction so
    // the sticky cell doesn't have to scroll its own children when a
    // page configures additional buttons (e.g. the "reset traffic"
    // action on the Traffic Limiters page).
    let sum = 72 + 92 + (config.rowActions?.length ?? 0) * 32;
    for (const c of config.columns) {
      const key = String(c.key);
      const stored = columnWidths[key];
      const naturalMin = getColumnNaturalMin(key);
      sum += stored != null
        ? Math.max(stored, naturalMin)
        : Math.max(naturalMin, DEFAULT_DATA_COL_WIDTH);
    }
    return sum;
  }, [config.columns, columnWidths, getColumnNaturalMin]);

  // getColumnMaxWidth — upper bound for a single column's width during
  // a resize drag. Excel-style: the only cap is the column's own
  // natural minimum (which is really a lower-bound, applied via
  // `Math.max(min, target)` in the drag handler — exposed here so the
  // ResizeHandle's max never falls below it for over-tight viewports).
  //
  // We deliberately do NOT cap by the visible scroll viewport: the
  // surrounding `TableContainer` is `overflow-x: auto`, so dragging a
  // column wider than the viewport just makes the table overflow and
  // scroll horizontally. The sticky Actions column stays pinned to
  // the right edge of the viewport regardless of how wide the data
  // columns get, which is the same behaviour spreadsheet users
  // expect.
  const getColumnMaxWidth = useCallback(
    (_key: string): number => {
      // No upper cap: the user can pull a column as wide as they like;
      // the table simply grows past the viewport and the surrounding
      // TableContainer scrolls horizontally.
      return Number.POSITIVE_INFINITY;
    },
    [],
  );
  const reload = useCallback(async () => {
    const reqId = ++reqRef.current;
    setLoading(true);
    try {
      // Read every config field through the ref so a content-equivalent
      // config swap (see `configRef` above) doesn't reach this callback's
      // dep array and trigger a duplicate fetch.
      const cfg = configRef.current;
      const filterQuery = buildFilterQuery(filterSpecs, appliedFilters);
      // Only the list endpoint cares about pagination + sort; count is
      // computed against the same filters but ignores those params.
      const listQuery: Listable = {
        ...filterQuery,
        offset: page * pageSize,
        limit: pageSize,
      };
      if (sortField) {
        if (sortDir === "asc") listQuery.sort_asc = sortField;
        else listQuery.sort_desc = sortField;
      }
      const [rowsResult, countResult] = await Promise.all([
        cfg.list(listQuery),
        cfg.count ? cfg.count(filterQuery) : Promise.resolve<number | null>(null),
      ]);
      if (reqRef.current !== reqId) return;
      // Notify observers (e.g. useSquadCatalog) with the new row set
      // *before* publishing it so they can fetch the auxiliary data
      // those rows reference (squad names, …). When the observer
      // returns a promise we await it, which is what keeps the table
      // from briefly rendering with raw ids before the friendly chip
      // labels arrive — once setRows fires, the supporting catalogs
      // are already populated and the first paint shows the final
      // names. `onRowsChange` is read through configRef — not the
      // `reload` dep array — so a new callback identity from the
      // parent's `useMemo` doesn't retrigger the fetch.
      if (cfg.onRowsChange) {
        try {
          await cfg.onRowsChange(rowsResult);
        } catch {
          /* best-effort: a misbehaving observer must not break the table */
        }
        if (reqRef.current !== reqId) return;
      }
      // Reconcile by primary key so refreshes that return identical data
      // re-use the previous row references — the memoised <CrudRow>
      // skips its render path when `prev.row === next.row`, which is
      // what keeps the table from visibly redrawing on a no-op refresh.
      // When every row is unchanged we even hand back the previous
      // array so React's setState bail-out short-circuits the parent
      // re-render entirely.
      setRows((prev) =>
        reconcileRows(
          prev as unknown as Record<string, unknown>[],
          rowsResult as unknown as Record<string, unknown>[],
          String(cfg.idKey),
        ) as unknown as TEntity[],
      );
      setTotal(countResult);
    } catch (e) {
      if (reqRef.current !== reqId) return;
      // Reload errors are surfaced exclusively through the global toast
      // stack — no inline Alert in the page chrome. The empty-state
      // placeholder still renders below (the table just stays empty)
      // so the user has both the toast and the visual cue that no rows
      // came back. `notifyApiError` picks a useful description for the
      // exception class (connection vs. HTTP vs. unauthorized).
      notifyApiError(notify, `Failed to load ${configRef.current.title}`, e);
    } finally {
      if (reqRef.current === reqId) {
        setLoading(false);
        setHasFetched(true);
        // Drop the `paginating` flag the moment the latest in-flight
        // request resolves — success or failure. The empty-state
        // placeholder reappears (if `rows` is still empty) and the
        // user's pagination/sort/filter change is fully landed.
        // Stale reloads (reqId mismatch above) leave it alone so a
        // newer pending pagination keeps the placeholder hidden.
        setPaginating(false);
      }
    }
  }, [filterSpecs, appliedFilters, page, pageSize, sortField, sortDir, notify]);

  useEffect(() => {
    if (!filtersFirstPaintReady) return;
    void reload();
  }, [reload, filtersFirstPaintReady]);

  // Safety net for the animated-open path: the Collapse's `onEntered`
  // is what normally flips `filtersFirstPaintReady` to true after the
  // panel finishes its ~180 ms open transition. If for any reason that
  // event doesn't fire — e.g. the user toggled the panel closed
  // mid-animation, or the Collapse unmounted before the transitionend
  // landed — fall back to a short timeout so the table doesn't sit
  // empty forever waiting for an event that already came and went.
  // This effect is a no-op for every mount path that initialises
  // `filtersFirstPaintReady` to true (cold mounts, no-filter pages,
  // and subsequent mounts with the panel left closed).
  useEffect(() => {
    if (filtersFirstPaintReady) return;
    const t = window.setTimeout(() => setFiltersFirstPaintReady(true), 250);
    return () => window.clearTimeout(t);
  }, [filtersFirstPaintReady]);

  const setFilterValue = (name: string, v: unknown) => {
    setFilterValues((p) => ({ ...p, [name]: v }));
  };
  // Applying / clearing filters resets the pagination to the first page
  // so the user is never left on a page that no longer exists. The row
  // list is faded to opacity 0 (but kept mounted) by the dependency-
  // driven effect that watches the same five values (search for
  // `setPaginating`), which arms the `paginating` flag the moment
  // any of `page`, `pageSize`, `sortField`, `sortDir`, or
  // `appliedFilters` change. The flag is cleared again from inside
  // `reload` once the new rows arrive, at which point the container
  // fades back to opacity 1 and the new rows cross-fade into the
  // slot the old ones occupied.
  const applyFilters = () => {
    setAppliedFilters(filterValues);
    setPage(0);
  };
  const resetFilters = () => {
    setFilterValues({});
    setAppliedFilters({});
    setPage(0);
  };

  // handleSort toggles between asc → desc → unsorted on the active column,
  // and switches to a fresh column when a different header is clicked.
  // Changing sort always returns to the first page so the user sees the
  // top of the new ordering.
  const handleSort = (key: string) => {
    if (sortField === key) {
      if (sortDir === "asc") {
        setSortDir("desc");
      } else {
        // Third click clears the sort.
        setSortField(null);
        setSortDir("asc");
      }
    } else {
      setSortField(key);
      setSortDir("asc");
    }
    setPage(0);
  };

  const [editing, setEditing] = useState<TEntity | null>(null);
  const [creating, setCreating] = useState(false);
  // `dialogOpen` drives the MUI Dialog's `open` prop directly; flipping it
  // to false starts the leave transition. `creating` / `editing` are
  // cleared only after the transition finishes (handleDialogExited) so the
  // dialog keeps rendering its current title and form contents through
  // the fade-out — same trick the delete-confirm dialog uses with
  // `lastPendingDeleteRef` below.
  const [dialogOpen, setDialogOpen] = useState(false);

  const openCreate = useCallback(() => {
    setEditing(null);
    setCreating(true);
    setDialogOpen(true);
  }, []);

  const closeDialog = () => {
    setDialogOpen(false);
  };

  const handleDialogExited = () => {
    setCreating(false);
    setEditing(null);
  };

  // Global keyboard shortcut: pressing "n" (physical key, layout-
  // independent) anywhere on the page opens the Create dialog. We use
  // `ev.code === "KeyN"` rather than `ev.key === "n"` so the shortcut
  // fires regardless of keyboard layout — a Russian / Cyrillic layout
  // would otherwise emit `ev.key === "т"`.
  // Skipped while another dialog is open, when a modifier is held
  // (so Ctrl+N etc. keep their browser meaning), and when the user is
  // typing into an input.
  // While the dialog is closing the MUI `open` prop is already false but
  // `creating`/`editing` are still set (cleared by handleDialogExited);
  // gate the shortcut on that combined "live" predicate so a stray "n"
  // press during the leave animation doesn't immediately reopen.
  const dialogLive = dialogOpen || creating || editing !== null;
  useEffect(() => {
    const handler = (ev: globalThis.KeyboardEvent) => {
      if (ev.code !== "KeyN") return;
      if (ev.ctrlKey || ev.metaKey || ev.altKey) return;
      if (dialogLive) return;
      const target = ev.target as HTMLElement | null;
      if (target) {
        const tag = target.tagName;
        if (
          tag === "INPUT" ||
          tag === "TEXTAREA" ||
          tag === "SELECT" ||
          target.isContentEditable
        )
          return;
      }
      ev.preventDefault();
      openCreate();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [dialogLive, openCreate]);

  // Minimum visible window for the form dialog's "Saving…" busy state,
  // mirroring the delete-dialog treatment. Without it, a sub-100 ms
  // create/update round-trip causes the spinner + label to appear for
  // a single frame and disappear — the user perceives that as a glitch
  // rather than as the action having run. Both handlers gate `closeDialog`
  // (and the error toast) on this so the on-screen busy state is held
  // long enough to be perceived even on a fast network.
  const ensureMinFormBusy = async (startTs: number) => {
    const elapsed = performance.now() - startTs;
    const minBusyMs = 350;
    if (elapsed < minBusyMs) {
      await new Promise((r) => setTimeout(r, minBusyMs - elapsed));
    }
  };

  // Both handlers re-throw so the dialog's inline error UI keeps working
  // (the dialog catches and renders the message inside an Alert). The toast
  // is a complementary signal: it flashes a quick "X created" / "Failed to
  // create X" status without interfering with the dialog's per-field error
  // panel. notifyApiError silently swallows UnauthorizedError because the
  // global 401 handler in AuthContext already announces those.
  const handleCreate = async (form: Record<string, unknown>) => {
    const body = config.toCreate(form) as TCreate;
    const startTs = performance.now();
    try {
      await config.create(body);
    } catch (e) {
      await ensureMinFormBusy(startTs);
      notifyApiError(notify, `Failed to create ${entityLabel}`, e);
      throw e;
    }
    await ensureMinFormBusy(startTs);
    closeDialog();
    notify.success(`${entityLabel} created successfully`);
    await reload();
  };

  const handleUpdate = async (form: Record<string, unknown>) => {
    if (!editing) return;
    const id = editing[config.idKey] as unknown as string | number;
    const body = config.toUpdate(form, editing) as TUpdate;
    const startTs = performance.now();
    try {
      await config.update(id, body);
    } catch (e) {
      await ensureMinFormBusy(startTs);
      notifyApiError(notify, `Failed to update ${entityLabel}`, e);
      throw e;
    }
    await ensureMinFormBusy(startTs);
    closeDialog();
    notify.success(`${entityLabel} updated successfully`);
    await reload();
  };

  // -------- Delete confirmation ----------------------------------------
  // A single MUI dialog drives both the per-row Delete icon and the bulk
  // "Delete selected" button. `pendingDelete` carries the primary keys
  // about to be removed; null means the dialog is closed.
  const [pendingDelete, setPendingDelete] = useState<
    | { kind: "single"; id: string | number; label: string }
    | { kind: "bulk"; ids: (string | number)[] }
    | null
  >(null);
  const [deleteBusy, setDeleteBusy] = useState(false);
  // Hold onto the last non-null `pendingDelete` so the dialog title and
  // body keep showing the entity label/count during the MUI fade-out
  // animation that fires after `setPendingDelete(null)`. Without this,
  // the closing dialog briefly renders " will be permanently removed
  // from the database." with an empty subject — which looks like the
  // name "vanishes" the instant the user clicks Delete.
  const lastPendingDeleteRef = useRef(pendingDelete);
  if (pendingDelete !== null) {
    lastPendingDeleteRef.current = pendingDelete;
  }
  const displayPendingDelete = pendingDelete ?? lastPendingDeleteRef.current;

  const handleDelete = useCallback(
    (row: TEntity) => {
      const id = row[config.idKey] as unknown as string | number;
      setPendingDelete({
        kind: "single",
        id,
        label: `${config.title.slice(0, -1)} #${String(id)}`,
      });
    },
    [config.idKey, config.title],
  );
  // Stable `setEditing` wrapper so memoised rows don't re-render just
  // because the inline `() => setEditing(row)` arrow swaps reference
  // every parent render. setEditing itself is already stable from
  // useState, but the row needs a `(row) => void` callback. We also flip
  // `dialogOpen` here to start the enter transition — closeDialog leaves
  // it set to false, so reopening must explicitly set it back to true.
  const handleEdit = useCallback((row: TEntity) => {
    setCreating(false);
    setEditing(row);
    setDialogOpen(true);
  }, []);

  // pendingAction drives the row-action confirmation dialog (mirror of
  // pendingDelete above). Null when no dialog is open. Pages opt into
  // the dialog by setting `RowActionSpec.confirm`; actions without
  // `confirm` skip this state and run inline in `handleRunAction`.
  const [pendingAction, setPendingAction] = useState<
    { row: TEntity; action: RowActionSpec<TEntity> } | null
  >(null);
  const [actionBusy, setActionBusy] = useState(false);
  // Same trick as `lastPendingDeleteRef`: hold the last non-null
  // pendingAction so the dialog can keep displaying its title /
  // description while it animates closed (after `setPendingAction(null)`).
  const lastPendingActionRef = useRef(pendingAction);
  if (pendingAction !== null) {
    lastPendingActionRef.current = pendingAction;
  }
  const displayPendingAction = pendingAction ?? lastPendingActionRef.current;
  const displayActionConfirm = useMemo(() => {
    if (!displayPendingAction?.action.confirm) return null;
    return displayPendingAction.action.confirm(displayPendingAction.row);
  }, [displayPendingAction]);

  // handleRunAction either opens the confirmation dialog (when the
  // action declares one) or invokes the action immediately. Inline
  // errors are surfaced through the global toast stack the same way
  // the CrudPage's own Create / Edit / Delete failures are; the
  // action's `onClick` itself is responsible for emitting any success
  // toast.
  const handleRunAction = useCallback(
    (row: TEntity, action: RowActionSpec<TEntity>) => {
      if (action.confirm) {
        setPendingAction({ row, action });
        return;
      }
      void Promise.resolve(action.onClick(row, { reload })).catch((e) => {
        notifyApiError(notify, `Failed to ${action.label.toLowerCase()}`, e);
      });
    },
    [reload, notify],
  );

  // confirmAction is the primary-button handler for the row-action
  // dialog. Modeled on confirmDelete: minimum-visible busy state to
  // suppress single-frame flickers, errors keep the dialog open so
  // the user can retry, success closes it and reloads the table.
  const confirmAction = async () => {
    if (!pendingAction) return;
    setActionBusy(true);
    const startTs = performance.now();
    const minBusyMs = 350;
    let shouldClose = false;
    try {
      await Promise.resolve(
        pendingAction.action.onClick(pendingAction.row, { reload }),
      );
      shouldClose = true;
    } catch (e) {
      notifyApiError(
        notify,
        `Failed to ${pendingAction.action.label.toLowerCase()}`,
        e,
      );
    }
    const elapsed = performance.now() - startTs;
    if (elapsed < minBusyMs) {
      await new Promise((r) => setTimeout(r, minBusyMs - elapsed));
    }
    if (shouldClose) {
      setPendingAction(null);
      // Hold the busy visuals through the dialog's exit animation so
      // the button label / spinner don't snap back to idle while the
      // dialog itself is still fading away on screen — same 260 ms
      // as confirmDelete.
      setTimeout(() => setActionBusy(false), 260);
    } else {
      setActionBusy(false);
    }
  };

  // pluralEntityLabel formats the entity label for a count of things —
  // singular when count === 1, the configured plural title otherwise. Used
  // for bulk-delete toasts so 1 row reads "Squad deleted" while 5 rows
  // read "5 Squads deleted".
  const pluralEntityLabel = (count: number) =>
    count === 1 ? entityLabel : config.title;

  const confirmDelete = async () => {
    if (!pendingDelete) return;
    setDeleteBusy(true);
    const startTs = performance.now();
    // Minimum visible duration for the "Deleting…" state. Without
    // this, a sub-100 ms network round-trip causes the label /
    // spinner to flicker on for a single frame and back off, which
    // reads as "the button glitched" rather than "the action ran".
    const minBusyMs = 350;
    let shouldClose = false;
    try {
      if (pendingDelete.kind === "single") {
        try {
          await config.remove(pendingDelete.id);
        } catch (e) {
          notifyApiError(notify, `Failed to delete ${entityLabel}`, e);
          throw e;
        }
        notify.success(`${entityLabel} deleted successfully`);
      } else {
        // Run bulk deletes in parallel; settle-all so a single failure
        // doesn't hide the successes from the reload below. We then split
        // the results so the user sees both halves: a green "N deleted"
        // chip for the wins and a red "M failed" chip for the losses.
        const results = await Promise.allSettled(
          pendingDelete.ids.map((id) => config.remove(id)),
        );
        const ok = results.filter((r) => r.status === "fulfilled").length;
        const failed = results.length - ok;
        if (ok > 0) {
          notify.success(
            `${ok} ${pluralEntityLabel(ok)} deleted successfully`,
          );
        }
        if (failed > 0) {
          // Surface the first error verbatim — almost always the same
          // for every entry (permissions / FK constraint / connectivity)
          // so picking a representative one keeps the toast useful.
          const firstReason = (results.find(
            (r) => r.status === "rejected",
          ) as PromiseRejectedResult | undefined)?.reason;
          if (firstReason !== undefined) {
            notifyApiError(
              notify,
              `Failed to delete ${failed} ${pluralEntityLabel(failed)}`,
              firstReason,
            );
          } else {
            notify.error(
              `Failed to delete ${failed} ${pluralEntityLabel(failed)}`,
            );
          }
        }
      }
      shouldClose = true;
    } catch {
      // Already announced via `notifyApiError` inside the inner try.
      // Swallow here so the rejection doesn't bubble to the global
      // error handler — the dialog stays open (we never set
      // `shouldClose = true`) so the user can retry or cancel.
    }
    const elapsed = performance.now() - startTs;
    if (elapsed < minBusyMs) {
      await new Promise((r) => setTimeout(r, minBusyMs - elapsed));
    }
    if (shouldClose) {
      setPendingDelete(null);
      setSelected(new Set());
      await reload();
      // Hold the busy visuals through the dialog's exit animation
      // (~225 ms default MUI Dialog fade) so the button label /
      // spinner don't snap back to the idle "Delete" state while
      // the dialog itself is still fading away on screen.
      setTimeout(() => setDeleteBusy(false), 260);
    } else {
      setDeleteBusy(false);
    }
  };

  // -------- Selection / bulk actions ------------------------------------
  // `selected` holds the primary-key values (string | number) of every
  // currently checked row. We scope the selection to the rows that are
  // actually visible — paginating, applying filters, sorting or reloading
  // wipes it so the user can't accidentally bulk-act on rows they're no
  // longer looking at.
  const idOf = useCallback(
    (row: TEntity): string | number =>
      row[config.idKey] as unknown as string | number,
    [config.idKey],
  );
  // Stabilise the columns reference so memoised rows don't re-render
  // every time the parent's config object is reconstructed (which happens
  // on each parent render when filterValues / loading / etc. change).
  const columnsRef = useMemo(() => config.columns, [config.columns]);

  // Subset of columns the user is allowed to sort by — mirrors the
  // desktop header logic where each TableSortLabel is gated on
  // `c.sortable !== false`. Computed once per columns reference so
  // the mobile sort dropdown doesn't rebuild its option list on every
  // unrelated render.
  const sortableColumns = useMemo(
    () => config.columns.filter((c) => (c.sortable ?? true) !== false),
    [config.columns],
  );

  // -------- Smooth size transitions ------------------------------------
  // The table card's height changes every time the row count does
  // (filter applied, page changed, route switched). The Web Animations
  // API smoothly tweens between the old and new heights — useLayoutEffect
  // runs after the DOM update but before paint, so the captured height
  // represents the *new* layout while `prevHeightRef.current` still holds
  // the previous one.
  //
  // Speed (px / sec) is held constant rather than the duration: with a
  // fixed 220 ms a small +1-row change felt sluggish while a +25-row
  // jump looked rushed, because the same 220 ms had to cover wildly
  // different deltas. Sliding at a constant px/sec keeps the visual
  // velocity uniform regardless of how many rows just arrived from
  // the API. The clamp on the bottom prevents micro-deltas from
  // animating in 5 ms (effectively a snap), and the cap on top keeps
  // very large jumps from feeling laggy.
  //
  // Desktop (md+) skips this tween entirely: the layout pins the Paper
  // to `flex: 1` of the leftover viewport space, so its `offsetHeight`
  // is governed by flex, not by row count. Animating `height: Xpx`
  // through the Web Animations API would temporarily inline an
  // explicit pixel height that fights the flex algorithm — the
  // browser briefly resolves the Paper to that fixed height while
  // it would have otherwise been "fill-leftover", which translates
  // into the PageHeader / filter area visibly jumping toward the
  // top each time fetched rows arrive (because the parent flex
  // chain redistributes the leftover space differently when one
  // child has an explicit height versus a `flex-basis: 0%`). On
  // mobile / sm where the Paper is still block-laid-out and grows
  // with content, the tween stays useful and runs unchanged.
  const heightTweenTheme = useTheme();
  const heightTweenIsDesktop = useMediaQuery(
    heightTweenTheme.breakpoints.up("md"),
  );
  const tableRef = useRef<HTMLDivElement | null>(null);
  const prevHeightRef = useRef<number | null>(null);
  useLayoutEffect(() => {
    const el = tableRef.current;
    if (!el) return;
    if (heightTweenIsDesktop) {
      // Keep the ref bookkeeping in sync so a future viewport
      // resize back to mobile starts from a sane baseline rather
      // than from the height captured pre-`md`.
      prevHeightRef.current = el.offsetHeight;
      return;
    }
    const newHeight = el.offsetHeight;
    if (
      prevHeightRef.current !== null &&
      prevHeightRef.current !== newHeight &&
      typeof el.animate === "function"
    ) {
      const delta = Math.abs(newHeight - prevHeightRef.current);
      // Calibrated so big swaps don't drag: at 1300 px/sec, a
      // typical single-row delta (~50 px) still clears the
      // 240 ms floor; a 200 px change takes ~154 ms (floored);
      // a ~40-row swap (~800 px) takes ~615 ms; a full-page
      // resize (e.g. 100 → 10 rows, ~4500 px) takes ~3.5 s
      // mathematically but is hard-capped at 560 ms so very
      // large reflows never feel like waiting.
      const PX_PER_SEC = 1300;
      // Floor of 240 ms is the inflection where motion reads
      // as "deliberate movement" rather than a snap on 60 Hz
      // displays — going below ~220 ms with a symmetric easing
      // curve loses the perceptible glide.
      const MIN_MS = 240;
      // Ceiling of 560 ms keeps even the biggest page-size
      // changes from dragging — past ~600 ms a height tween
      // tips over from "the table is settling" into "the table
      // is slow", regardless of how many rows just arrived.
      const MAX_MS = 560;
      const duration = Math.max(
        MIN_MS,
        Math.min(MAX_MS, (delta / PX_PER_SEC) * 1000),
      );
      el.animate(
        [
          { height: `${prevHeightRef.current}px` },
          { height: `${newHeight}px` },
        ],
        // Symmetric S-curve (gentle ease-in-out). The previous
        // Material-standard `cubic-bezier(0.4, 0, 0.2, 1)`
        // started fast and decelerated — the card lurched out
        // of its starting height and then crawled into place.
        // `0.45, 0, 0.55, 1` is a balanced sigmoid: slow at both
        // ends and brisk through the middle, which reads as a
        // continuous, "pulled" reflow.
        { duration, easing: "cubic-bezier(0.45, 0, 0.55, 1)" },
      );
    }
    prevHeightRef.current = newHeight;
  }, [rows.length, hasFetched, heightTweenIsDesktop]);

  // -------- Row-count-scaled animation timings -------------------------
  // The dim overlay and the top progress bar both fade with a duration
  // that grows with the size of the visible table. Few rows → snappy
  // (the table is small, so the eye absorbs the change instantly);
  // many rows → graceful (a wall of cells benefits from a longer
  // breath so the dim looks like a deliberate veil rather than a
  // strobe).
  //
  // The square-root curve climbs steeply for the first few rows then
  // flattens out — perceptually we're far more sensitive to the
  // difference between 0 and 5 rows than between 50 and 100, so the
  // ramp matches that. `Math.sqrt(50) ≈ 7.07`, so the divisor of 7
  // saturates the scale near 50 rows and then plateaus.
  //
  // The height-tween animation already scales with pixel delta
  // (`PX_PER_SEC` / `MIN_MS` / `MAX_MS` above), which is itself a
  // proxy for "how many rows just appeared/disappeared", so we don't
  // need a separate row-count factor there.
  const rowAnimScale = Math.min(1, Math.sqrt(rows.length) / 7);
  // 220 ms (empty / 1 row) → 460 ms (50+ rows). The upper bound is
  // intentionally compressed: at the previous 700 ms ceiling, big
  // tables felt sluggish — a wall of 50+ rows benefits from a
  // longer-than-snappy fade, but past ~450 ms the user starts
  // *waiting* on the dim instead of perceiving it as stale-state
  // feedback.
  const dimDurationMs = Math.round(220 + rowAnimScale * 240);
  // 180 ms (empty / 1 row) → 360 ms (50+ rows). Still slightly
  // faster than the dim so the progress bar leads the dim into /
  // out of view, and tightened in lockstep so big tables don't
  // sit watching a slow strip of motion above static cells.
  const progressDurationMs = Math.round(180 + rowAnimScale * 180);

  const [selected, setSelected] = useState<Set<string | number>>(new Set());
  // Rebuild the selection so it only ever contains keys that exist on the
  // current page (e.g. a row was deleted by another tab).
  useEffect(() => {
    setSelected((prev) => {
      if (prev.size === 0) return prev;
      const visible = new Set<string | number>(rows.map(idOf));
      let changed = false;
      const next = new Set<string | number>();
      for (const k of prev) {
        if (visible.has(k)) next.add(k);
        else changed = true;
      }
      return changed ? next : prev;
    });
  }, [rows, idOf]);
  // Clear selection whenever the user paginates, sorts, or applies a new
  // filter — bulk actions should only target rows the user can see right
  // now.
  useEffect(() => {
    setSelected(new Set());
  }, [page, pageSize, sortField, sortDir, appliedFilters]);
  // Arm the `paginating` flag the moment the user paginates / sorts /
  // changes a filter. We don't clear `rows` here on purpose — clearing
  // would collapse the table card from "25 visible rows" down to the
  // bare empty-state placeholder height, which reads as a sudden
  // layout snap. Instead, the existing rows stay mounted (so the
  // card keeps its current height) but get faded to opacity 0 via
  // the gate on the desktop TableBody / mobile row-cards Stack
  // below — the column headers and mobile toolbar above them stay
  // fully visible. When the new data lands, `reload`'s
  // `setRows(reconcileRows(...))` swaps the entries in place and
  // `setPaginating(false)` lets the body fade back to opacity 1, so
  // the new rows appear to cross-fade into the slot the old ones
  // were occupying. The empty-state placeholder stays hidden for
  // the same window so "No data yet" doesn't flash mid-roundtrip.
  //
  // Skipped on the very first run (initial mount) — `rows` is already
  // `[]` and we haven't even fetched anything, so there's nothing to
  // hide and nothing to gate against. Without this guard the initial
  // empty-state placeholder would briefly arm `paginating` for the
  // duration of the first reload, keeping the "No data yet" copy
  // hidden longer than necessary on cold mounts that legitimately
  // resolve to an empty list.
  const dataDepsFirstRunRef = useRef(true);
  useEffect(() => {
    if (dataDepsFirstRunRef.current) {
      dataDepsFirstRunRef.current = false;
      return;
    }
    setPaginating(true);
  }, [page, pageSize, sortField, sortDir, appliedFilters]);

  const allSelected = rows.length > 0 && selected.size === rows.length;
  const someSelected = selected.size > 0 && !allSelected;
  const toggleAll = () => {
    setSelected(allSelected ? new Set() : new Set(rows.map(idOf)));
  };
  const toggleRow = useCallback(
    (row: TEntity) => {
      const id = idOf(row);
      setSelected((prev) => {
        const next = new Set(prev);
        if (next.has(id)) next.delete(id);
        else next.add(id);
        return next;
      });
    },
    [idOf],
  );

  const handleBulkDelete = () => {
    if (selected.size === 0) return;
    setPendingDelete({ kind: "bulk", ids: Array.from(selected) });
  };

  return (
    // Desktop (md+): flex column that fills the page-content slot
    // exactly, so the table card below can `flex: 1` and stay inside
    // the viewport regardless of how many rows / how tall a filter
    // panel is open. Mobile: default block layout — the page
    // continues to scroll naturally on phones, where a "fit to
    // viewport" table card would just feel cramped.
    <Box
      sx={{
        display: { md: "flex" },
        flexDirection: { md: "column" },
        flex: { md: 1 },
        minHeight: { md: 0 },
      }}
    >
      <PageHeader
        title={config.title}
        subtitle={config.subtitle}
        icon={config.icon}
        actions={
          // `flexWrap: "wrap"` lets the toolbar fold onto a second row
          // on very narrow phones (≤ 360 px) where Filters + Refresh +
          // New together don't fit on a single line. Stack's default
          // `spacing` doesn't apply across wrapped lines, so we add an
          // explicit `rowGap` to keep wrapped buttons from touching.
          <Stack
            direction="row"
            // Spacing + size match the topbar in Layout.tsx so the
            // page-level toolbar reads as a continuation of the
            // global header chrome: 1.5 (= 12 px) between buttons,
            // 40 × 40 footprint per button, `borderRadius: 2`,
            // `fontSize="small"` icons inside.
            spacing={1.5}
            alignItems="center"
            sx={{ flexWrap: "wrap", rowGap: 1 }}
          >
            {hasCustomColumnWidths && (
              <Tooltip title="Reset column widths">
                <IconButton
                  onClick={resetColumnWidths}
                  size="medium"
                  aria-label="Reset column widths"
                  sx={{
                    width: 40,
                    height: 40,
                    borderRadius: 2,
                    color: "text.primary",
                    // Same hover-gating as the Refresh sibling: only paint
                    // the hover tint on real hover-capable pointers at
                    // desktop widths so a tap on touch / DevTools mobile
                    // emulation doesn't leave the tint stuck on.
                    "@media (hover: hover) and (min-width: 600px)": {
                      "&:hover": { backgroundColor: "action.hover" },
                    },
                  }}
                >
                  <RestartAltIcon fontSize="small" />
                </IconButton>
              </Tooltip>
            )}
            <Tooltip title="Refresh">
              <span>
                <IconButton
                  onClick={() => {
                    setRefreshSpinning(true);
                    void reload();
                  }}
                  size="medium"
                  sx={{
                    width: 40,
                    height: 40,
                    borderRadius: 2,
                    color: "text.primary",
                    // Mobile browsers leave `:hover` stuck on the
                    // last-tapped button until the user taps elsewhere,
                    // which paints a hover tint around Refresh after
                    // every tap. Gate the hover rule on a real
                    // hover-capable pointer AND a desktop-width
                    // viewport so the tint doesn't fire either on real
                    // touch devices or in Chrome DevTools' mobile
                    // emulation mode (which keeps `(hover: hover)`
                    // true because the host machine still has a
                    // mouse, but matches the narrow viewport of a
                    // phone). 599.95 px is the upper edge of MUI's
                    // `xs` breakpoint.
                    "@media (hover: hover) and (min-width: 600px)": {
                      "&:hover": { backgroundColor: "action.hover" },
                    },
                  }}
                >
                  <RefreshIcon
                    fontSize="small"
                    onAnimationIteration={() => {
                      if (!loading) setRefreshSpinning(false);
                    }}
                    sx={{
                      animation: refreshSpinning
                        ? "sb-refresh-spin 0.35s linear infinite"
                        : "none",
                      "@keyframes sb-refresh-spin": {
                        from: { transform: "rotate(0deg)" },
                        to: { transform: "rotate(360deg)" },
                      },
                    }}
                  />
                </IconButton>
              </span>
            </Tooltip>
            {filterSpecs.length > 0 && (
              <Tooltip
                title={
                  activeFilterCount > 0
                    ? `Filters · ${activeFilterCount} active`
                    : "Filters"
                }
              >
                {/* Filters trigger collapsed to an icon-only button.
                    The active-count is rendered as a small Badge dot
                    in the top-right corner so the user still gets a
                    visual cue when filters are applied without the
                    "Filters" word taking up toolbar space. */}
                <Badge
                  color="primary"
                  badgeContent={activeFilterCount}
                  invisible={activeFilterCount === 0}
                  overlap="circular"
                  sx={{
                    "& .MuiBadge-badge": {
                      height: 16,
                      minWidth: 16,
                      fontSize: 10,
                      fontWeight: 700,
                      padding: "0 4px",
                    },
                  }}
                >
                  <IconButton
                    onClick={() => setShowFilters((s) => !s)}
                    size="medium"
                    aria-label="Filters"
                    sx={{
                      width: 40,
                      height: 40,
                      borderRadius: 2,
                      // When the panel is open OR there's an active
                      // filter, paint the button in accent so it
                      // reads as "engaged"; otherwise it sits
                      // alongside Refresh as a quiet toolbar action.
                      color:
                        showFilters || activeFilterCount > 0
                          ? "var(--sb-accent)"
                          : "text.primary",
                      // Desktop split: 12 % accent at rest, 20 % under
                      // a real hover (handled in the desktop branch
                      // below). The mobile branch promotes the
                      // engaged tint straight to 20 % so it doesn't
                      // depend on a hover state the user can't reach.
                      bgcolor:
                        showFilters || activeFilterCount > 0
                          ? "color-mix(in srgb, var(--sb-accent) 12%, transparent)"
                          : "transparent",
                      // "Mobile version" branch — matches both real
                      // touch devices (`(hover: none)`) AND Chrome
                      // DevTools' mobile-emulation mode (which keeps
                      // `(hover: hover)` true because the host
                      // machine still has a mouse, but does shrink
                      // the viewport). 599.95 px is the upper edge
                      // of MUI's `xs` breakpoint, so this catches
                      // every "phone-shaped" layout regardless of
                      // input type.
                      //
                      // On the phone breakpoint we deliberately drop
                      // the accent-tinted engaged-state background
                      // entirely — that backdrop was what the user
                      // perceived as a halo "appearing on reload"
                      // (since `usePersistedFiltersOpen` rehydrates
                      // `showFilters: true` from localStorage on
                      // remount, the engaged tint would render in
                      // the very first frame after a refresh, with
                      // no tap to attribute it to). The Badge in
                      // the upper-right corner already carries the
                      // active-filter count, and the icon glyph
                      // recolours to `var(--sb-accent)` for the
                      // engaged state, so the indication isn't
                      // lost — it just stops painting a filled
                      // background. `transition: color` (no
                      // background-color) keeps the icon recolour
                      // smooth without ever needing to animate a
                      // backdrop that no longer exists.
                      "@media (hover: none), (max-width: 599.95px)": {
                        bgcolor: "transparent",
                        transition: "color 0.14s ease",
                      },
                      // Desktop branch — only fires when the user
                      // genuinely has a hover-capable pointer AND
                      // the layout is wide enough to read as
                      // "desktop". Touch devices and the DevTools
                      // mobile preset are both excluded so a tap
                      // there doesn't leave the 20 %-tint hover
                      // background stuck on the button (which is
                      // the original "halo remains after tap" bug).
                      "@media (hover: hover) and (min-width: 600px)": {
                        "&:hover": {
                          backgroundColor:
                            showFilters || activeFilterCount > 0
                              ? "color-mix(in srgb, var(--sb-accent) 20%, transparent)"
                              : "action.hover",
                        },
                      },
                    }}
                  >
                    <FilterAltIcon fontSize="small" />
                  </IconButton>
                </Badge>
              </Tooltip>
            )}
            {/* The "create" pill is intentionally smaller (32 × 32)
                than the neutral Refresh / Filters siblings, but it's
                wrapped in a 40 × 40 layout slot so the lower toolbar
                stays exactly the same total width as the upper bar's
                3-button row (each is 3 × 40 px + 2 × 12 px gap =
                144 px). Without this slot the lower toolbar would
                end 8 px earlier and the right edges of the two bars
                wouldn't line up. */}
            <Box
              sx={{
                width: 40,
                height: 40,
                display: "grid",
                placeItems: "center",
              }}
            >
              <Tooltip
                title={`New ${config.title.slice(0, -1).toLowerCase()}`}
              >
                <IconButton
                  onClick={openCreate}
                  size="small"
                  aria-label="Create new"
                  sx={{
                    width: 32,
                    height: 32,
                    // Tighter corner radius on the primary "create"
                    // action so it reads as a distinctly different
                    // control next to the more rounded Refresh /
                    // Filters siblings.
                    borderRadius: 1,
                    color: "var(--sb-accent-contrast, #ffffff)",
                    bgcolor: "var(--sb-accent)",
                    "&:hover": {
                      backgroundColor:
                        "color-mix(in srgb, var(--sb-accent) 88%, transparent)",
                    },
                  }}
                >
                  <AddIcon fontSize="small" />
                </IconButton>
              </Tooltip>
            </Box>
          </Stack>
        }
      />
      {filterSpecs.length > 0 && (
        // `flexShrink: 0` keeps the desktop flex column from squeezing
        // the Collapse below the height it just measured for its own
        // open animation. Without it, when this CrudPage mounts on a
        // page where filters were persisted as open, the freshly
        // re-rendered Collapse and the `flex: 1` Paper sibling would
        // briefly compete for the same vertical pixels — the flex
        // algorithm shrinks the Collapse on the same frame MUI is
        // tweening its height up, the CSS `transitionend` never
        // matches the ever-moving target, and the panel snaps open
        // without animation. Forcing `flex-shrink: 0` lets the
        // Collapse own its full natural height for the duration of
        // its own transition; the Paper's `flex: 1` minus its
        // `minHeight: 0` already lets it shrink to make room.
        <Collapse
          in={showFilters}
          unmountOnExit
          timeout={180}
          // Lift the first-paint gate once the panel has finished
          // animating open — this is what makes the table wait until
          // the filter panel is fully visible before it loads rows
          // when the user navigates between admin pages with
          // persisted-open filters. After the gate has lifted once
          // it stays lifted; later open/close toggles by the user
          // re-fire `onEntered` but the setter is a no-op when
          // already true.
          onEntered={() => setFiltersFirstPaintReady(true)}
          sx={{ flexShrink: 0 }}
        >
          {/* Pressing Enter anywhere inside the filter panel submits the
              current draft — same as clicking Search. Avoids a full <form>
              wrapper which would conflict with the table form-less buttons. */}
          <Box
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                applyFilters();
              }
            }}
            sx={{
              mb: 2,
              p: 2,
              pl: 2.25,
              borderRadius: 2.5,
              border: "1px solid",
              borderColor: "divider",
              // Custom request: dedicated surfaces per theme so the filter
              // panel reads as a distinct slab — `#f5f7fa` on light,
              // `#191919` on dark.
              bgcolor: (t) => (t.palette.mode === "light" ? "#f5f7fa" : "#191919"),
              display: "flex",
              flexDirection: "column",
              gap: 1.5,
              position: "relative",
              overflow: "hidden",
              // Subtle accent bar on the left edge — visually couples the
              // panel to the toolbar's "Filters" button without shouting.
              "&::before": {
                content: '""',
                position: "absolute",
                top: 12,
                bottom: 12,
                left: 0,
                width: 2,
                borderRadius: 2,
                bgcolor: "primary.main",
                opacity: 0.6,
              },
            }}
          >
            <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 0.5 }}>
              <Box
                sx={{
                  width: 22,
                  height: 22,
                  borderRadius: 1,
                  display: "grid",
                  placeItems: "center",
                  bgcolor: "action.selected",
                  color: "text.secondary",
                }}
              >
                <FilterAltIcon sx={{ fontSize: 14 }} />
              </Box>
              <Typography
                variant="subtitle2"
                color="text.primary"
                sx={{ fontWeight: 600, letterSpacing: 0.2 }}
              >
                Filters
              </Typography>
              {activeFilterCount > 0 && (
                <Chip
                  size="small"
                  color="primary"
                  label={`${activeFilterCount} active`}
                  sx={{ height: 20, fontSize: 11 }}
                />
              )}
              <Box sx={{ flexGrow: 1 }} />
              <Button
                size="small"
                color="inherit"
                startIcon={<FilterAltOffIcon fontSize="small" />}
                disabled={activeFilterCount === 0 && draftFilterCount === 0}
                onClick={resetFilters}
                sx={{ textTransform: "none" }}
              >
                Clear
              </Button>
              <Button
                size="small"
                variant="contained"
                color="primary"
                startIcon={<SearchIcon fontSize="small" />}
                onClick={applyFilters}
                disabled={!filtersDirty}
              >
                Search
              </Button>
            </Stack>
            {/* Each filter has a fixed width — datetime-range cells (which
                pack two pickers side by side) and any cell explicitly
                marked `wide: true` get 1.5× the slot — and the row simply
                flex-wraps when there isn't enough horizontal space, so the
                number of filters per row adapts to the viewport without
                forcing every cell to share the same fractional column. */}
            <Box
              sx={{
                display: "flex",
                flexWrap: "wrap",
                gap: `${FILTER_GAP}px`,
              }}
            >
              {filterSpecs.map((f) => (
                <Box
                  key={f.name}
                  sx={{
                    // On mobile (< 900 px) every filter cell takes the
                    // full row — the fixed 240 / 372 px slot layout from
                    // desktop squeezes two half-height inputs into
                    // viewports too narrow to comfortably use them,
                    // especially `datetime-range` which packs two
                    // pickers side-by-side.
                    width: {
                      xs: "100%",
                      md:
                        f.type === "datetime-range" || f.wide
                          ? WIDE_FILTER_WIDTH
                          : FILTER_WIDTH,
                    },
                    flexShrink: 0,
                  }}
                >
                  <FilterField
                    spec={f}
                    value={filterValues[f.name]}
                    onChange={(v) => setFilterValue(f.name, v)}
                  />
                </Box>
              ))}
            </Box>
          </Box>
        </Collapse>
      )}
      <Paper
        ref={tableRef}
        variant="outlined"
        sx={(t) => ({
          overflow: "hidden",
          position: "relative",
          // Desktop: claim the leftover vertical space below the
          // PageHeader / filter panel and lay the inner pieces
          // (progress bar, TableContainer, TablePagination) out as a
          // flex column so the *rows* are the only part that scrolls.
          // The card stays pinned inside the browser window — no
          // page-level scroll — regardless of row count or page size.
          display: { md: "flex" },
          flexDirection: { md: "column" },
          flex: { md: 1 },
          minHeight: { md: 0 },
          // Soft drop shadow gives the table some depth without making
          // the rest of the layout look heavy. Tuned per mode so the
          // shadow stays visible on white as well as on dark.
          boxShadow:
            t.palette.mode === "light"
              ? "0 1px 0 rgba(15,23,42,0.04), 0 8px 22px rgba(15,23,42,0.10)"
              : "0 1px 0 rgba(255,255,255,0.02), 0 12px 28px rgba(0,0,0,0.28)",
        })}
      >
        {/* Thin top progress bar visible during any load (initial or reload).
            Gated on `loadingVisible` (loading + ~180 ms) for *refreshes* so
            fast roundtrips don't flash a strip of motion at all, but the
            very first load bypasses that lag (`!hasFetched`) — the user
            sees the progress bar the moment the table mounts, sitting
            on top of the empty-state placeholder we now reserve. */}
        <Box
          sx={{
            position: "absolute",
            top: 0,
            left: 0,
            right: 0,
            height: 2,
            zIndex: 2,
            // Initial load: `!hasFetched` makes the bar appear instantly so
            // the empty placeholder doesn't sit silent while the first
            // request is in flight.
            //
            // Reloads: gated on the lagging `loadingVisible` so a refresh
            // that finishes inside the ~180 ms threshold never flashes a
            // strip of motion. (We no longer additionally gate on
            // `rows.length > 0`; clicking Refresh on an empty list now
            // also shows the bar, which is the expected feedback for a
            // user-initiated action.)
            //
            // Gating on `loading` (in addition to the lagging
            // `loadingVisible`) so the bar disappears the moment the
            // fetch finishes — without it, the post-fetch render would
            // briefly keep the bar visible while `loadingVisible` waits
            // for its useEffect to flip it off, which read as a "double
            // render" flicker right when the rows appeared.
            opacity: loading && (loadingVisible || !hasFetched) ? 1 : 0,
            transition: `opacity ${progressDurationMs}ms cubic-bezier(0.45, 0, 0.55, 1)`,
            pointerEvents: "none",
          }}
        >
          <LinearProgress sx={{ height: 2 }} />
        </Box>
        {/* Bulk-action toolbar: appears as a thin top strip on the table
            card whenever at least one row is selected. Replaces the per-
            row delete button for batch operations and gives the user a
            one-click way to clear the selection. Rendered as a sibling
            *above* the scrolling TableContainer (rather than inside it)
            so the strip stays visible while the user scrolls the rows
            vertically — otherwise it would scroll out of the viewport
            together with the body and the user would lose the bulk-
            action affordance the moment they paged past the first
            screenful of selected rows. */}
        <Collapse in={selected.size > 0} unmountOnExit>
          <Stack
            direction="row"
            alignItems="center"
            spacing={1.5}
            sx={{
              px: 2,
              py: 1,
              borderBottom: "1px solid",
              borderColor: "divider",
              // Neutral tint — keeps the table chrome from flashing the
              // accent color when the user toggles a checkbox.
              bgcolor: "action.hover",
            }}
          >
            <Typography variant="body2" sx={{ fontWeight: 600 }}>
              {selected.size} selected
            </Typography>
            <Box sx={{ flexGrow: 1 }} />
            <Button
              size="small"
              color="inherit"
              onClick={() => setSelected(new Set())}
              disabled={deleteBusy}
              sx={{ textTransform: "none" }}
            >
              Clear
            </Button>
            <Button
              size="small"
              variant="contained"
              color="error"
              startIcon={<DeleteIcon fontSize="small" />}
              onClick={handleBulkDelete}
              disabled={deleteBusy}
            >
              Delete selected
            </Button>
          </Stack>
        </Collapse>
        <TableContainer
          ref={scrollContainerRef}
          sx={{
            // Desktop: take the leftover vertical space inside the
            // Paper card and scroll the rows internally — the
            // pagination bar at the bottom of the card stays pinned
            // to the bottom of the viewport instead of sitting below
            // the fold. `minHeight: 0` is required for the
            // flex-fill child to be allowed to shrink below its
            // intrinsic content height. MUI's TableContainer ships
            // with `overflow-x: auto` only; we add `overflow-y:
            // auto` here so the Y-axis scroll lives inside the
            // card too.
            flex: { md: 1 },
            minHeight: { md: 0 },
            overflowY: { md: "auto" },
            // Soft dim while a reload is in flight (only when there's
            // existing data to dim — first load stays at full opacity).
            // Gated on `loadingVisible` rather than `loading` so a
            // refresh that finishes inside the ~180 ms threshold never
            // visibly dims the table at all (no flash on fast networks).
            //
            // Resting dim of 0.78 is a gentle attenuation — the table
            // content stays clearly legible mid-reload while still
            // reading as "stale". The transition duration scales
            // with the number of currently-visible rows (`rowAnimScale`
            // above): a 1-row table dims/un-dims in ~220 ms (snappy,
            // because the table is small and the eye absorbs the
            // change instantly), a 50+ row table dims/un-dims in
            // ~700 ms (graceful, because a wall of cells benefits
            // from a longer breath). The symmetric S-curve makes the
            // change read as a deliberate "pulled" veil at every
            // size rather than a sudden flash.
            // `loadingVisible` is delayed by ~180 ms after `loading`
            // flips on, but it's also delayed by one render *off* —
            // setLoadingVisible(false) only runs in the cleanup effect
            // after `loading` flips to false. Without the extra
            // `loading &&` gate the post-fetch render would dim the
            // freshly-mounted rows for one frame before the effect
            // fired, which read as a "double render" flicker. With
            // the gate, the dim disappears the moment the fetch
            // resolves regardless of `loadingVisible`'s lag.
            opacity: loading && loadingVisible && rows.length > 0 ? 0.78 : 1,
            transition: `opacity ${dimDurationMs}ms cubic-bezier(0.45, 0, 0.55, 1)`,
            // `pointerEvents` follows the same delayed signal so a
            // sub-180 ms refresh never briefly disables hovers / clicks
            // (which used to surface as a tiny "dead zone" over the
            // table for the duration of a fast roundtrip).
            pointerEvents: loading && loadingVisible ? "none" : "auto",
          }}
        >
          {isMobile ? (
            <Box sx={{ p: 1.5 }}>
              {rows.length === 0 ? (
                // Mirror of the desktop empty state, just outside any
                // table cell so we can drop the colSpan plumbing.
                //
                // Rendered immediately on mount so the card reserves
                // the same vertical space the empty-state CTA will
                // eventually occupy. While the very first reload is
                // still in flight (`!hasFetched`) the stack is kept
                // invisible — the user doesn't see the "No data yet"
                // copy or the Create button flash before we know
                // whether the API actually has rows for them.
                <Stack
                  alignItems="center"
                  spacing={1.5}
                  sx={{
                    py: 6,
                    // Fade in once the first reload finishes — we keep the
                    // stack mounted from the start so the card reserves
                    // its full height, but cross-fade the contents in
                    // gently instead of snapping from `visibility:
                    // hidden` to `visible`. `pointerEvents` follow the
                    // same gate so the (visually invisible) Create
                    // button never receives stray taps before the
                    // empty-state has actually been confirmed.
                    //
                    // The `!paginating` clause keeps the placeholder
                    // hidden while the user's pagination / sort /
                    // filter change is in flight: in the common case
                    // the previous rows are still mounted (faded to
                    // opacity 0 by the inner row-cards Stack down
                    // below) and rows.length is non-zero, so this
                    // branch isn't even rendered. The gate matters
                    // for the case where the previous page was
                    // already empty AND the user paginates / changes
                    // a filter — then this branch IS rendered but
                    // should stay hidden during the round-trip, not
                    // flash "No data yet" mid-fetch.
                    opacity: hasFetched && !paginating ? 1 : 0,
                    transition:
                      "opacity 320ms cubic-bezier(0.22, 0.61, 0.36, 1)",
                    pointerEvents:
                      hasFetched && !paginating ? "auto" : "none",
                  }}
                >
                  <Box
                    sx={{
                      width: 56,
                      height: 56,
                      borderRadius: 2.5,
                      display: "grid",
                      placeItems: "center",
                      color: "text.secondary",
                      bgcolor: "action.hover",
                      border: "1px solid",
                      borderColor: "divider",
                    }}
                  >
                    <InboxRoundedIcon />
                  </Box>
                  <Box sx={{ color: "text.secondary", fontSize: 13 }}>
                    No data yet
                  </Box>
                  <Button
                    variant="contained"
                    color="primary"
                    size="small"
                    startIcon={<AddIcon />}
                    onClick={openCreate}
                  >
                    Create the first one
                  </Button>
                </Stack>
              ) : (
                <Stack spacing={1.25}>
                  {/* Mobile toolbar that replaces the desktop table's
                      header row: the select-all checkbox sits on the
                      left, and a compact "sort by + direction"
                      control sits on the right. The Stack uses
                      `flexWrap: wrap` so on very narrow phones the
                      sort group can drop onto its own line instead
                      of pushing into the checkbox. */}
                  {rows.length > 0 && (
                    <Stack
                      direction="row"
                      alignItems="center"
                      spacing={1}
                      sx={{
                        pl: 0.5,
                        pb: 0.5,
                        flexWrap: "wrap",
                        rowGap: 1,
                      }}
                    >
                      <Stack
                        direction="row"
                        alignItems="center"
                        spacing={0.5}
                        sx={{ color: "text.secondary", fontSize: 12.5 }}
                      >
                        <Checkbox
                          size="small"
                          color="primary"
                          indeterminate={someSelected}
                          checked={allSelected}
                          onChange={toggleAll}
                          inputProps={{ "aria-label": "select all rows" }}
                        />
                        <Box>Select all</Box>
                      </Stack>
                      <Box sx={{ flexGrow: 1 }} />
                      <Stack
                        direction="row"
                        alignItems="center"
                        spacing={0.5}
                      >
                        <TextField
                          select
                          size="small"
                          // displayEmpty + a value="" MenuItem lets us
                          // render "No sort" when the user hasn't
                          // picked a sort column. Without it the
                          // empty string would render as a blank
                          // field with no label.
                          SelectProps={{ displayEmpty: true }}
                          value={sortField ?? ""}
                          onChange={(e) => {
                            const v = e.target.value;
                            if (v === "") {
                              setSortField(null);
                              setSortDir("asc");
                            } else if (v !== sortField) {
                              setSortField(v);
                              // Default to ascending whenever the
                              // user picks a new column. The arrow
                              // button next to the field flips the
                              // direction without re-opening the
                              // menu.
                              setSortDir("asc");
                            }
                            setPage(0);
                          }}
                          aria-label="Sort by"
                          sx={{
                            minWidth: 132,
                            "& .MuiSelect-select": {
                              py: 0.5,
                              fontSize: 13,
                            },
                          }}
                        >
                          <MenuItem
                            value=""
                            sx={{
                              fontStyle: "italic",
                              color: "text.secondary",
                            }}
                          >
                            No sort
                          </MenuItem>
                          {sortableColumns.map((c) => (
                            <MenuItem
                              key={String(c.key)}
                              value={String(c.key)}
                            >
                              {c.label}
                            </MenuItem>
                          ))}
                        </TextField>
                        <Tooltip
                          title={
                            sortDir === "asc"
                              ? "Ascending — tap to flip"
                              : "Descending — tap to flip"
                          }
                        >
                          <span>
                            <IconButton
                              size="small"
                              disabled={!sortField}
                              onClick={() =>
                                setSortDir((d) =>
                                  d === "asc" ? "desc" : "asc",
                                )
                              }
                              aria-label="Toggle sort direction"
                              sx={{
                                width: 32,
                                height: 32,
                                color: "text.secondary",
                                "&:hover": { color: "var(--sb-accent)" },
                              }}
                            >
                              {sortDir === "asc" ? (
                                <ArrowUpwardIcon fontSize="small" />
                              ) : (
                                <ArrowDownwardIcon fontSize="small" />
                              )}
                            </IconButton>
                          </span>
                        </Tooltip>
                      </Stack>
                    </Stack>
                  )}
                  {/* Just the row cards live inside this inner Stack
                      so the `paginating` opacity gate hides the data
                      cards alone — the select-all + sort toolbar
                      above (this branch's mobile equivalent of the
                      desktop column headers) stays fully visible
                      during the in-flight request. The inner
                      `spacing={1.25}` matches the outer Stack's
                      spacing so the visible gap between toolbar and
                      first card is unchanged. Cards stay mounted
                      during the fade so the table card height
                      doesn't snap. */}
                  <Stack
                    spacing={1.25}
                    sx={{
                      opacity: paginating ? 0 : 1,
                      transition:
                        "opacity 320ms cubic-bezier(0.45, 0, 0.55, 1)",
                      pointerEvents: paginating ? "none" : "auto",
                    }}
                  >
                    {rows.map((row, i) => {
                      const key = config.rowKey
                        ? config.rowKey(row)
                        : String(row[config.idKey]);
                      return (
                        <CrudCard
                          key={key}
                          rowKey={key}
                          row={row}
                          index={i}
                          columns={columnsRef}
                          selected={selected.has(idOf(row))}
                          onToggle={toggleRow}
                          onEdit={handleEdit}
                          onDelete={handleDelete}
                          rowActions={config.rowActions}
                          onRunAction={handleRunAction}
                        />
                      );
                    })}
                  </Stack>
                </Stack>
              )}
            </Box>
          ) : (
          <Table
            size="small"
            // `stickyHeader` keeps the column titles (and the pinned
            // Actions header on the right) visible while the body rows
            // scroll vertically inside the TableContainer — required
            // now that the desktop layout claims a fixed viewport
            // height and scrolls the rows internally rather than
            // letting the page itself scroll. Combines with the
            // existing `ACTIONS_HEADER_CELL_SX` (which already pins
            // the Actions header to the right) to make that one cell
            // sticky on both axes simultaneously.
            stickyHeader
            // Excel-style resizing requires `tableLayout: fixed` so the
            // explicit pixel widths set on the header cells are honoured
            // strictly (otherwise the browser would still grow columns to
            // fit content). Cells without an explicit width fall back to
            // the auto-distributed remainder.
            //
            // `minWidth: tableMinWidth` keeps the table from being
            // squeezed below the sum of column widths — without it, a
            // user-resized column would visually overlap its neighbours
            // when their total exceeded the container's width.
            sx={{ tableLayout: "fixed", minWidth: tableMinWidth }}
          >
            <TableHead>
              <TableRow>
                <TableCell
                  sx={{
                    // Plain cell (no `padding="checkbox"`) so MUI's
                    // hardcoded `width: 48px` and tight 4 px padding don't
                    // collide with the resizable-column layout. Centered
                    // contents keep the Checkbox visually balanced inside
                    // the column regardless of the chosen width.
                    width: 72,
                    paddingLeft: 0,
                    paddingRight: 0,
                    textAlign: "center",
                    overflow: "visible",
                  }}
                >
                  <Checkbox
                    size="small"
                    color="primary"
                    indeterminate={someSelected}
                    checked={allSelected}
                    onChange={toggleAll}
                    disabled={rows.length === 0}
                    inputProps={{ "aria-label": "select all rows" }}
                  />
                </TableCell>
                {config.columns.map((c, idx) => {
                  const sortable = c.sortable ?? true;
                  // The last data column has no resize handle at all.
                  // Its right edge is the boundary with the trailing
                  // filler cell, so dragging it would be perceived as
                  // "resizing the spacer" — every adjustment to this
                  // column would have to come out of the filler's
                  // budget. Skipping the handle keeps that boundary
                  // visually inert; the column's width is governed
                  // solely by `effectiveWidth` (default + natural
                  // minimum), and the filler absorbs whatever space
                  // is left over.
                  const isLastDataColumn = idx === config.columns.length - 1;
                  const key = String(c.key);
                  const isActive = sortable && sortField === key;
                  const stored = columnWidths[key];
                  // Effective width = whatever the user stored, but never
                  // narrower than the measured natural minimum. This is
                  // what stops a previously-resized cell (or a fresh
                  // localStorage value from before the per-column min was
                  // enforced) from rendering smaller than its header
                  // content — without it, the label would visually spill
                  // into the neighbouring column.
                  //
                  // For unstored columns we still assign an explicit
                  // pixel width (DEFAULT_DATA_COL_WIDTH, or a measured
                  // natural minimum if it's larger). With every data
                  // column carrying an explicit width, the only
                  // auto-sized cell in the row is the trailing
                  // <td> filler — which is what stops `tableLayout:
                  // fixed` from rubber-banding the unstored neighbours
                  // when the user resizes one column. The filler
                  // soaks up all the leftover horizontal space, and
                  // shrinks to 0 when the column sum exceeds the
                  // viewport so the table can overflow horizontally.
                  const naturalMin = columnNaturalMins[key];
                  const effectiveWidth =
                    stored != null
                      ? naturalMin != null
                        ? Math.max(stored, naturalMin)
                        : stored
                      : Math.max(naturalMin ?? 0, DEFAULT_DATA_COL_WIDTH);
                  return (
                    <TableCell
                      key={key}
                      ref={(el: HTMLTableCellElement | null) => {
                        headerCellRefs.current[key] = el;
                      }}
                      sortDirection={isActive ? sortDir : false}
                      sx={{
                        // `position: sticky` (instead of the previous
                        // `relative`) is required so the data-column
                        // header tracks `stickyHeader`'s `top: 0` and
                        // stays glued to the top edge while the body
                        // rows scroll vertically. Without this override,
                        // MUI's `stickyHeader` rule would lose against
                        // the cell's own sx — and only the cells that
                        // happen to lack an explicit `position`
                        // (checkbox, filler, Actions) would end up
                        // sticky, which read as "three random columns
                        // glued to the top" while the rest of the
                        // header scrolled away with the rows.
                        //
                        // Sticky positioning also creates a containing
                        // block for the absolute-positioned
                        // `ResizeHandle` child, exactly the way the
                        // previous `relative` did, so the resize-grip
                        // geometry below is unaffected.
                        position: "sticky",
                        top: 0,
                        // Match the explicit Actions header bg so a
                        // body row scrolling under the sticky data
                        // headers doesn't show through. The theme's
                        // `MuiTableCell.head` rule already paints
                        // `--sb-elevated` here, but listing it
                        // explicitly keeps this cell's sticky
                        // background self-contained against any
                        // future theme override.
                        backgroundColor: "var(--sb-elevated)",
                        width: `${effectiveWidth}px`,
                        // Long header / cell content was overflowing the
                        // user's chosen column width — clip with ellipsis
                        // so the resize stays predictable.
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {/* Inline-flex measurement wrapper — the inner span
                          sizes itself to its natural content (label +
                          sort caret) regardless of the cell's enforced
                          pixel width, so its `getBoundingClientRect()`
                          gives us the smallest cell size that wouldn't
                          spill into the next column. */}
                      <Box
                        component="span"
                        ref={(el: HTMLElement | null) => {
                          headerLabelRefs.current[key] = el;
                        }}
                        sx={{
                          // Crucial: do NOT cap this with `maxWidth: 100%`.
                          // The wrapper has to keep its natural content
                          // width even when the cell is constrained
                          // narrower — otherwise `getBoundingClientRect`
                          // would return the cell's clamped width and
                          // `naturalMin` would never grow large enough to
                          // prevent the column from being resized below
                          // its header content. Visually nothing changes:
                          // when the cell is wider than the content the
                          // wrapper just sits left-aligned, when narrower
                          // the cell's `overflow: hidden` clips the
                          // overflow exactly as before.
                          display: "inline-flex",
                          alignItems: "center",
                          whiteSpace: "nowrap",
                        }}
                      >
                        {sortable ? (
                          <TableSortLabel
                            active={isActive}
                            direction={isActive ? sortDir : "asc"}
                            onClick={() => handleSort(key)}
                            // Inactive sortable columns get a symmetric
                            // up-and-down chevron icon (`UnfoldMore`) so
                            // it reads as "this column can be sorted in
                            // either direction" without committing to a
                            // default arrow. Once a direction is picked
                            // the column becomes active and MUI's default
                            // `ArrowDownward` icon takes over (rotated to
                            // match `sortDir`).
                            IconComponent={
                              isActive ? undefined : UnfoldMoreIcon
                            }
                            sx={{
                              "& .MuiTableSortLabel-icon": {
                                opacity: isActive ? 1 : 0.45,
                                // The inactive icon is symmetric, so
                                // MUI's direction-based rotation is
                                // meaningless for it — pin it at 0deg so
                                // the visual never drifts when MUI flips
                                // the rotation class on hover / mount.
                                transform: isActive
                                  ? undefined
                                  : "none !important",
                                transition:
                                  "opacity 0.14s ease, transform 0.14s ease",
                              },
                              "&:hover .MuiTableSortLabel-icon": {
                                opacity: isActive ? 1 : 0.75,
                              },
                            }}
                          >
                            {c.label}
                          </TableSortLabel>
                        ) : (
                          c.label
                        )}
                      </Box>
                      {!isLastDataColumn && (
                        <ResizeHandle
                          columnKey={key}
                          getCurrentWidth={() => getColumnLiveWidth(key)}
                          setWidth={setColumnWidth}
                          getMinWidth={() => getColumnNaturalMin(key)}
                          getMaxWidth={() => getColumnMaxWidth(key)}
                          onResizeStart={lockInUnstoredColumnWidths}
                        />
                      )}
                    </TableCell>
                  );
                })}
                {/* Filler cell — the only auto-width cell in the row.
                    Under `tableLayout: fixed` it absorbs whatever
                    horizontal space is left over after the fixed-
                    width columns (checkbox + each data column +
                    Actions). When the user resizes a column the
                    filler shrinks/grows to compensate so the data
                    columns themselves stay pixel-stable. Once the
                    sum of the fixed columns exceeds the viewport
                    the filler collapses to 0 and the surrounding
                    `TableContainer` provides a horizontal scroll. */}
                <TableCell aria-hidden sx={FILLER_CELL_SX} />
                <TableCell
                  align="center"
                  sx={{
                    ...ACTIONS_HEADER_CELL_SX,
                    width: 92 + (config.rowActions?.length ?? 0) * 32,
                  }}
                >
                  Actions
                </TableCell>
              </TableRow>
            </TableHead>
            <TableBody
              sx={{
                // Fade just the row body to opacity 0 the moment the
                // user paginates / sorts / filters. The column
                // headers above (TableHead) stay fully visible so the
                // structure of the table remains legible during the
                // round-trip — only the data cells disappear. Rows
                // stay *mounted* (we never call `setRows([])` here)
                // so the table card keeps its current height; once
                // `reload` lands the new rows in `setRows` and flips
                // `paginating` back to false, the body fades back to
                // opacity 1, cross-fading the new entries into the
                // slot the old ones occupied.
                opacity: paginating ? 0 : 1,
                transition: `opacity ${dimDurationMs}ms cubic-bezier(0.45, 0, 0.55, 1)`,
                // Lock out interaction while the body is visually
                // gone — clicking an invisible row would be
                // surprising.
                pointerEvents: paginating ? "none" : "auto",
              }}
            >
              {rows.length === 0 && (
                // Empty-state row is rendered the moment the table mounts
                // so the card reserves the same vertical space the "No
                // data yet" stack will eventually occupy — no collapse-
                // to-header-only bounce, and no layout jump when the
                // first response lands.
                //
                // Before the first reload finishes (`!hasFetched`) the
                // inner stack is kept invisible: the cell still
                // contributes its full height to the row, but the user
                // doesn't see the icon / "No data yet" label / Create
                // button flash before we even know whether there's
                // data. Once `hasFetched` flips to true and `rows` is
                // still empty, the stack becomes visible and the user
                // gets the real empty-state CTA.
                <TableRow
                  // The global `MuiTableRow` override in theme.ts paints
                  // every row with an `${elevated2} !important` tint on
                  // `:hover` so data rows feel responsive to the cursor.
                  // The empty-state row isn't a data row — there's
                  // nothing to "select" — so that highlight reads as a
                  // misleading affordance: the user moves the mouse to
                  // click "Create the first one" and the entire band
                  // behind the icon / label / button lights up. Pin
                  // the hover background to transparent (also using
                  // `!important`, since the theme rule does) so the
                  // empty state sits on the plain table surface; the
                  // small `action.hover`-tinted icon tile below stays
                  // exactly as it was — only the surrounding row band
                  // stops reacting to hover.
                  sx={{
                    "&:hover": {
                      backgroundColor: "transparent !important",
                    },
                  }}
                >
                  <TableCell
                    // Spans every cell in the row: checkbox + each
                    // data column + the auto-width filler + Actions.
                    colSpan={config.columns.length + 3}
                    sx={{ py: 8, px: 0 }}
                  >
                    <Box
                      sx={{
                        position: "sticky",
                        left: 0,
                        width: tableViewportWidth ?? "100%",
                        display: "flex",
                        justifyContent: "center",
                      }}
                    >
                      <Stack
                        alignItems="center"
                        spacing={1.5}
                        sx={{
                          // Cross-fade the empty-state contents in once
                          // the first reload finishes; the stack itself
                          // stays mounted from initial render so the
                          // table card reserves its full height. Using
                          // `opacity` (instead of `visibility: hidden`
                          // → `visible`) gives a soft entrance that
                          // doesn't snap into place the moment the
                          // first response lands. `pointerEvents`
                          // follow the same gate so taps on the
                          // (transparent) Create button can't fire
                          // before the empty-state is confirmed.
                          //
                          // The `!paginating` clause keeps the
                          // placeholder hidden while a pagination /
                          // sort / filter request is in flight: in
                          // the common case the previous rows are
                          // still mounted (the surrounding TableBody
                          // is faded to opacity 0) and rows.length
                          // is non-zero so this branch isn't
                          // rendered. The gate matters for the case
                          // where the previous page was already
                          // empty AND the user paginates / changes a
                          // filter — then this branch IS rendered
                          // but should stay hidden during the round-
                          // trip, not flash "No data yet" mid-fetch.
                          opacity: hasFetched && !paginating ? 1 : 0,
                          transition:
                            "opacity 320ms cubic-bezier(0.22, 0.61, 0.36, 1)",
                          pointerEvents:
                            hasFetched && !paginating ? "auto" : "none",
                        }}
                      >
                        <Box
                          sx={{
                            width: 56,
                            height: 56,
                            borderRadius: 2.5,
                            display: "grid",
                            placeItems: "center",
                            color: "text.secondary",
                            bgcolor: "action.hover",
                            border: "1px solid",
                            borderColor: "divider",
                          }}
                        >
                          <InboxRoundedIcon />
                        </Box>
                        <Box sx={{ color: "text.secondary", fontSize: 13 }}>
                          No data yet
                        </Box>
                        <Button
                          variant="contained"
                          color="primary"
                          size="small"
                          startIcon={<AddIcon />}
                          onClick={openCreate}
                        >
                          Create the first one
                        </Button>
                      </Stack>
                    </Box>
                  </TableCell>
                </TableRow>
              )}
              {rows.map((row, i) => {
                const key = config.rowKey
                  ? config.rowKey(row)
                  : String(row[config.idKey]);
                return (
                  <CrudRow
                    key={key}
                    rowKey={key}
                    row={row}
                    index={i}
                    columns={columnsRef}
                    selected={selected.has(idOf(row))}
                    onToggle={toggleRow}
                    onEdit={handleEdit}
                    onDelete={handleDelete}
                    rowActions={config.rowActions}
                    onRunAction={handleRunAction}
                  />
                );
              })}
            </TableBody>
          </Table>
          )}
        </TableContainer>
        {config.count !== undefined && (
          // The pagination toolbar is rendered from the first paint
          // onwards so the Paper card has a stable total height
          // before the first `list()` + `count()` round-trip
          // resolves. Without that, the bottom edge of the card
          // (and everything below it on the page) visibly jerked
          // by ~48 px the moment the toolbar appeared, which read
          // as a twitch of the table's bottom bar.
          //
          // While we're still waiting on count, `total` is `null`
          // and `total ?? -1` falls through to -1; the
          // `labelDisplayedRows` fallback below converts that into
          // a stable "0–0 of 0" placeholder (same fallback also
          // covers the edge case where `count` errors out but
          // `list()` succeeded). Pre-fetch the toolbar's controls
          // are dimmed and pointer-events disabled so the user
          // can't accidentally change the page or page size before
          // we know what's there.
          <TablePagination
            component="div"
            count={total ?? -1}
            page={page}
            onPageChange={(_, p) => setPage(p)}
            rowsPerPage={pageSize}
            onRowsPerPageChange={(e) => {
              setPageSize(Number(e.target.value));
              setPage(0);
            }}
            rowsPerPageOptions={[10, 25, 50, 100]}
            // Custom range label. MUI's default formatter renders
            // "X–Y of more than Y" whenever `count` is negative —
            // which is what we pass on the *first* render of the
            // page (before /count has resolved, `total` is still
            // `null` and `total ?? -1` falls through to -1). The
            // resulting "of more than 0" / "of more than 25"
            // flashes for a frame on every page reload until the
            // count endpoint replies, which reads as a glitch.
            //
            // While we're waiting on the count we render a stable
            // "0–0 of 0" placeholder — same shape as the eventual
            // real label, so the toolbar's width / arrow positions
            // don't shift the moment the real number arrives. Once
            // the count has resolved, this is identical to MUI's
            // default formatter ("from–to of count") so the
            // user-visible UX is unchanged in the steady state.
            labelDisplayedRows={({ from, to, count }) =>
              count < 0 ? "0–0 of 0" : `${from}–${to} of ${count}`
            }
            sx={{
              borderTop: "1px solid",
              borderColor: "divider",
              ".MuiTablePagination-toolbar": { minHeight: 48 },
              // Tabular numerals — every digit advances the same
              // width regardless of glyph. Without this the
              // "X–Y of Z" range reflows as the user paginates
              // (e.g. "1–25 of 100" → "26–50 of 100": the "26"
              // is visibly wider than "1", which pushed the
              // chevron buttons sideways). The property is
              // inherited, so applying it on the root reaches the
              // displayed-rows label and the rows-per-page select
              // value together. Every other text in the toolbar
              // is non-numeric and is unaffected.
              fontVariantNumeric: "tabular-nums",
              // Pre-fetch: dim the toolbar and disable interaction
              // so the placeholder "0–0 of 0" doesn't read as a
              // working control. Cross-fades to full opacity once
              // the first reload finishes, in lockstep with the
              // empty-state CTA / data rows materialising above.
              opacity: hasFetched ? 1 : 0.55,
              pointerEvents: hasFetched ? "auto" : "none",
              transition:
                "opacity 320ms cubic-bezier(0.22, 0.61, 0.36, 1)",
            }}
          />
        )}
      </Paper>
      {/* Mount the dialog while EITHER `dialogOpen` is true OR the
          underlying creating/editing state still has content — that
          second clause keeps the component alive through the MUI leave
          transition (open=false → onExited fires → handleDialogExited
          clears the state → next render unmounts). Without it the
          dialog would yank itself out of the DOM the moment the user
          clicks Cancel and the close animation would never play. */}
      {(dialogOpen || creating || editing !== null) && (
        <CrudDialog
          open={dialogOpen}
          mode={creating ? "create" : "update"}
          fields={config.fields}
          initial={editing ? (config.fromEntity ? config.fromEntity(editing) : (editing as unknown as Record<string, unknown>)) : undefined}
          title={creating ? `New ${config.title.slice(0, -1)}` : `Edit ${config.title.slice(0, -1)}`}
          onClose={closeDialog}
          onExited={handleDialogExited}
          onSubmit={creating ? handleCreate : handleUpdate}
        />
      )}
      {/* Delete-confirmation dialog: replaces the previous browser-native
          window.confirm and serves both per-row and bulk deletes.
          Stays a compact pop-over on mobile too (it's tiny), no need for
          the full-screen treatment the form dialog gets. */}
      <Dialog
        open={pendingDelete !== null}
        onClose={() => {
          if (!deleteBusy) setPendingDelete(null);
        }}
        maxWidth="xs"
        fullWidth
      >
        <DialogTitle>
          {displayPendingDelete?.kind === "bulk"
            ? `Delete ${displayPendingDelete.ids.length} ${
                displayPendingDelete.ids.length === 1
                  ? config.title.slice(0, -1).toLowerCase()
                  : config.title.toLowerCase()
              }?`
            : `Delete ${config.title.slice(0, -1).toLowerCase()}?`}
        </DialogTitle>
        <DialogContent dividers>
          <Typography variant="body2" color="text.secondary">
            {displayPendingDelete?.kind === "bulk"
              ? `This will permanently remove ${displayPendingDelete.ids.length} ${
                  displayPendingDelete.ids.length === 1
                    ? config.title.slice(0, -1).toLowerCase()
                    : config.title.toLowerCase()
                } from the database. This action cannot be undone.`
              : `${
                  displayPendingDelete?.kind === "single" ? displayPendingDelete.label : ""
                } will be permanently removed from the database. This action cannot be undone.`}
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => setPendingDelete(null)}
            disabled={deleteBusy}
          >
            Cancel
          </Button>
          <Button
            variant="contained"
            color="error"
            startIcon={
              // Cross-fade the trash icon with a small spinner instead
              // of swapping them in a single frame. Both glyphs share
              // the same 18×18 box so the start-icon column doesn't
              // shift width when busy flips.
              <Box
                component="span"
                sx={{
                  position: "relative",
                  display: "inline-flex",
                  alignItems: "center",
                  justifyContent: "center",
                  width: 18,
                  height: 18,
                }}
              >
                <DeleteIcon
                  fontSize="small"
                  sx={{
                    position: "absolute",
                    opacity: deleteBusy ? 0 : 1,
                    transition: "opacity 180ms ease",
                  }}
                />
                <CircularProgress
                  size={14}
                  thickness={5}
                  color="inherit"
                  sx={{
                    position: "absolute",
                    opacity: deleteBusy ? 1 : 0,
                    transition: "opacity 180ms ease",
                  }}
                />
              </Box>
            }
            onClick={() => void confirmDelete()}
            disabled={deleteBusy}
            // Keep the red palette while the button is disabled mid-
            // delete instead of MUI's default washed-out gray. The
            // action is in flight, not unavailable — the spinner is
            // already telling the user it's busy, so we don't need
            // a second "this control is dead" signal on top.
            sx={{
              "&.Mui-disabled": {
                bgcolor: "error.main",
                color: "error.contrastText",
              },
            }}
          >
            {/* Cross-fade "Delete" ↔ "Deleting…" while keeping the
                button at a fixed width — the longer label is rendered
                as an invisible spacer so MUI lays the button out
                against it once and the size doesn't animate. */}
            <Box
              component="span"
              sx={{
                position: "relative",
                display: "inline-block",
                lineHeight: "inherit",
              }}
            >
              <Box component="span" sx={{ visibility: "hidden" }}>
                Deleting…
              </Box>
              <Box
                component="span"
                sx={{
                  position: "absolute",
                  inset: 0,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  opacity: deleteBusy ? 0 : 1,
                  transition: "opacity 180ms ease",
                }}
              >
                Delete
              </Box>
              <Box
                component="span"
                sx={{
                  position: "absolute",
                  inset: 0,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  opacity: deleteBusy ? 1 : 0,
                  transition: "opacity 180ms ease",
                }}
              >
                Deleting…
              </Box>
            </Box>
          </Button>
        </DialogActions>
      </Dialog>
      {/* Row-action confirmation dialog. Opens whenever a configured
          RowActionSpec.confirm() returns a payload — the per-page
          replacement for `window.confirm` for non-destructive actions
          like "Reset traffic". Same compact size and chrome as the
          Delete dialog above; the start icon, primary colour and
          button labels come from the action / its `confirm` payload
          so the dialog can read as either a primary "Reset" or a
          destructive "Wipe" depending on the spec. */}
      <Dialog
        open={pendingAction !== null}
        onClose={() => {
          if (!actionBusy) setPendingAction(null);
        }}
        maxWidth="xs"
        fullWidth
      >
        <DialogTitle>{displayActionConfirm?.title ?? ""}</DialogTitle>
        <DialogContent dividers>
          <Typography variant="body2" color="text.secondary">
            {displayActionConfirm?.description ?? ""}
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => setPendingAction(null)}
            disabled={actionBusy}
          >
            Cancel
          </Button>
          <Button
            variant="contained"
            color={displayActionConfirm?.color ?? "primary"}
            startIcon={
              // Cross-fade the action's icon with a small spinner so
              // the start-icon column doesn't shift width when the
              // busy flag flips. Mirrors the same pattern used in the
              // Delete dialog above.
              <Box
                component="span"
                sx={{
                  position: "relative",
                  display: "inline-flex",
                  alignItems: "center",
                  justifyContent: "center",
                  width: 18,
                  height: 18,
                }}
              >
                <Box
                  component="span"
                  sx={{
                    position: "absolute",
                    display: "inline-flex",
                    alignItems: "center",
                    justifyContent: "center",
                    opacity: actionBusy ? 0 : 1,
                    transition: "opacity 180ms ease",
                  }}
                >
                  {displayPendingAction?.action.icon}
                </Box>
                <CircularProgress
                  size={14}
                  thickness={5}
                  color="inherit"
                  sx={{
                    position: "absolute",
                    opacity: actionBusy ? 1 : 0,
                    transition: "opacity 180ms ease",
                  }}
                />
              </Box>
            }
            onClick={() => void confirmAction()}
            disabled={actionBusy}
            // Same disabled-state colour preservation as the Delete
            // button: keep the configured palette so the spinner is
            // the only "I'm busy" signal, not a washed-out grey
            // background on top of it.
            sx={(t) => {
              const palette =
                t.palette[displayActionConfirm?.color ?? "primary"];
              return {
                "&.Mui-disabled": {
                  bgcolor: palette.main,
                  color: palette.contrastText,
                },
              };
            }}
          >
            {/* Cross-fade idle ↔ busy labels at a fixed width — the
                longer of the two labels acts as the spacer so MUI
                lays the button out against it once and the size
                doesn't animate. */}
            {(() => {
              const idle =
                displayActionConfirm?.confirmLabel ??
                displayPendingAction?.action.label ??
                "Confirm";
              const busy =
                displayActionConfirm?.busyLabel ?? `${idle}…`;
              const spacer = idle.length >= busy.length ? idle : busy;
              return (
                <Box
                  component="span"
                  sx={{
                    position: "relative",
                    display: "inline-block",
                    lineHeight: "inherit",
                  }}
                >
                  <Box component="span" sx={{ visibility: "hidden" }}>
                    {spacer}
                  </Box>
                  <Box
                    component="span"
                    sx={{
                      position: "absolute",
                      inset: 0,
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      opacity: actionBusy ? 0 : 1,
                      transition: "opacity 180ms ease",
                    }}
                  >
                    {idle}
                  </Box>
                  <Box
                    component="span"
                    sx={{
                      position: "absolute",
                      inset: 0,
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      opacity: actionBusy ? 1 : 0,
                      transition: "opacity 180ms ease",
                    }}
                  >
                    {busy}
                  </Box>
                </Box>
              );
            })()}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

// CrudRowInner renders a single table row. Wrapped in React.memo with a
// custom equality fn so typing in a filter / opening dialogs / paging
// doesn't re-render every visible row through MUI's emotion CSS-in-JS
// (which was the source of the small <100 ms freezes when pressing
// buttons or typing). Only `row` data, the `selected` boolean, and the
// `columns` reference participate in equality — handler refs and any
// other parent state are intentionally ignored, since the closures
// always do the same thing.
interface CrudRowProps<TEntity> {
  row: TEntity;
  rowKey: string;
  columns: ColumnSpec<TEntity>[];
  selected: boolean;
  // Position of the row inside the currently-visible page slice.
  // Drives the staggered entrance animation below — the actual prop
  // is intentionally NOT part of the memo equality check (see
  // `CrudRow` further down) so a row simply changing position
  // (resort / page change with overlap) doesn't re-render via
  // emotion just because its index moved by one.
  index: number;
  onToggle: (row: TEntity) => void;
  onEdit: (row: TEntity) => void;
  onDelete: (row: TEntity) => void;
  // Optional extra actions (rendered before Edit / Delete). Stable
  // reference from the parent — see the memo equality fn below.
  rowActions?: RowActionSpec<TEntity>[];
  onRunAction?: (row: TEntity, action: RowActionSpec<TEntity>) => void;
}
function CrudRowInner<TEntity>(props: CrudRowProps<TEntity>) {
  const {
    row,
    rowKey,
    columns,
    selected,
    index,
    onToggle,
    onEdit,
    onDelete,
    rowActions,
    onRunAction,
  } = props;
  // Entrance animation — opacity-only fade so the row reads as
  // "just arrived" when the table fills in (initial load, page
  // change, filter applied, sort change). Driven by the Web
  // Animations API rather than a CSS keyframe rule for the same
  // reason DashboardTile uses WAAPI: emotion's class-hash churn
  // can re-trigger a CSS keyframe on an already-mounted element,
  // which surfaced as a "flash twice on cold load" glitch on the
  // dashboard. The `animatedRef` flag guarantees one play per
  // row fiber lifetime.
  //
  // We deliberately animate *opacity* only. `transform: translateY`
  // would create a containing block on the `<tr>`, which breaks
  // `position: sticky` on the Actions cell (the right-pinned
  // column would stop sticking to the scroll viewport and start
  // sticking to the row instead). Plain opacity has none of
  // those side effects.
  //
  // Stagger delay is `min(index * 22, 220)` ms: the first ~10
  // rows cascade in quick succession, every later row fires at
  // the 220 ms cap so a 100-row page doesn't take 2.2 s to
  // settle. With a 280 ms duration the last staggered row
  // finishes at ~500 ms — under the 600 ms threshold where a
  // table tween starts to feel like waiting.
  //
  // `prefers-reduced-motion` users skip the animation entirely
  // and the row mounts at full opacity from the first frame.
  const rowRef = useRef<HTMLTableRowElement | null>(null);
  const animatedRef = useRef(false);
  useLayoutEffect(() => {
    const el = rowRef.current;
    if (!el || animatedRef.current) return;
    if (typeof el.animate !== "function") return;
    animatedRef.current = true;
    if (
      typeof window !== "undefined" &&
      typeof window.matchMedia === "function" &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches
    ) {
      return;
    }
    el.animate(
      [{ opacity: 0 }, { opacity: 1 }],
      {
        duration: 280,
        delay: Math.min(index * 22, 220),
        easing: "cubic-bezier(0.22, 0.61, 0.36, 1)",
        fill: "backwards",
      },
    );
    // Mount-time animation only — `index` deliberately omitted so
    // a row whose position shifts later doesn't re-trigger.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return (
    <TableRow hover ref={rowRef}>
      <TableCell
        sx={{
          paddingLeft: 0,
          paddingRight: 0,
          textAlign: "center",
          overflow: "visible",
        }}
      >
        <Checkbox
          size="small"
          color="primary"
          checked={selected}
          onChange={() => onToggle(row)}
          inputProps={{ "aria-label": `select row ${rowKey}` }}
        />
      </TableCell>
      {columns.map((c) => {
        const isId = c.key === "id" || c.key === "uuid";
        return (
          <TableCell
            key={String(c.key)}
            sx={isId ? ID_CELL_SX : BODY_CELL_SX}
          >
            {c.render
              ? c.render(row)
              : renderDefault((row as Record<string, unknown>)[c.key as string])}
          </TableCell>
        );
      })}
      {/* Body filler cell — mirrors the auto-width filler in the
          header so each body row has the same column count and the
          column widths line up. Empty content; padding stripped so
          it can collapse to 0 px under `tableLayout: fixed` when
          the fixed columns exceed the viewport. */}
      <TableCell aria-hidden sx={FILLER_CELL_SX} />
      <TableCell align="center" sx={ACTIONS_CELL_SX}>
        <Stack
          direction="row"
          spacing={0.5}
          justifyContent="center"
          alignItems="center"
        >
          {rowActions?.map((action) => {
            if (action.visible && !action.visible(row)) return null;
            return (
              <Tooltip key={action.key} title={action.label}>
                <IconButton
                  size="small"
                  aria-label={action.label}
                  onClick={() => onRunAction?.(row, action)}
                  sx={action.variant === "danger" ? DELETE_BTN_SX : EDIT_BTN_SX}
                >
                  {action.icon}
                </IconButton>
              </Tooltip>
            );
          })}
          <Tooltip title="Edit">
            <IconButton size="small" onClick={() => onEdit(row)} sx={EDIT_BTN_SX}>
              <EditIcon fontSize="small" />
            </IconButton>
          </Tooltip>
          <Tooltip title="Delete">
            <IconButton
              size="small"
              onClick={() => onDelete(row)}
              sx={DELETE_BTN_SX}
            >
              <DeleteIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Stack>
      </TableCell>
    </TableRow>
  );
}
const CrudRow = memo(CrudRowInner, (prev, next) => {
  return (
    prev.row === next.row &&
    prev.selected === next.selected &&
    prev.columns === next.columns &&
    prev.rowKey === next.rowKey &&
    prev.rowActions === next.rowActions
  );
}) as typeof CrudRowInner;

// CrudCardInner — phone-friendly card variant of CrudRow. Same data,
// same handlers (onToggle / onEdit / onDelete), but laid out as a
// vertical label/value list inside a bordered Paper-style Box so the
// row stays fully visible without horizontal scrolling.
//
// Memo'd with the same equality fn as CrudRow for the same reason —
// keep typing in a filter or paging through cheap.
function CrudCardInner<TEntity>(props: CrudRowProps<TEntity>) {
  const {
    row,
    rowKey,
    columns,
    selected,
    index,
    onToggle,
    onEdit,
    onDelete,
    rowActions,
    onRunAction,
  } = props;
  // Mirror of the CrudRowInner entrance animation but with the
  // upgrade an HTML <Box> permits: a small `translateY` slide
  // alongside the opacity fade. The Box doesn't host a sticky
  // sibling the way a `<tr>` does, so the new containing block
  // a transform creates is harmless here.
  const cardRef = useRef<HTMLDivElement | null>(null);
  const animatedRef = useRef(false);
  useLayoutEffect(() => {
    const el = cardRef.current;
    if (!el || animatedRef.current) return;
    if (typeof el.animate !== "function") return;
    animatedRef.current = true;
    if (
      typeof window !== "undefined" &&
      typeof window.matchMedia === "function" &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches
    ) {
      return;
    }
    el.animate(
      [
        { opacity: 0, transform: "translateY(8px)" },
        { opacity: 1, transform: "translateY(0)" },
      ],
      {
        duration: 320,
        delay: Math.min(index * 28, 280),
        easing: "cubic-bezier(0.22, 0.61, 0.36, 1)",
        fill: "backwards",
      },
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return (
    <Box
      ref={cardRef}
      sx={{
        border: "1px solid",
        borderColor: selected ? "primary.main" : "divider",
        borderRadius: 1.5,
        bgcolor: "background.paper",
        transition: "border-color 0.18s ease, box-shadow 0.18s ease",
      }}
    >
      {/* Top strip — selection + actions. Compact so the card itself
          stays tight on a small screen, but tap targets are still
          large enough (Checkbox + IconButtons are 30+ px each). */}
      <Stack
        direction="row"
        alignItems="center"
        sx={{
          px: 0.5,
          py: 0.25,
          borderBottom: "1px solid",
          borderColor: "divider",
        }}
      >
        <Checkbox
          size="small"
          color="primary"
          checked={selected}
          onChange={() => onToggle(row)}
          inputProps={{ "aria-label": `select row ${rowKey}` }}
        />
        <Box sx={{ flexGrow: 1 }} />
        {rowActions?.map((action) => {
          if (action.visible && !action.visible(row)) return null;
          return (
            <Tooltip key={action.key} title={action.label}>
              <IconButton
                size="small"
                aria-label={action.label}
                onClick={() => onRunAction?.(row, action)}
                sx={action.variant === "danger" ? DELETE_BTN_SX : EDIT_BTN_SX}
              >
                {action.icon}
              </IconButton>
            </Tooltip>
          );
        })}
        <Tooltip title="Edit">
          <IconButton size="small" onClick={() => onEdit(row)} sx={EDIT_BTN_SX}>
            <EditIcon fontSize="small" />
          </IconButton>
        </Tooltip>
        <Tooltip title="Delete">
          <IconButton
            size="small"
            onClick={() => onDelete(row)}
            sx={DELETE_BTN_SX}
          >
            <DeleteIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      </Stack>
      {/* Body — one row per column. Label hugs a fixed-width left
          column so values line up vertically; the value column flexes
          to the available width and wraps on long content
          (uuids, comma-separated IDs, etc.) instead of being clipped
          like the desktop table cell would. */}
      <Stack spacing={1} sx={{ px: 1.5, py: 1.25 }}>
        {columns.map((c) => {
          const isId = c.key === "id" || c.key === "uuid";
          const value = c.render
            ? c.render(row)
            : renderDefault((row as Record<string, unknown>)[c.key as string]);
          return (
            <Box
              key={String(c.key)}
              sx={{
                display: "flex",
                alignItems: "flex-start",
                gap: 1.25,
              }}
            >
              <Box
                sx={{
                  flexShrink: 0,
                  width: 96,
                  fontSize: 11,
                  fontWeight: 600,
                  letterSpacing: 0.6,
                  textTransform: "uppercase",
                  color: "text.secondary",
                  pt: 0.25,
                  // Wrap long column labels (e.g. "Bandwidth limit")
                  // onto two lines instead of forcing a wider label
                  // gutter that would steal space from values.
                  wordBreak: "break-word",
                }}
              >
                {c.label}
              </Box>
              <Box
                sx={{
                  flexGrow: 1,
                  minWidth: 0,
                  fontSize: 13.5,
                  // Allow values to break onto multiple lines on
                  // narrow screens. ID-style columns get the
                  // monospace treatment to match the table's
                  // ID_CELL_SX, but without the ellipsis (the whole
                  // value is useful here, and we have room to wrap).
                  wordBreak: "break-word",
                  ...(isId
                    ? {
                        fontFamily:
                          '"JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace',
                        fontSize: 12.5,
                        color: "text.secondary",
                      }
                    : {}),
                }}
              >
                {value}
              </Box>
            </Box>
          );
        })}
      </Stack>
    </Box>
  );
}
const CrudCard = memo(CrudCardInner, (prev, next) => {
  return (
    prev.row === next.row &&
    prev.selected === next.selected &&
    prev.columns === next.columns &&
    prev.rowKey === next.rowKey &&
    prev.rowActions === next.rowActions
  );
}) as typeof CrudCardInner;

// DateCell — pretty two-line date display used by `renderDefault` whenever
// it sees an ISO datetime. Top row is the day in `15 Jan 2025` form (year
// dropped if it's the current year so the cell stays compact); bottom row
// is the time in `HH:mm` form, dimmer and a touch smaller. Hovering shows
// the full localized stamp plus a relative ("2 hours ago"-style) hint;
// for entries too old to express compactly the relative half is dropped
// and only the full stamp is shown.
function DateCell({ value }: { value: string }) {
  const d = dayjs(value);
  if (!d.isValid()) return <>{value}</>;
  const now = dayjs();
  const sameYear = d.year() === now.year();
  const datePart = sameYear ? d.format("D MMM") : d.format("D MMM YYYY");
  const timePart = d.format("HH:mm");
  const fullStamp = d.format("D MMMM YYYY, HH:mm:ss");
  // Cheap "Xy ago" formatter — avoids pulling in dayjs's relativeTime
  // plugin just for one column. For entries older than 30 days we omit
  // the relative half and let the tooltip show the full stamp on its own.
  const diffMs = now.diff(d);
  const sec = Math.round(diffMs / 1000);
  const min = Math.round(sec / 60);
  const hr = Math.round(min / 60);
  const day = Math.round(hr / 24);
  let relative = "";
  if (Math.abs(sec) < 60) relative = "just now";
  else if (Math.abs(min) < 60) relative = `${min} min ago`;
  else if (Math.abs(hr) < 24) relative = `${hr}h ago`;
  else if (Math.abs(day) < 30) relative = `${day}d ago`;
  const tooltipTitle = relative ? `${fullStamp} · ${relative}` : fullStamp;
  return (
    <Tooltip title={tooltipTitle} placement="top">
      <Box
        sx={{
          display: "inline-flex",
          flexDirection: "column",
          lineHeight: 1.1,
          fontVariantNumeric: "tabular-nums",
        }}
      >
        <Box component="span" sx={{ fontWeight: 500 }}>
          {datePart}
        </Box>
        <Box
          component="span"
          sx={{ fontSize: 12, color: "text.secondary", mt: 0.25 }}
        >
          {timePart}
        </Box>
      </Box>
    </Tooltip>
  );
}

function renderDefault(v: unknown): ReactNode {
  if (v === null || v === undefined) return "";
  if (Array.isArray(v)) {
    // gap (instead of Stack spacing) gives the chips a real two-axis
    // gutter when the column is narrow enough that the chips have to wrap
    // onto multiple lines — so e.g. `squad_ids` no longer reads as two
    // crammed-together rows of chips when the page is squeezed.
    return (
      <Box
        sx={{
          display: "flex",
          flexWrap: "wrap",
          rowGap: 0.5,
          columnGap: 0.5,
          maxWidth: "100%",
        }}
      >
        {v.map((x, i) => (
          <Chip key={i} label={String(x)} size="small" />
        ))}
      </Box>
    );
  }
  if (typeof v === "object") return JSON.stringify(v);
  if (typeof v === "string" && /\d{4}-\d{2}-\d{2}T/.test(v)) {
    return <DateCell value={v} />;
  }
  return String(v);
}

interface DialogProps {
  // Controls MUI's `open` directly so the parent can flip it to false to
  // trigger the leave transition while the component stays mounted; the
  // parent then waits for `onExited` before clearing its own state.
  open: boolean;
  mode: "create" | "update";
  fields: FieldSpec[];
  initial?: Record<string, unknown>;
  title: string;
  onClose: () => void;
  onExited?: () => void;
  onSubmit: (form: Record<string, unknown>) => Promise<void>;
}

function CrudDialog({
  open,
  mode,
  fields,
  initial,
  title,
  onClose,
  onExited,
  onSubmit,
}: DialogProps) {
  // Mirror the mobile detection used in CrudPage so the create / edit
  // form dialog goes full-screen on phones + portrait tablets — with a
  // narrow viewport a width-sm modal covers most of the screen anyway,
  // but full-screen gives the long squad / user forms room to breathe
  // and avoids awkward double-scroll (modal scroll + page scroll).
  const dialogTheme = useTheme();
  const dialogIsMobile = useMediaQuery(dialogTheme.breakpoints.down("md"));
  const [form, setForm] = useState<Record<string, unknown>>(() => {
    const base = emptyForm(fields, mode);
    if (initial) {
      // Seed every initial value, including those for fields that are
      // currently hidden (e.g. `type` on the user edit form). Hidden values
      // are still read by `visibleWhen` predicates and dropped at submit
      // time by `normalizeFormForSubmit`.
      for (const f of fields) {
        const v = initial[f.name];
        if (v === undefined) continue;
        if (f.type === "ids" && Array.isArray(v)) base[f.name] = v.join(",");
        else if (f.type === "multiselect" && Array.isArray(v)) {
          // The multi-select stores values as strings (so `Squad.id` numbers
          // become "1", "2"…); coerce here so editing pre-selects the right
          // entries and the submit step can re-parse them.
          base[f.name] = (v as unknown[]).map(String);
        } else base[f.name] = v as unknown;
      }
    }
    return base;
  });
  // Re-evaluate visibility every render so dynamic `visibleWhen` predicates
  // reflect the latest form values (e.g. switching the user `type`).
  const visibleFields = useMemo(
    () => fields.filter((f) => fieldVisible(f, mode, form)),
    [fields, mode, form],
  );

  // Async option loaders are fired once when the dialog mounts. Each entry
  // overrides the field's static `options` while rendering. Loaders are
  // skipped for fields hidden in the current mode (e.g. a create-only
  // squad picker when the dialog was opened for edit) so the API isn't
  // hit for options no one will see.
  type LoadedOpts = Record<string, { value: string; label?: string }[]>;
  const [loadedOptions, setLoadedOptions] = useState<LoadedOpts>({});
  useEffect(() => {
    const targets = fields.filter(
      (f) =>
        typeof f.optionsLoader === "function" && (!f.only || f.only === mode),
    );
    if (targets.length === 0) return;
    let cancelled = false;
    (async () => {
      try {
        const entries = await Promise.all(
          targets.map(async (f) => {
            const opts = await f.optionsLoader!();
            return [f.name, opts] as const;
          }),
        );
        if (cancelled) return;
        const next: LoadedOpts = {};
        for (const [name, opts] of entries) next[name] = opts;
        setLoadedOptions(next);
      } catch {
        /* loaders are best-effort; fall back to whatever static options exist */
      }
    })();
    return () => {
      cancelled = true;
    };
    // Run only once per dialog instance.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const optionsFor = (f: FieldSpec) => loadedOptions[f.name] ?? f.options ?? [];
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  // Per-field validation messages. A non-empty entry causes the field to
  // render in error state with the message as helper text. Cleared as soon
  // as the user provides a value for the offending field.
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});

  // set updates a single field's value. If the field declares `clears`, every
  // listed dependent field is reset to its empty default at the same time —
  // this is what "switching the user type clears the credential fields"
  // relies on.
  const set = (name: string, value: unknown) => {
    setForm((p) => {
      const next: Record<string, unknown> = { ...p, [name]: value };
      const source = fields.find((f) => f.name === name);
      if (source?.clears && source.clears.length > 0) {
        for (const target of source.clears) {
          const f = fields.find((x) => x.name === target);
          next[target] = f ? emptyValueForField(f) : "";
        }
      }
      return next;
    });
    // Clear the error for the field as soon as the user touches it; also
    // clear any errors on dependent fields that just got reset.
    setFieldErrors((prev) => {
      if (!prev[name] && !fields.find((f) => f.name === name)?.clears) return prev;
      const next = { ...prev };
      delete next[name];
      const source = fields.find((f) => f.name === name);
      if (source?.clears) for (const t of source.clears) delete next[t];
      return next;
    });
  };

  const submit = async () => {
    // Validate visible required fields first. If anything is missing we
    // surface it inline (per-field) and via a top-level alert, and skip the
    // network round-trip entirely.
    const errors = validateRequired(visibleFields, form);
    if (Object.keys(errors).length > 0) {
      setFieldErrors(errors);
      const missing = visibleFields
        .filter((f) => errors[f.name])
        .map((f) => f.label);
      setErr(`Please fill in the required field${missing.length > 1 ? "s" : ""}: ${missing.join(", ")}`);
      return;
    }
    setFieldErrors({});
    setBusy(true);
    setErr(null);
    try {
      await onSubmit(normalizeFormForSubmit(fields, mode, form));
    } catch {
      // Server-side failures are surfaced via the global toast stack
      // by the parent's `notifyApiError` call inside handleCreate /
      // handleUpdate. The dialog stays open (we never advance past
      // the throw) so the user can retry without re-typing the form.
    } finally {
      setBusy(false);
    }
  };

  // submitOnEnter forwards a top-level Enter key inside the dialog to the
  // submit handler. We deliberately ignore Enter coming from elements that
  // own their own keyboard semantics:
  //
  //   - <textarea> (would lose newline support)
  //   - the buttons themselves (they invoke their own click handler)
  //   - any element inside a portal — open <Select> menus and the
  //     DateTimePicker popover render outside this Dialog node, so their
  //     Enter never reaches us in the first place.
  const submitOnEnter = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key !== "Enter" || e.shiftKey || e.nativeEvent.isComposing) return;
    const target = e.target as HTMLElement;
    const tag = target.tagName;
    if (tag === "TEXTAREA" || tag === "BUTTON" || tag === "A") return;
    e.preventDefault();
    void submit();
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      fullWidth
      maxWidth="sm"
      fullScreen={dialogIsMobile}
      onKeyDown={submitOnEnter}
      // MUI's default Fade transition runs both directions, but the dialog
      // used to unmount the moment `open` flipped to false (parent gated
      // rendering on `dialogOpen`), so the leave half never had a chance.
      // The parent now keeps us mounted until this callback fires; once
      // it does, it's safe to drop the form state and unmount us.
      TransitionProps={{ onExited }}
    >
      <DialogTitle>{title}</DialogTitle>
      <DialogContent dividers>
        {/* Inline alert reserved for client-side validation summaries
            ("Please fill in the required field…"): server errors are
            announced via the global toast stack instead, so the dialog
            never grows a red bar at the top in response to a failed
            CRUD round-trip. */}
        {err && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {err}
          </Alert>
        )}
        <Stack spacing={2} sx={{ mt: 1 }}>
          {visibleFields.map((f) => {
            const value = form[f.name];
            // Error / helper-text wiring shared across every field type:
            // when the field has a validation error we show it in MUI's
            // error state and override the helper text; otherwise the
            // configured helperText (if any) is shown.
            const fieldErr = fieldErrors[f.name];
            const errored = !!fieldErr;
            if (f.type === "select") {
              return (
                <TextField
                  key={f.name}
                  select
                  fullWidth
                  size="small"
                  required={f.required}
                  label={f.label}
                  error={errored}
                  helperText={fieldErr ?? f.helperText}
                  value={(value as string) ?? ""}
                  onChange={(e) => set(f.name, e.target.value)}
                >
                  {/* Optional fields keep an explicit "(none)" choice so the
                      user can clear them. Required fields skip it — there is
                      always a real selection. */}
                  {!f.required && (
                    <MenuItem value="">
                      <em>(none)</em>
                    </MenuItem>
                  )}
                  {(optionsFor(f)).map((o) => (
                    <MenuItem key={o.value} value={o.value}>
                      {o.label ?? o.value}
                    </MenuItem>
                  ))}
                </TextField>
              );
            }
            if (f.type === "multiselect") {
              const arr = Array.isArray(value) ? (value as string[]) : [];
              const opts = optionsFor(f);
              const labelOf = (v: string) =>
                opts.find((o) => o.value === v)?.label ?? v;
              return (
                <TextField
                  key={f.name}
                  select
                  fullWidth
                  size="small"
                  required={f.required}
                  label={f.label}
                  error={errored}
                  helperText={fieldErr ?? f.helperText}
                  SelectProps={{
                    multiple: true,
                    value: arr,
                    onChange: (e) => set(f.name, e.target.value as string[]),
                    // Two display modes:
                    //   - default chips, one per selection (no implied
                    //     ordering between them);
                    //   - chain mode (`displayAsChain: true`): the same
                    //     chips but joined by `→` arrows so an ordered
                    //     pipeline like flow_keys reads as
                    //     "User → Destination → IP".
                    renderValue: (selected) => {
                      const values = selected as string[];
                      if (f.displayAsChain) {
                        return (
                          <Box
                            sx={{
                              display: "flex",
                              flexWrap: "wrap",
                              alignItems: "center",
                              gap: 0.5,
                            }}
                          >
                            {values.map((v, i) => (
                              <Box
                                key={v}
                                sx={{
                                  display: "inline-flex",
                                  alignItems: "center",
                                  gap: 0.5,
                                }}
                              >
                                {i > 0 && (
                                  <Box
                                    component="span"
                                    sx={{
                                      color: "text.secondary",
                                      fontSize: 12,
                                      userSelect: "none",
                                    }}
                                  >
                                    →
                                  </Box>
                                )}
                                <Chip
                                  label={labelOf(v)}
                                  size="small"
                                  color="primary"
                                  sx={{ height: 22 }}
                                />
                              </Box>
                            ))}
                          </Box>
                        );
                      }
                      return (
                        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                          {values.map((v) => (
                            <Chip
                              key={v}
                              label={labelOf(v)}
                              size="small"
                              color="primary"
                              sx={{ height: 22 }}
                            />
                          ))}
                        </Box>
                      );
                    },
                  }}
                  value={arr}
                >
                  {opts.map((o) => (
                    <MenuItem key={o.value} value={o.value}>
                      {o.label ?? o.value}
                    </MenuItem>
                  ))}
                </TextField>
              );
            }
            if (f.type === "uuid") {
              return (
                <TextField
                  key={f.name}
                  fullWidth
                  size="small"
                  required={f.required}
                  label={f.label}
                  error={errored}
                  helperText={fieldErr ?? f.helperText}
                  value={(value as string | undefined) ?? ""}
                  onChange={(e) => set(f.name, e.target.value)}
                  InputProps={{
                    endAdornment: (
                      <Tooltip title="Generate UUID">
                        <IconButton
                          size="small"
                          edge="end"
                          onClick={() => set(f.name, generateUUID())}
                        >
                          <AutorenewIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    ),
                  }}
                />
              );
            }
            if (f.type === "string-list") {
              const arr = Array.isArray(value) ? (value as string[]) : [];
              return (
                <Box key={f.name} sx={{ mt: -1 }}>
                  <Typography variant="caption" color={errored ? "error" : "textSecondary"} sx={{ mb: 0.5, ml: "14px", display: "block" }}>
                    {f.label}{f.required ? " *" : ""}
                  </Typography>
                  <Stack spacing={1}>
                    {arr.map((item, idx) => (
                      <Stack key={idx} direction="row" spacing={1} alignItems="center">
                        <TextField
                          fullWidth
                          size="small"
                          value={item}
                          placeholder={`Key ${idx + 1}`}
                          onChange={(e) => {
                            const next = [...arr];
                            next[idx] = e.target.value;
                            set(f.name, next);
                          }}
                        />
                        <IconButton size="small" color="error" onClick={() => set(f.name, arr.filter((_, i) => i !== idx))}>
                          <DeleteIcon fontSize="small" />
                        </IconButton>
                      </Stack>
                    ))}
                  </Stack>
                  <Button size="small" startIcon={<AddIcon />} sx={{ mt: 1 }} onClick={() => set(f.name, [...arr, ""])}>
                    Add
                  </Button>
                  {fieldErr && <Typography variant="caption" color="error" sx={{ mt: 0.5, display: "block" }}>{fieldErr}</Typography>}
                </Box>
              );
            }
            const isNumber = f.type === "number";
            // Numeric value of the current cell. Falls back to 0 for the
            // empty state so the up-arrow always has a sensible base to
            // increment from. Decrement is clamped at 0 because the
            // input pattern only accepts non-negative integers anyway.
            const numericValue = isNumber
              ? (() => {
                  const v = (value as string | number | undefined) ?? "";
                  const n = parseInt(String(v), 10);
                  return Number.isFinite(n) ? n : 0;
                })()
              : 0;
            const stepValue = (delta: number) => {
              const next = Math.max(0, numericValue + delta);
              set(f.name, String(next));
            };
            return (
              <TextField
                key={f.name}
                fullWidth
                size="small"
                required={f.required}
                label={f.label}
                error={errored}
                helperText={
                  fieldErr ??
                  f.helperText ??
                  (f.type === "ids" ? "Comma-separated IDs" : undefined)
                }
                // Number fields render as plain `text` (rather than the
                // native `type="number"`) so we can fully control which
                // characters are accepted: HTML5 number inputs still let
                // through "e", "+", "-", scientific notation and even some
                // localized separators on certain locales. We strip every
                // non-digit on input and on paste, and block letter keys
                // before they reach the value at all.
                type="text"
                inputMode={isNumber ? "numeric" : undefined}
                // The keyboard / paste handlers go through `inputProps` so
                // they attach directly to the underlying <input> element.
                // Putting `onKeyDown` on the TextField itself isn't always
                // forwarded to the inner input in MUI v6 — this is the
                // reliable spot.
                inputProps={
                  isNumber
                    ? {
                        pattern: "[0-9]*",
                        onKeyDown: (e: React.KeyboardEvent<HTMLInputElement>) => {
                          // ArrowUp / ArrowDown step the value by 1 even
                          // though we render as `type="text"` (where the
                          // browser would otherwise just move the caret).
                          // This matches the behaviour users expect from
                          // a numeric field with spinner arrows.
                          if (e.key === "ArrowUp") {
                            e.preventDefault();
                            stepValue(1);
                            return;
                          }
                          if (e.key === "ArrowDown") {
                            e.preventDefault();
                            stepValue(-1);
                            return;
                          }
                          // Allow Backspace, Tab, Enter, Home, End,
                          // Delete (key.length > 1) and any combo with
                          // a modifier (Ctrl+A / Cmd+V / etc.). Block
                          // every other single-character key that isn't
                          // 0-9.
                          if (e.key.length > 1) return;
                          if (e.ctrlKey || e.metaKey || e.altKey) return;
                          if (!/^[0-9]$/.test(e.key)) e.preventDefault();
                        },
                        onPaste: (e: React.ClipboardEvent<HTMLInputElement>) => {
                          // Strip non-digits from clipboard text before it
                          // reaches the input. Without this the onChange
                          // sanitiser would still clean it, but the input
                          // would briefly flash the raw paste contents.
                          const txt = e.clipboardData.getData("text");
                          const cleaned = txt.replace(/\D+/g, "");
                          if (cleaned !== txt) {
                            e.preventDefault();
                            const target = e.currentTarget;
                            const start = target.selectionStart ?? target.value.length;
                            const end = target.selectionEnd ?? target.value.length;
                            const next =
                              target.value.slice(0, start) +
                              cleaned +
                              target.value.slice(end);
                            set(f.name, next);
                          }
                        },
                      }
                    : undefined
                }
                // Spinner arrows for numeric fields. Two stacked
                // IconButtons sized to fit the small TextField height
                // (~32 px) — 14 px each, 0 px padding — with the up
                // arrow on top and the down arrow underneath. They
                // share the `var(--sb-accent)` hover treatment used
                // elsewhere in the panel.
                InputProps={
                  isNumber
                    ? {
                        endAdornment: (
                          <Box
                            sx={{
                              display: "flex",
                              flexDirection: "column",
                              alignItems: "stretch",
                              ml: 0.5,
                              mr: -0.75,
                            }}
                          >
                            <IconButton
                              aria-label={`Increase ${f.label}`}
                              tabIndex={-1}
                              onClick={() => stepValue(1)}
                              sx={{
                                width: 22,
                                height: 14,
                                p: 0,
                                borderRadius: 0.75,
                                color: "text.secondary",
                                transition:
                                  "color 0.16s ease, background-color 0.16s ease",
                                "&:hover": { color: "var(--sb-accent)" },
                              }}
                            >
                              <KeyboardArrowUpIcon sx={{ fontSize: 16 }} />
                            </IconButton>
                            <IconButton
                              aria-label={`Decrease ${f.label}`}
                              tabIndex={-1}
                              disabled={numericValue <= 0}
                              onClick={() => stepValue(-1)}
                              sx={{
                                width: 22,
                                height: 14,
                                p: 0,
                                borderRadius: 0.75,
                                color: "text.secondary",
                                transition:
                                  "color 0.16s ease, background-color 0.16s ease",
                                "&:hover": { color: "var(--sb-accent)" },
                              }}
                            >
                              <KeyboardArrowDownIcon sx={{ fontSize: 16 }} />
                            </IconButton>
                          </Box>
                        ),
                      }
                    : undefined
                }
                value={(value as string | number | undefined) ?? ""}
                onChange={(e) => {
                  const v = isNumber
                    ? e.target.value.replace(/\D+/g, "")
                    : e.target.value;
                  set(f.name, v);
                }}
              />
            );
          })}
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={busy}>
          Cancel
        </Button>
        <Button
          variant="contained"
          onClick={() => void submit()}
          disabled={busy}
          // Same treatment as the delete dialog's primary action: keep
          // the active palette while disabled mid-submit so the spinner
          // is the only "I'm working" cue, instead of layering a washed-
          // out gray on top of it.
          sx={{
            "&.Mui-disabled": {
              bgcolor: "primary.main",
              color: "primary.contrastText",
            },
          }}
        >
          {/* Cross-fade idle ("Create" / "Save") with the busy state
              ("[spinner] Saving…") at a fixed button width — the busy
              version is rendered as an invisible spacer once so MUI
              lays the button out against it and the size doesn't
              animate as `busy` flips. */}
          <Box
            component="span"
            sx={{
              position: "relative",
              display: "inline-flex",
              alignItems: "center",
              justifyContent: "center",
              lineHeight: "inherit",
            }}
          >
            <Box
              component="span"
              sx={{
                visibility: "hidden",
                display: "inline-flex",
                alignItems: "center",
              }}
            >
              <Box component="span" sx={{ width: 14, height: 14, mr: 1 }} />
              Saving…
            </Box>
            <Box
              component="span"
              sx={{
                position: "absolute",
                inset: 0,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                opacity: busy ? 0 : 1,
                transition: "opacity 180ms ease",
              }}
            >
              {mode === "create" ? "Create" : "Save"}
            </Box>
            <Box
              component="span"
              sx={{
                position: "absolute",
                inset: 0,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                opacity: busy ? 1 : 0,
                transition: "opacity 180ms ease",
              }}
            >
              <CircularProgress
                size={14}
                thickness={5}
                color="inherit"
                sx={{ mr: 1 }}
              />
              Saving…
            </Box>
          </Box>
        </Button>
      </DialogActions>
    </Dialog>
  );
}

// FilterField renders a single filter input based on its spec type. Kept
// inside this file because the filter model is tightly coupled to
// `FilterSpec` and the surrounding CrudPage.
function FilterField({
  spec,
  value,
  onChange,
}: {
  spec: FilterSpec;
  value: unknown;
  onChange: (v: unknown) => void;
}) {
  if (spec.type === "select") {
    return (
      <TextField
        select
        fullWidth
        size="small"
        label={spec.label}
        value={(value as string) ?? ""}
        onChange={(e) => onChange(e.target.value)}
      >
        <MenuItem value="">
          <em>(any)</em>
        </MenuItem>
        {(spec.options ?? []).map((o) => (
          <MenuItem key={o.value} value={o.value}>
            {o.label ?? o.value}
          </MenuItem>
        ))}
      </TextField>
    );
  }
  if (spec.type === "datetime-range") {
    return <DateRangeFilterField spec={spec} value={value} onChange={onChange} />;
  }
  return (
    <TextField
      fullWidth
      size="small"
      label={spec.label}
      placeholder={spec.placeholder}
      value={(value as string) ?? ""}
      onChange={(e) => onChange(e.target.value)}
    />
  );
}

// DateRangeFilterField — the datetime-range filter as a single bordered
// box that visually reads like one "calendar button" filling the whole
// cell. Two halves (start / end) are themselves clickable: clicking
// either half opens its DateTimePicker calendar in a popper. The picker
// is rendered headless (its field replaced via `slots.field`) so MUI X
// doesn't draw any input, format mask, or `YYYY-MM-DD` placeholder
// inside the cell.
function DateRangeFilterField({
  spec,
  value,
  onChange,
}: {
  spec: FilterSpec;
  value: unknown;
  onChange: (v: unknown) => void;
}) {
  const r = (value ?? {}) as { start?: string; end?: string };
  const toDayjs = (s: string | undefined): Dayjs | null => {
    if (!s) return null;
    const d = dayjs(s);
    return d.isValid() ? d : null;
  };
  const fromDayjs = (d: Dayjs | null): string | undefined =>
    d && d.isValid() ? d.format("YYYY-MM-DDTHH:mm") : undefined;
  const formatDisplay = (s: string | undefined): string | null => {
    const d = toDayjs(s);
    return d ? d.format("YYYY-MM-DD HH:mm") : null;
  };
  const [openStart, setOpenStart] = useState(false);
  const [openEnd, setOpenEnd] = useState(false);
  // Anchors used by the picker popper. We point them at the visible
  // half-buttons (instead of the headless field) so the calendar opens
  // attached to whichever side the user clicked.
  const startAnchorRef = useRef<HTMLElement | null>(null);
  const endAnchorRef = useRef<HTMLElement | null>(null);
  const halfSx = {
    flex: 1,
    minWidth: 0,
    height: "100%",
    display: "flex",
    alignItems: "center",
    // Centre the [calendar icon + date text] group horizontally
    // inside each half so the value reads as visually centred
    // rather than left-aligned against the inner edge of the cell.
    // The inner text span loses its `flex: 1` (see below) so the
    // group keeps its natural width and `justifyContent: center`
    // can actually move it.
    justifyContent: "center",
    gap: 0.75,
    paddingInline: "10px",
    cursor: "pointer",
    fontSize: 13.5,
    overflow: "hidden",
    userSelect: "none" as const,
  };
  const startDisplay = formatDisplay(r.start);
  const endDisplay = formatDisplay(r.end);
  return (
    <Box
      sx={(t) => ({
        position: "relative",
        display: "flex",
        alignItems: "center",
        width: "100%",
        height: 40,
        borderRadius: `${t.shape.borderRadius}px`,
        border: `1px solid ${t.palette.divider}`,
        backgroundColor:
          t.palette.mode === "light" ? "#ffffff" : "rgba(255,255,255,0.02)",
        transition: "border-color 0.16s ease, box-shadow 0.16s ease",
        "&:hover": { borderColor: t.palette.text.secondary },
        "&:focus-within": {
          borderColor: "var(--sb-accent)",
          boxShadow: `0 0 0 1px var(--sb-accent)`,
        },
      })}
    >
      <Box
        ref={(el: HTMLElement | null) => {
          startAnchorRef.current = el;
        }}
        role="button"
        tabIndex={0}
        onClick={() => setOpenStart(true)}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") setOpenStart(true);
        }}
        sx={(t) => ({
          ...halfSx,
          color: startDisplay ? t.palette.text.primary : t.palette.text.secondary,
        })}
      >
        <CalendarTodayIcon
          sx={{ fontSize: 16, opacity: 0.7, flexShrink: 0 }}
        />
        <Box
          component="span"
          sx={{
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            // No `flex: 1` — keep the span at its content width so
            // the parent's `justifyContent: center` actually centres
            // the [icon + date] group instead of stretching the span
            // to fill the half. `minWidth: 0` still lets the span
            // shrink (with ellipsis) if the date string is wider
            // than the available space.
            minWidth: 0,
          }}
        >
          {startDisplay ?? `${spec.label} from`}
        </Box>
      </Box>
      <Box
        sx={(t) => ({
          flex: "0 0 auto",
          color: t.palette.text.secondary,
          fontSize: 13,
          userSelect: "none",
          paddingInline: "4px",
        })}
      >
        —
      </Box>
      <Box
        ref={(el: HTMLElement | null) => {
          endAnchorRef.current = el;
        }}
        role="button"
        tabIndex={0}
        onClick={() => setOpenEnd(true)}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") setOpenEnd(true);
        }}
        sx={(t) => ({
          ...halfSx,
          color: endDisplay ? t.palette.text.primary : t.palette.text.secondary,
        })}
      >
        <CalendarTodayIcon
          sx={{ fontSize: 16, opacity: 0.7, flexShrink: 0 }}
        />
        <Box
          component="span"
          sx={{
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            // See the matching comment on the `start` half above —
            // the span is intentionally content-width so the parent
            // can centre the [icon + date] pair.
            minWidth: 0,
          }}
        >
          {endDisplay ?? `${spec.label} to`}
        </Box>
      </Box>
      {/* Headless pickers — their fields are stripped via the `field`
          slot so they exist purely to render the calendar popper when
          opened. The popper is explicitly anchored to whichever
          half-button is active so the calendar lines up under it. */}
      <DateTimePicker
        open={openStart}
        onClose={() => setOpenStart(false)}
        value={toDayjs(r.start)}
        onChange={(d) => onChange({ ...r, start: fromDayjs(d) })}
        ampm={false}
        format="YYYY-MM-DD HH:mm"
        slots={{ field: HiddenField }}
        slotProps={{
          popper: { anchorEl: () => startAnchorRef.current ?? document.body },
        }}
      />
      <DateTimePicker
        open={openEnd}
        onClose={() => setOpenEnd(false)}
        value={toDayjs(r.end)}
        onChange={(d) => onChange({ ...r, end: fromDayjs(d) })}
        ampm={false}
        format="YYYY-MM-DD HH:mm"
        slots={{ field: HiddenField }}
        slotProps={{
          popper: { anchorEl: () => endAnchorRef.current ?? document.body },
        }}
      />
    </Box>
  );
}

// HiddenField — a no-op replacement for MUI X's default field. We still
// `forwardRef` so the picker's internal ref-pinning logic gets a real
// node (the picker would warn / fail to render otherwise). The element
// itself takes zero layout space, the popper anchors to our explicit
// half-button refs.
const HiddenField = forwardRef<HTMLSpanElement>(function HiddenField(_, ref) {
  return <span ref={ref} style={{ display: "none" }} aria-hidden="true" />;
});
