import PeopleIcon from "@mui/icons-material/People";
import { useMemo } from "react";
import {
  CrudPage,
  renderOptionLabel,
  type CrudConfig,
} from "../components/CrudPage";
import { useApi } from "../auth/AuthContext";
import type { User, UserCreate, UserType, UserUpdate } from "../api/types";
import {
  parseSquadIds,
  pickSquadIds,
  renderSquadIds,
  squadIdsField,
  useSquadCatalog,
} from "./squadField";

// Display labels mirror service/admin_panel/tables/user.go.
const USER_TYPES: { value: UserType; label: string }[] = [
  { value: "anytls", label: "AnyTLS" },
  { value: "http", label: "HTTP" },
  { value: "hysteria", label: "Hysteria" },
  { value: "hysteria2", label: "Hysteria2" },
  { value: "mixed", label: "Mixed" },
  { value: "mtproxy", label: "MTProxy" },
  { value: "naive", label: "Naive" },
  { value: "socks", label: "SOCKS" },
  { value: "ssh", label: "SSH" },
  { value: "trojan", label: "Trojan" },
  { value: "trusttunnel", label: "TrustTunnel" },
  { value: "tuic", label: "TUIC" },
  { value: "vless", label: "VLESS" },
  { value: "vmess", label: "VMess" },
];

const FLOW_OPTIONS: { value: string; label: string }[] = [
  { value: "xtls-rprx-vision", label: "xtls-rprx-vision" },
];

// Per-type field visibility, mirroring FieldOnChooseOptionsHide in
// service/admin_panel/tables/user.go and the struct-level validator for
// constant.UserCreate in service/manager/service.go. Every field in a
// SHOW_* set is also required for that type — the Go validator reports
// "required" for each missing credential, so the client enforces the
// same rule up-front (required fields invisible for the current type
// are filtered out before validateRequired runs).
const SHOW_UUID = new Set<UserType>(["vless", "vmess", "tuic"]);
const SHOW_PASSWORD = new Set<UserType>(["anytls", "http", "hysteria", "hysteria2", "mixed", "naive", "socks", "ssh", "trojan", "trusttunnel", "tuic"]);
const SHOW_SECRET = new Set<UserType>(["mtproxy"]);
const SHOW_AUTHORIZED_KEYS = new Set<UserType>(["ssh"]);
const SHOW_FLOW = new Set<UserType>(["vless"]);
const SHOW_ALTER_ID = new Set<UserType>(["vmess"]);

const showFor = (set: Set<UserType>) => (form: Record<string, unknown>) =>
  set.has(form.type as UserType);

export function UsersPage() {
  const api = useApi();
  const squads = useSquadCatalog(api);
  // Memoise the CRUD config so CrudPage's `reload` callback stays stable
  // across re-renders. Recomputed only when the API client or the squad
  // catalog actually changes (a new squad name arriving through
  // observeRows re-renders the table with the fresh chip labels).
  const config = useMemo<CrudConfig<User, UserCreate, UserUpdate>>(() => ({
    title: "Users",
    icon: <PeopleIcon />,
    idKey: "id",
    // After each page of users is loaded, fetch the squad names
    // referenced by those rows (only the ones we haven't cached yet).
    onRowsChange: (rows) => squads.observeRows(rows, pickSquadIds),
    columns: [
      { key: "id", label: "ID" },
      {
        key: "squad_ids",
        label: "Squads",
        sortable: false,
        render: renderSquadIds<User>(squads.names),
      },
      { key: "username", label: "Username" },
      { key: "inbound", label: "Inbound" },
      { key: "type", label: "Type", render: renderOptionLabel<User>("type", USER_TYPES) },
      { key: "created_at", label: "Created at" },
      { key: "updated_at", label: "Updated at" },
    ],
    filters: [
      { name: "username", label: "Username", type: "text" },
      { name: "inbound", label: "Inbound", type: "text" },
      { name: "type", label: "Type", type: "select", options: USER_TYPES },
      { name: "created_at", label: "Created at", type: "datetime-range" },
      { name: "updated_at", label: "Updated at", type: "datetime-range" },
    ],
    fields: [
      // FieldDisableWhenUpdate in service/admin_panel/tables/user.go.
      // The squad catalog is fetched lazily when the dialog opens —
      // never on page mount — via CrudDialog's optionsLoader.
      squadIdsField(squads.loadOptions),
      { name: "username", label: "Username", type: "text", required: true, only: "create" },
      { name: "inbound", label: "Inbound", type: "text", required: true, only: "create" },
      {
        name: "type",
        label: "Type",
        type: "select",
        required: true,
        only: "create",
        options: USER_TYPES,
        // Switching the user type wipes every credential field so the form
        // matches the legacy admin's behaviour of starting fresh.
        clears: ["uuid", "password", "secret", "authorized_keys", "flow", "alter_id"],
      },
      // Credential fields: the Go struct validator reports "required" for
      // whichever of these is missing once the type is chosen, so each one
      // is marked required AND gated by its SHOW_* set. Invisible fields
      // are filtered out before validateRequired runs, so e.g. Password is
      // only enforced for hysteria/hysteria2/trojan/tuic and not for vless.
      { name: "uuid", label: "UUID", type: "uuid", required: true, visibleWhen: showFor(SHOW_UUID) },
      { name: "password", label: "Password", type: "text", visibleWhen: showFor(SHOW_PASSWORD) },
      { name: "secret", label: "Secret", type: "text", required: true, visibleWhen: showFor(SHOW_SECRET) },
      { name: "authorized_keys", label: "Authorized Keys", type: "string-list", visibleWhen: showFor(SHOW_AUTHORIZED_KEYS) },
      {
        name: "flow",
        label: "Flow",
        type: "select",
        options: FLOW_OPTIONS,
        visibleWhen: showFor(SHOW_FLOW),
      },
      { name: "alter_id", label: "Alter ID", type: "number", required: true, visibleWhen: showFor(SHOW_ALTER_ID) },
    ],
    list: (q) => api.users.list(q),
    count: (q) => api.users.count(q),
    create: (b) => api.users.create(b),
    update: (id, b) => api.users.update(Number(id), b),
    remove: (id) => api.users.remove(Number(id)),
    // Seed `type` even though the field is create-only; the dialog uses it
    // for visibleWhen when editing existing users.
    fromEntity: (u) => ({
      squad_ids: u.squad_ids,
      type: u.type,
      uuid: u.uuid,
      password: u.password,
      secret: u.secret,
      authorized_keys: u.authorized_keys ?? [],
      flow: u.flow,
      alter_id: u.alter_id,
    }),
    toCreate: (f) => ({
      squad_ids: parseSquadIds(f.squad_ids),
      username: String(f.username ?? "").trim(),
      inbound: String(f.inbound ?? "").trim(),
      type: String(f.type ?? "") as UserType,
      uuid: f.uuid ? String(f.uuid).trim() : undefined,
      password: f.password ? String(f.password) : undefined,
      secret: f.secret ? String(f.secret) : undefined,
      authorized_keys: Array.isArray(f.authorized_keys) ? (f.authorized_keys as string[]).filter(Boolean) : undefined,
      flow: f.flow ? String(f.flow) : undefined,
      alter_id: f.alter_id !== undefined && f.alter_id !== "" ? Number(f.alter_id) : undefined,
    }),
    toUpdate: (f) => {
      const out: UserUpdate = {};
      if (f.uuid && String(f.uuid).trim() !== "") out.uuid = String(f.uuid).trim();
      if (f.password !== undefined && f.password !== "") out.password = String(f.password);
      if (f.secret !== undefined && f.secret !== "") out.secret = String(f.secret);
      if (Array.isArray(f.authorized_keys) && (f.authorized_keys as string[]).filter(Boolean).length > 0) out.authorized_keys = (f.authorized_keys as string[]).filter(Boolean);
      if (f.flow !== undefined && f.flow !== "") out.flow = String(f.flow);
      if (f.alter_id !== undefined && f.alter_id !== "") out.alter_id = Number(f.alter_id);
      return out;
    },
  }), [api, squads]);
  return <CrudPage<User, UserCreate, UserUpdate> config={config} />;
}
