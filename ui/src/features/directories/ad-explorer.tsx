import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Folder, User, Users, Monitor, Box, ChevronRight, Search } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { directoryLdap, type LdapEntry } from "@/lib/api";

// Read-only AD Explorer: browse the DC's tree (OUs/containers) + objects, view attributes.
// All reads go through the BFF, which binds with the directory's own admin creds.

function first(e: LdapEntry, k: string): string {
  return e.attributes[k]?.[0] ?? "";
}
function ocs(e: LdapEntry): string[] {
  return e.attributes["objectClass"] ?? [];
}
function isContainer(e: LdapEntry): boolean {
  const c = ocs(e);
  return (
    c.includes("organizationalUnit") ||
    c.includes("container") ||
    c.includes("builtinDomain") ||
    c.includes("domainDNS") ||
    c.includes("domain")
  );
}
function kindOf(e: LdapEntry): string {
  const c = ocs(e);
  if (c.includes("computer")) return "Computer";
  if (c.includes("group")) return "Group";
  if (c.includes("user")) return "User";
  if (c.includes("organizationalUnit")) return "OU";
  if (isContainer(e)) return "Container";
  return c[c.length - 1] ?? "object";
}
function iconFor(e: LdapEntry) {
  switch (kindOf(e)) {
    case "Computer":
      return <Monitor className="size-4 text-muted-foreground" />;
    case "Group":
      return <Users className="size-4 text-muted-foreground" />;
    case "User":
      return <User className="size-4 text-muted-foreground" />;
    case "OU":
    case "Container":
      return <Folder className="size-4 text-primary" />;
    default:
      return <Box className="size-4 text-muted-foreground" />;
  }
}
function label(e: LdapEntry): string {
  return (
    first(e, "displayName") ||
    first(e, "name") ||
    first(e, "cn") ||
    first(e, "sAMAccountName") ||
    e.dn
  );
}

export function AdExplorer({ namespace, name }: { namespace: string; name: string }) {
  // trail from the domain root; [] = root. baseDN for the query is the last entry's DN.
  const [trail, setTrail] = useState<{ dn: string; label: string }[]>([]);
  const [selected, setSelected] = useState<LdapEntry | null>(null);
  const [term, setTerm] = useState("");
  const [query, setQuery] = useState("");

  const baseDN = trail.at(-1)?.dn ?? "";

  const q = useQuery({
    queryKey: ["ad-ldap", namespace, name, baseDN, query],
    queryFn: () =>
      query
        ? directoryLdap(namespace, name, {
            filter: `(&(objectClass=*)(|(cn=*${query}*)(sAMAccountName=*${query}*)(displayName=*${query}*)))`,
            scope: "sub",
          })
        : directoryLdap(namespace, name, { baseDN, scope: "one" }),
  });

  const entries = (q.data?.entries ?? []).slice().sort((a, b) => {
    const ac = isContainer(a) ? 0 : 1;
    const bc = isContainer(b) ? 0 : 1;
    if (ac !== bc) return ac - bc;
    return label(a).localeCompare(label(b));
  });

  function enter(e: LdapEntry) {
    setTrail((t) => [...t, { dn: e.dn, label: label(e) }]);
    setSelected(null);
    setTerm("");
    setQuery("");
  }
  function jump(i: number) {
    setTrail((t) => t.slice(0, i));
    setSelected(null);
    setTerm("");
    setQuery("");
  }

  return (
    <div className="grid gap-4 lg:grid-cols-[1fr_360px]">
      <Card>
        <CardContent className="p-0">
          {/* breadcrumb + search */}
          <div className="flex flex-wrap items-center gap-2 border-b border-border p-3">
            <button
              className="text-sm font-medium hover:underline"
              onClick={() => jump(0)}
            >
              {q.data?.domain ?? "domain"}
            </button>
            {trail.map((t, i) => (
              <span key={t.dn} className="flex items-center gap-2">
                <ChevronRight className="size-3 text-muted-foreground" />
                <button
                  className="text-sm hover:underline"
                  onClick={() => jump(i + 1)}
                >
                  {t.label}
                </button>
              </span>
            ))}
            <div className="ml-auto flex items-center gap-1.5 rounded-md border border-border px-2">
              <Search className="size-3.5 text-muted-foreground" />
              <input
                value={term}
                onChange={(e) => setTerm(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") setQuery(term.trim());
                }}
                placeholder="Search whole directory…"
                className="h-8 w-48 bg-transparent text-sm outline-none"
              />
              {query ? (
                <button
                  className="text-xs text-muted-foreground hover:text-foreground"
                  onClick={() => {
                    setQuery("");
                    setTerm("");
                  }}
                >
                  clear
                </button>
              ) : null}
            </div>
          </div>

          {/* object list */}
          {q.isLoading ? (
            <div className="p-6 text-sm text-muted-foreground">Loading…</div>
          ) : q.isError ? (
            <div className="p-6 text-sm text-destructive">
              {q.error instanceof Error ? q.error.message : "Couldn't query the directory."}
            </div>
          ) : entries.length === 0 ? (
            <div className="p-6 text-sm text-muted-foreground">
              {query ? "No matches." : "Empty container."}
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead className="text-left text-xs text-muted-foreground">
                <tr className="border-b border-border">
                  <th className="p-2 pl-3 font-medium">Name</th>
                  <th className="p-2 font-medium">Type</th>
                  <th className="p-2 font-medium">sAMAccountName</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((e) => (
                  <tr
                    key={e.dn}
                    className={`cursor-pointer border-b border-border/60 hover:bg-muted/50 ${
                      selected?.dn === e.dn ? "bg-muted" : ""
                    }`}
                    onClick={() => setSelected(e)}
                    onDoubleClick={() => isContainer(e) && enter(e)}
                  >
                    <td className="flex items-center gap-2 p-2 pl-3">
                      {iconFor(e)}
                      <span>{label(e)}</span>
                      {isContainer(e) ? (
                        <button
                          className="ml-1 text-xs text-primary hover:underline"
                          onClick={(ev) => {
                            ev.stopPropagation();
                            enter(e);
                          }}
                        >
                          open →
                        </button>
                      ) : null}
                    </td>
                    <td className="p-2 text-muted-foreground">{kindOf(e)}</td>
                    <td className="p-2 font-mono text-xs text-muted-foreground">
                      {first(e, "sAMAccountName") || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>

      {/* attribute panel */}
      <Card>
        <CardContent className="p-0">
          {selected ? (
            <div>
              <div className="flex items-center gap-2 border-b border-border p-3">
                {iconFor(selected)}
                <div className="min-w-0">
                  <div className="truncate text-sm font-medium">{label(selected)}</div>
                  <div className="truncate font-mono text-[11px] text-muted-foreground">
                    {selected.dn}
                  </div>
                </div>
              </div>
              <div className="max-h-[520px] overflow-auto p-3">
                <table className="w-full text-xs">
                  <tbody>
                    {Object.keys(selected.attributes)
                      .sort()
                      .map((k) => (
                        <tr key={k} className="align-top">
                          <td className="w-40 py-1 pr-2 font-medium text-muted-foreground">
                            {k}
                          </td>
                          <td className="py-1 font-mono break-all">
                            {(selected.attributes[k] ?? []).join(", ")}
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : (
            <div className="p-6 text-sm text-muted-foreground">
              Select an object to view its attributes. Double-click (or “open”) a
              container to browse into it.
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
