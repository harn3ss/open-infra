import { LogOut, Settings } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
} from "@/components/ui/dropdown-menu";
import { useAuth } from "@/lib/auth";
import { useTheme } from "@/lib/theme";
import { useDensity } from "@/lib/use-density";

/** Top-right utility menu: appearance (light/dark) + content density. */
export function SettingsMenu() {
  const { theme, setTheme } = useTheme();
  const { density, setDensity } = useDensity();
  const { user, signOut } = useAuth();
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon" aria-label="Settings" title="Settings">
          <Settings className="size-4" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-52">
        <DropdownMenuLabel>Appearance</DropdownMenuLabel>
        <DropdownMenuRadioGroup
          value={theme}
          onValueChange={(v) => setTheme(v === "dark" ? "dark" : "light")}
        >
          <DropdownMenuRadioItem value="light">Light</DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="dark">Dark</DropdownMenuRadioItem>
        </DropdownMenuRadioGroup>

        <DropdownMenuSeparator />

        <DropdownMenuLabel>Density</DropdownMenuLabel>
        <DropdownMenuRadioGroup
          value={density}
          onValueChange={(v) => setDensity(v === "compact" ? "compact" : "comfortable")}
        >
          <DropdownMenuRadioItem value="comfortable">
            Comfortable
          </DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="compact">Compact</DropdownMenuRadioItem>
        </DropdownMenuRadioGroup>

        {user && !user.authDisabled ? (
          <>
            <DropdownMenuSeparator />
            <DropdownMenuLabel className="font-normal text-muted-foreground">
              Signed in as{" "}
              <span className="font-medium text-foreground">{user.user}</span>
            </DropdownMenuLabel>
            <DropdownMenuItem onClick={() => void signOut()}>
              <LogOut className="size-4" />
              Sign out
            </DropdownMenuItem>
          </>
        ) : null}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
