import { ExternalLink } from "lucide-react";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { useHelp } from "@/components/help/help-context";

/**
 * The Help panel — AWS/Cloudscape's right-side "Info" drawer. It opens when an InfoLink is clicked,
 * shows contextual guidance without navigating away or losing form state, and footers a "Learn more"
 * link to the full docs (new tab). Rendered once at the app root.
 */
export function HelpPanel() {
  const { content, close } = useHelp();
  return (
    <Sheet open={!!content} onOpenChange={(o) => (!o ? close() : undefined)}>
      <SheetContent side="right" className="w-full overflow-y-auto sm:max-w-md">
        {content ? (
          <>
            <SheetHeader>
              <SheetTitle>{content.title}</SheetTitle>
            </SheetHeader>
            <div className="mt-4 space-y-3 text-sm leading-relaxed text-muted-foreground">{content.body}</div>
            {content.docsHref ? (
              <a
                href={content.docsHref}
                target="_blank"
                rel="noreferrer"
                className="mt-5 inline-flex items-center gap-1 text-sm font-medium text-primary hover:underline"
              >
                Learn more <ExternalLink className="size-3.5" />
              </a>
            ) : null}
          </>
        ) : null}
      </SheetContent>
    </Sheet>
  );
}
