"use client";

import type { ReactNode } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { logout } from "@/lib/user";
import { useAuthTypeMetadata } from "@/hooks/useAuthTypeMetadata";
import { AuthType } from "@/lib/constants";
import LineItem from "@/refresh-components/buttons/LineItem";
import { SvgArrowExchange } from "@opal/icons";
import { toast } from "@/hooks/useToast";
import OriginalAccountPopover, {
  type SettingsProps,
} from "./AccountPopoverBase";

export type { SettingsProps };

function SwitchAccountMenuItem() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const handleSwitchAccount = () => {
    logout()
      .then((response) => {
        if (!response?.ok) {
          alert("Failed to logout");
          return;
        }

        const currentUrl = `${pathname}${
          searchParams?.toString() ? `?${searchParams.toString()}` : ""
        }`;

        const encodedRedirect = encodeURIComponent(currentUrl);

        // Directly redirect to OIDC authorize with prompt=login
        // This bypasses the login page and forces re-authentication
        window.location.href = `/api/auth/oidc/authorize?prompt=login&next=${encodedRedirect}&redirect=true`;
      })
      .catch(() => {
        toast.error("Failed to switch account");
      });
  };

  return (
    <LineItem
      key="switch-account"
      icon={SvgArrowExchange}
      onClick={handleSwitchAccount}
    >
      Switch Account
    </LineItem>
  );
}

export default function AccountPopover({
  folded,
  onShowBuildIntro,
}: SettingsProps) {
  const { authTypeMetadata } = useAuthTypeMetadata();
  const isOIDCUser = authTypeMetadata.authType === AuthType.OIDC;

  const extraMenuItems: ReactNode | undefined = isOIDCUser ? (
    <SwitchAccountMenuItem />
  ) : undefined;

  return (
    <OriginalAccountPopover
      folded={folded}
      onShowBuildIntro={onShowBuildIntro}
      extraMenuItems={extraMenuItems}
    />
  );
}
