export interface GoogleAuditUser {
  aliases: string[];
  archived: boolean;
  deleted: boolean;
  id: string;
  primaryEmail: string;
  suspended: boolean;
}

export interface GoogleAuditGroup {
  email: string;
  id: string;
}

export interface GoogleAuditMembership {
  groupId: string;
  memberEmail: string;
  memberId: string;
  memberType: "GROUP" | "USER";
  role?: "MANAGER" | "MEMBER" | "OWNER";
  status?: "ACTIVE" | "ARCHIVED" | "SUSPENDED" | "UNKNOWN";
}

export interface GoogleAuthoritySnapshot {
  capturedAt: string;
  complete: boolean;
  groups: GoogleAuditGroup[];
  issues: { code: string; message: string }[];
  memberships: GoogleAuditMembership[];
  reachableGroupIds: string[];
  reports:
    | {
        events: {
          groupEmail?: string;
          name: string;
          parameters: Record<string, string[]>;
          subjectEmail?: string;
          time: string;
        }[];
        issues: string[];
        status: "partial" | "unavailable";
      }
    | {
        events: {
          groupEmail?: string;
          name: string;
          parameters: Record<string, string[]>;
          subjectEmail?: string;
          time: string;
        }[];
        status: "available";
      };
  unmappedDescendantGroups: GoogleAuditGroup[];
  users: GoogleAuditUser[];
}
