export interface GoogleUserLifecycle {
  archived?: boolean | undefined;
  deletionTime?: string | undefined;
  suspended?: boolean | undefined;
}

export function isActiveGoogleUser(user: GoogleUserLifecycle): boolean {
  return (
    user.suspended !== true &&
    user.archived !== true &&
    user.deletionTime === undefined
  );
}

export function isInactiveGoogleUser(user: GoogleUserLifecycle): boolean {
  return !isActiveGoogleUser(user);
}
