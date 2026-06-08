// Disabled for local build to avoid Turbopack standalone issues
export async function register() {
  // No-op
}

export const onRequestError = (error: unknown) => {
  console.error("Request error:", error);
};
