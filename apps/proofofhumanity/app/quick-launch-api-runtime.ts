export const QUICK_LAUNCH_API_RUNTIME = "dedicated-single-replica" as const;

export const QUICK_LAUNCH_TRANSACTIONS_DISABLED_CODE = "blockchain-transactions-disabled" as const;

export interface QuickLaunchApiRuntimeAssessment {
  dedicatedSingleReplica: boolean;
  transactionFree: boolean;
}

/**
 * Fail closed unless the process explicitly declares the dedicated Quick Launch API role. Amplify
 * compiles the route modules too, but must never execute signing or process-local state there.
 */
export function assessQuickLaunchApiRuntime(
  env: NodeJS.ProcessEnv = process.env,
): QuickLaunchApiRuntimeAssessment {
  return {
    dedicatedSingleReplica: env.POH_API_RUNTIME?.trim() === QUICK_LAUNCH_API_RUNTIME,
    transactionFree: env.POH_BLOCKCHAIN_TRANSACTIONS_ENABLED?.trim().toLowerCase() !== "true",
  };
}
