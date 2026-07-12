import { isRecord } from "../validation/guards";

export const LANGUAGE_SERVER_WORKER_MESSAGE_TYPES = {
  READY: "yara-x/language-server/ready",
  ERROR: "yara-x/language-server/error",
} as const;

export type LanguageServerWorkerBootstrapMessage =
  | {
      type: typeof LANGUAGE_SERVER_WORKER_MESSAGE_TYPES.READY;
    }
  | {
      type: typeof LANGUAGE_SERVER_WORKER_MESSAGE_TYPES.ERROR;
      error: string;
    };

export function isLanguageServerWorkerBootstrapMessage(
  value: unknown,
): value is LanguageServerWorkerBootstrapMessage {
  return (
    isRecord(value) &&
    (value.type === LANGUAGE_SERVER_WORKER_MESSAGE_TYPES.READY ||
      value.type === LANGUAGE_SERVER_WORKER_MESSAGE_TYPES.ERROR)
  );
}
