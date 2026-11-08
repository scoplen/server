// SPDX-License-Identifier: AGPL-3.0-only
import { useEffect, useRef, useState } from "react";
import { useLocale } from "./locale.tsx";

export function useConfirmation() {
  const { t } = useLocale();
  const [message, setMessage] = useState("");
  const resolve = useRef<((value: boolean) => void) | undefined>(undefined);
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    if (message) dialog.current?.showModal();
    else dialog.current?.close();
  }, [message]);
  useEffect(() => () => resolve.current?.(false), []);
  function close(value: boolean) {
    resolve.current?.(value);
    resolve.current = undefined;
    setMessage("");
  }
  const confirm = (text: string) =>
    new Promise<boolean>((accept) => {
      resolve.current?.(false);
      resolve.current = accept;
      setMessage(text);
    });
  return {
    confirm,
    dialog: (
      <dialog
        ref={dialog}
        className="confirmation"
        aria-labelledby="confirm-title"
        onCancel={(event) => {
          event.preventDefault();
          close(false);
        }}
      >
        <h2 id="confirm-title">{t("Review this action", "确认此操作")}</h2>
        <p>{message}</p>
        <div className="form-actions">
          <button className="secondary" autoFocus onClick={() => close(false)}>
            {t("Cancel", "取消")}
          </button>
          <button className="danger" onClick={() => close(true)}>
            {t("Continue", "继续")}
          </button>
        </div>
      </dialog>
    ),
  };
}
