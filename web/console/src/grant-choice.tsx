// SPDX-License-Identifier: AGPL-3.0-only
import { useEffect, useId, useRef, useState, type KeyboardEvent } from "react";

export interface GrantOption {
  id: string;
  label: string;
  detail?: string;
}
export function choiceIndex(key: string, index: number, count: number): number {
  if (!count) return -1;
  if (key === "Home") return 0;
  if (key === "End") return count - 1;
  if (key === "ArrowDown") return (index + 1 + count) % count;
  if (key === "ArrowUp") return (index - 1 + count) % count;
  return index;
}
export function GrantChoice({
  label,
  placeholder,
  options,
  value,
  disabled,
  onChange,
}: {
  label: string;
  placeholder: string;
  options: GrantOption[];
  value: string;
  disabled: boolean;
  onChange: (value: string) => void;
}) {
  const id = useId(),
    trigger = useRef<HTMLButtonElement>(null);
  const list = useRef<HTMLUListElement>(null),
    container = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false),
    [active, setActive] = useState(0);
  const selected = options.find((option) => option.id === value);
  useEffect(() => {
    if (open) list.current?.focus();
  }, [open]);
  useEffect(() => {
    if (open)
      list.current
        ?.querySelector<HTMLElement>(`[data-index="${active}"]`)
        ?.scrollIntoView({ block: "nearest" });
  }, [open, active]);
  function close() {
    setOpen(false);
    trigger.current?.focus();
  }
  function show(last = false) {
    if (disabled || !options.length) return;
    const index = options.findIndex((option) => option.id === value);
    setActive(index < 0 ? (last ? options.length - 1 : 0) : index);
    setOpen(true);
  }
  function navigate(event: KeyboardEvent<HTMLUListElement>) {
    if (["Home", "End", "ArrowDown", "ArrowUp"].includes(event.key)) {
      event.preventDefault();
      setActive(choiceIndex(event.key, active, options.length));
    } else if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      if (options[active]) onChange(options[active].id);
      close();
    } else if (event.key === "Escape") {
      event.preventDefault();
      close();
    } else if (event.key === "Tab") {
      trigger.current?.focus();
      setOpen(false);
    } else if (
      event.key.length === 1 &&
      !event.ctrlKey &&
      !event.metaKey &&
      !event.altKey
    ) {
      const ordered = [
        ...options.slice(active + 1),
        ...options.slice(0, active + 1),
      ];
      const match = ordered.find((option) =>
        option.label
          .toLocaleLowerCase()
          .startsWith(event.key.toLocaleLowerCase()),
      );
      if (match) {
        event.preventDefault();
        setActive(options.indexOf(match));
      }
    }
  }
  return (
    <div
      className="field grant-choice"
      ref={container}
      onBlur={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget)) setOpen(false);
      }}
    >
      <span id={`${id}-label`}>{label}</span>
      <button
        type="button"
        ref={trigger}
        className="grant-choice-trigger"
        disabled={disabled || !options.length}
        aria-labelledby={`${id}-label ${id}-value`}
        aria-haspopup="listbox"
        aria-expanded={open && !disabled}
        aria-controls={open && !disabled ? `${id}-list` : undefined}
        onClick={() => (open ? close() : show())}
        onKeyDown={(event) => {
          if (event.key === "ArrowDown" || event.key === "ArrowUp") {
            event.preventDefault();
            show(event.key === "ArrowUp");
          }
        }}
      >
        <span id={`${id}-value`}>{selected?.label ?? placeholder}</span>
        <span className="grant-choice-arrow" aria-hidden="true" />
      </button>
      {open && !disabled && (
        <ul
          id={`${id}-list`}
          ref={list}
          className="grant-choice-list"
          role="listbox"
          aria-labelledby={`${id}-label`}
          tabIndex={-1}
          aria-activedescendant={
            options[active] ? `${id}-option-${active}` : undefined
          }
          onKeyDown={navigate}
        >
          {options.map((option, index) => (
            <li
              key={option.id}
              id={`${id}-option-${index}`}
              data-index={index}
              role="option"
              aria-selected={value === option.id}
              className={index === active ? "active" : ""}
              onPointerMove={() => setActive(index)}
              onClick={() => {
                onChange(option.id);
                close();
              }}
            >
              <span>{option.label}</span>
              {option.detail && <small>{option.detail}</small>}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
