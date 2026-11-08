// SPDX-License-Identifier: AGPL-3.0-only
import {
  createContext,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";

type Language = "en" | "zh";
const Locale = createContext<{
  language: Language;
  setLanguage: (value: Language) => void;
  t: (english: string, chinese: string) => string;
}>({
  language: "en",
  setLanguage: (): void => {},
  t: (english): string => english,
});

export function LocaleProvider({ children }: { children: ReactNode }) {
  const [language, setLanguage] = useState<Language>(
    navigator.language.startsWith("zh") ? "zh" : "en",
  );
  useEffect(() => {
    document.documentElement.lang = language === "zh" ? "zh-CN" : "en";
  }, [language]);
  return (
    <Locale.Provider
      value={{
        language,
        setLanguage,
        t: (en, zh) => (language === "zh" ? zh : en),
      }}
    >
      {children}
    </Locale.Provider>
  );
}

export const useLocale = () => useContext(Locale);

export function LanguageControl() {
  const { language, setLanguage } = useLocale();
  return (
    <label className="language-control">
      <span className="sr-only">Language / 语言</span>
      <select
        value={language}
        onChange={(event) => setLanguage(event.target.value as Language)}
      >
        <option value="en">English</option>
        <option value="zh">简体中文</option>
      </select>
    </label>
  );
}
